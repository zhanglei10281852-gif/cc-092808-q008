from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.errors import ConflictError
from app.database import transaction
from app.forensics.service import ForensicService


BASE = datetime(2026, 9, 15, 10, 0, tzinfo=UTC)


def _build_finished_examination(service: ForensicService, suffix: str, *, discipline="法医毒物") -> tuple[dict, dict, dict]:
    agency = service.forensic_cases.create_agency({
        "agency_code": f"ORG-{suffix}", "agency_name": "市公安局", "jurisdiction_code": "CN",
        "contact_address": "", "licensed_on": "2025-01-01", "accreditation_no": None, "restrictions": {},
    })
    case = service.forensic_cases.create_forensic_case({
        "case_no": f"CASE-{suffix}", "case_name": "毒物鉴定", "discipline": discipline,
        "entrusted_matter": "", "agency_id": agency["id"], "case_source": "委托",
        "accepted_on": "2026-09-01", "passport": {}, "created_by": "登记员",
    })
    case = service.forensic_cases.transition(case["id"], {
        "target_status": "accepted", "reason": "齐全", "expected_version": 1, "actor": "审核员"})
    loc = service.custody.create_location({
        "location_code": f"V-{suffix}", "facility": "库", "room": "室", "rack": "R", "shelf": "S",
        "capacity_units": 1000, "reference_value": 4, "humidity_percent": 40})
    sp = service.custody.create_specimen({
        "specimen_no": f"SP-{suffix}", "case_id": case["id"], "parent_specimen_id": None,
        "received_year": 2026, "initial_quantity": 100, "integrity_percent": 100,
        "packaging": "", "sealed_on": "2026-09-01", "created_by": "登记员"})
    service.custody.place_specimen({
        "specimen_id": sp["id"], "location_id": loc["id"], "quantity": 100,
        "container_code": f"BOX-{suffix}", "idempotency_key": f"place-{suffix}", "actor": "保管员"})
    proto = service.examinations.create_protocol({
        "protocol_code": f"TOX-{suffix}", "discipline": discipline, "observation_target": 10,
        "checkpoint_count": 1, "reference_value": 1, "turnaround_days": 1,
        "conclusion_rule": "规则", "created_by": "负责人"})
    exam = service.examinations.schedule_examination({
        "examination_no": f"EX-{suffix}", "specimen_id": sp["id"], "protocol_id": proto["id"],
        "examination_type": "补充检验", "sample_quantity": 2, "scheduled_for": "2026-09-10",
        "requested_by": "检验员", "idempotency_key": f"sched-{suffix}"})
    service.examinations.start_examination(exam["id"], {"performed_by": "检验员", "expected_version": 1})
    service.examinations.add_observation(exam["id"], {
        "checkpoint_no": 1, "items_checked": 10, "conforming_count": 9, "exception_count": 1,
        "unusable_count": 0, "pending_count": 0, "sequence_no": 1, "observed_by": "检验员"})
    exam = service.examinations.complete_examination(exam["id"], {"performed_by": "检验员", "expected_version": 2})
    return case, service.repository.require_specimen(sp["id"]), exam


def _resource(service, exam, ref, *, rtype="reagent_batch", when=BASE, source="on_time", hours=2):
    return service.incidents.register_examination_resource(exam["id"], {
        "resource_type": rtype, "resource_ref": ref,
        "used_from": when, "used_to": when + timedelta(hours=hours),
        "source": source, "recorded_by": "检验员"})


def _incident(service, no="QE-1", resources=None, *, slack=0, start=None, end=None):
    return service.incidents.create_incident({
        "incident_no": no, "title": "空白对照污染", "description": "污染",
        "window_start": start or datetime(2026, 9, 14, tzinfo=UTC),
        "window_end": end or datetime(2026, 9, 17, tzinfo=UTC),
        "created_by": "质量负责人",
        "resources": resources if resources is not None else [
            {"resource_type": "reagent_batch", "resource_ref": "RB-77",
             "note": "可疑批次", "created_by": "质量负责人"}],
        "evidence": [{"evidence_type": "空白对照", "reference": "BLANK-1",
                      "detail": {"ct": 31}, "created_by": "质量负责人"}],
        "rule_window_slack_minutes": slack,
    })


def test_incident_register_generates_candidates_with_hit_paths(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, _, ex_hit = _build_finished_examination(service, "H")
        _, _, ex_miss = _build_finished_examination(service, "M")
        _resource(service, ex_hit, "RB-77")
        _resource(service, ex_miss, "RB-99")  # 不同批次
        incident = _incident(service)
        assert incident["active_rule_version"] == 1
        assert incident["candidate_counts"]["candidate"] == 1
        candidate = incident["candidates"][0]
        assert candidate["examination_id"] == ex_hit["id"]
        path = candidate["hit_paths"][0]
        assert path["resource_ref"] == "RB-77"
        assert path["rule_id"] == "reagent_batch:RB-77"
        assert path["incident_window_start"] < path["used_from"] < path["incident_window_end"]


def test_window_overlap_boundary_and_non_overlapping_usage_excluded(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, _, exam = _build_finished_examination(service, "W")
        # 使用区间在污染窗开始之前且无重叠
        _resource(service, exam, "RB-77", when=datetime(2026, 9, 10, 8, 0, tzinfo=UTC))
        incident = _incident(service, "QE-W")
        assert incident["candidate_counts"]["candidate"] == 0
        # 登记一条与窗口仅部分重叠的迟到记录后应命中（宽限 0 仍重叠）
        _resource(service, exam, "RB-77",
                  when=datetime(2026, 9, 13, 20, 0, tzinfo=UTC), hours=24, source="late")
        incident = service.incidents.incident_detail(incident["id"])
        assert incident["candidate_counts"]["candidate"] == 1


def test_slack_minutes_extend_match_window(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, _, exam = _build_finished_examination(service, "S")
        # 使用时间紧贴窗外 30 分钟
        _resource(service, exam, "RB-77", when=datetime(2026, 9, 17, 0, 30, tzinfo=UTC), hours=1)
        incident = _incident(service, "QE-S0", slack=0)
        assert incident["candidate_counts"]["candidate"] == 0
        incident = _incident(service, "QE-S1", slack=120)
        assert incident["candidate_counts"]["candidate"] == 1


def test_confirm_freezes_specimen_flags_review_and_opens_withdrawal_without_report_change(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, specimen, exam = _build_finished_examination(service, "C")
        _resource(service, exam, "RB-77")
        report = service.incidents.issue_report(exam["id"], {
            "report_no": "RPT-C", "opinion_text": "阴性意见原文", "result": {"c": "阴性"},
            "issued_by": "授权签字人", "issued_at": datetime(2026, 9, 16, tzinfo=UTC)})
        incident = _incident(service, "QE-C")
        cid = incident["candidates"][0]["id"]
        result = service.incidents.decide_candidate(cid, {
            "action": "confirm", "actor": "质量负责人", "reason": "污染吻合"})
        assert result["status"] == "confirmed"
        # 剩余检材冻结
        assert service.repository.require_specimen(specimen["id"])["status"] == "held"
        # 检验结果待复核
        assert result["review_flags"][0]["status"] == "pending"
        # 已签发意见只建撤回审查
        assert len(result["withdrawal_reviews"]) == 1
        assert result["withdrawal_reviews"][0]["status"] == "pending"
        # 原报告内容未被改写
        assert service.repository.require_report(report["id"])["opinion_text"] == "阴性意见原文"
        # 冻结阻止领用
        try:
            service.custody.withdraw({
                "specimen_id": specimen["id"], "quantity": 1, "movement_type": "领用",
                "idempotency_key": "wd-c", "actor": "保管员", "reason": "试验"})
        except ConflictError:
            pass
        else:
            raise AssertionError("冻结检材不应允许领用")


def test_review_flag_blocks_report_issuance(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, _, exam = _build_finished_examination(service, "B")
        _resource(service, exam, "RB-77")
        incident = _incident(service, "QE-B")
        service.incidents.decide_candidate(incident["candidates"][0]["id"], {
            "action": "confirm", "actor": "质量负责人", "reason": "污染"})
        try:
            service.incidents.issue_report(exam["id"], {
                "report_no": "RPT-B", "opinion_text": "新意见", "result": {}, "issued_by": "签字人"})
        except ConflictError:
            pass
        else:
            raise AssertionError("待复核检验不应允许签发")


def test_repeated_confirmation_does_not_create_second_disposition(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, _, exam = _build_finished_examination(service, "R")
        _resource(service, exam, "RB-77")
        incident = _incident(service, "QE-R")
        cid = incident["candidates"][0]["id"]
        service.incidents.decide_candidate(cid, {
            "action": "confirm", "actor": "质量负责人", "reason": "污染"})
        try:
            service.incidents.decide_candidate(cid, {
                "action": "confirm", "actor": "质量负责人", "reason": "再次确认"})
        except ConflictError:
            pass
        else:
            raise AssertionError("已确认候选不能重复确认")
        count = conn.execute(
            "SELECT COUNT(*) FROM impact_dispositions WHERE incident_id=?", (incident["id"],)).fetchone()[0]
        # 该检验无报告，仅冻结 + 待复核两项处置
        assert count == 2


def test_late_resource_and_late_usage_deterministically_expand_candidates(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, _, e1 = _build_finished_examination(service, "L1")
        _, _, e2 = _build_finished_examination(service, "L2")
        _resource(service, e1, "RB-77")
        _resource(service, e2, "RB-99")
        incident = _incident(service, "QE-L")
        assert incident["candidate_counts"]["candidate"] == 1
        # 迟到的设备批次信息：事件补登设备 GC-9，e1 用过 → 命中合并到既有候选
        _resource(service, e1, "GC-9", rtype="equipment")
        incident = service.incidents.add_incident_resource(incident["id"], {
            "resource_type": "equipment", "resource_ref": "GC-9", "note": "迟到设备",
            "created_by": "质量负责人"})
        assert incident["active_rule_version"] == 2
        assert incident["candidate_counts"]["candidate"] == 1
        paths = incident["candidates"][0]["hit_paths"]
        assert {p["resource_ref"] for p in paths} == {"RB-77", "GC-9"}
        # 迟到台账：e2 补录 GC-9 使用 → 新增候选
        _resource(service, e2, "GC-9", rtype="equipment", source="late")
        incident = service.incidents.incident_detail(incident["id"])
        assert incident["candidate_counts"]["candidate"] == 2
        # 重复补录同一迟到台账不产生第二份候选或有效评估
        _resource(service, e2, "GC-9", rtype="equipment", source="late")
        incident = service.incidents.incident_detail(incident["id"])
        assert incident["candidate_counts"]["candidate"] == 2


def test_excluded_candidate_reopens_on_newer_rule_hit(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, _, exam = _build_finished_examination(service, "X")
        _resource(service, exam, "RB-77")
        incident = _incident(service, "QE-X")
        cid = incident["candidates"][0]["id"]
        service.incidents.decide_candidate(cid, {
            "action": "exclude", "actor": "调查员", "reason": "有隔离记录"})
        # 同版本重放不翻案
        ev = incident["evaluations"][0]
        service.incidents.run_evaluation(ev["id"], worker="replay", batch_size=100)
        assert service.repository.require_candidate(cid)["status"] == "excluded"
        # 新版本规则 + 迟到新证据命中 → 重新开放
        service.incidents.add_incident_resource(incident["id"], {
            "resource_type": "reagent_batch", "resource_ref": "RB-88", "note": "新发现",
            "created_by": "质量负责人"})
        _resource(service, exam, "RB-88", source="late")
        candidate = service.repository.require_candidate(cid)
        assert candidate["status"] == "candidate"
        assert candidate["last_rule_version"] == 2


def test_incident_version_blocks_concurrent_rule_update(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        incident = _incident(service, "QE-V")
        # 第一次发布成功，事件版本前进
        updated = service.incidents.update_rules(incident["id"], {
            "expected_version": incident["version"], "actor": "质量负责人", "note": "扩大窗口",
            "window_start": datetime(2026, 9, 13, tzinfo=UTC),
            "window_end": datetime(2026, 9, 18, tzinfo=UTC)})
        assert updated["version"] == incident["version"] + 1
        # 持旧版本的并发调查员再提交应被拒绝
        try:
            service.incidents.update_rules(incident["id"], {
                "expected_version": incident["version"], "actor": "另一调查员", "note": "旧版本"})
        except ConflictError as exc:
            assert exc.context["current_version"] == updated["version"]
        else:
            raise AssertionError("旧事件版本应被拒绝")


def test_candidate_optimistic_version_blocks_stale_decision(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, _, exam = _build_finished_examination(service, "CV")
        _resource(service, exam, "RB-77")
        incident = _incident(service, "QE-CV")
        cid = incident["candidates"][0]["id"]
        try:
            service.incidents.decide_candidate(cid, {
                "action": "exclude", "actor": "调查员", "reason": "误报",
                "expected_candidate_version": 999})
        except ConflictError:
            pass
        else:
            raise AssertionError("旧候选版本应被拒绝")


def test_evaluation_resumes_from_cursor_after_restart(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        exam_ids = []
        for i in range(7):
            _, _, exam = _build_finished_examination(service, f"P{i}")
            _resource(service, exam, "RB-77", when=BASE + timedelta(minutes=5 * i))
            exam_ids.append(exam["id"])
        incident = _incident(service, "QE-P")
        eid = incident["evaluations"][0]["id"]
        # 清空候选并重置评估，用极小批次多次推进，模拟重启续跑
        conn.execute("DELETE FROM impact_candidates")
        conn.execute(
            "UPDATE impact_evaluations SET status='pending',cursor_rule=0,cursor_key=0,"
            "scanned_count=0,matched_count=0,added_count=0,result_json=NULL,locked_by=NULL,locked_at=NULL WHERE id=?",
            (eid,))
        statuses = []
        for _ in range(10):
            ev = service.incidents.run_evaluation(eid, worker="resume", batch_size=2)
            statuses.append(ev["status"])
            if ev["status"] == "completed":
                break
        assert statuses[-1] == "completed"
        detail = service.repository.require_evaluation(eid)
        assert detail["matched_count"] == 7
        assert detail["added_count"] == 7
        assert service.incidents.incident_detail(incident["id"])["candidate_counts"]["candidate"] == 7


def test_close_incident_requires_all_candidates_decided(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        _, _, exam = _build_finished_examination(service, "CL")
        _resource(service, exam, "RB-77")
        incident = _incident(service, "QE-CL")
        current = service.incidents.incident_detail(incident["id"])
        try:
            service.incidents.close_incident(incident["id"], {
                "expected_version": current["version"], "actor": "质量负责人", "reason": "尝试关闭"})
        except ConflictError as exc:
            assert exc.context["pending_candidates"] == 1
        else:
            raise AssertionError("存在待定候选时不应允许关闭")
        service.incidents.decide_candidate(incident["candidates"][0]["id"], {
            "action": "exclude", "actor": "调查员", "reason": "误报"})
        current = service.incidents.incident_detail(incident["id"])
        closed = service.incidents.close_incident(incident["id"], {
            "expected_version": current["version"], "actor": "质量负责人", "reason": "处置完成"})
        assert closed["status"] == "closed"


def test_traceability_chain_from_incident_to_report_and_decisions(client):
    with transaction(immediate=True) as conn:
        service = ForensicService(conn)
        case, specimen, exam = _build_finished_examination(service, "T")
        _resource(service, exam, "RB-77")
        service.incidents.issue_report(exam["id"], {
            "report_no": "RPT-T", "opinion_text": "原文", "result": {}, "issued_by": "签字人",
            "issued_at": datetime(2026, 9, 16, tzinfo=UTC)})
        incident = _incident(service, "QE-T")
        cid = incident["candidates"][0]["id"]
        service.incidents.decide_candidate(cid, {
            "action": "confirm", "actor": "质量负责人", "reason": "污染"})
        detail = service.incidents.candidate_detail(cid)
        # 事件 → 规则/资源 → 检验 → 检材/案件 → 报告 → 处置链
        assert detail["forensic_case"]["case_no"] == case["case_no"]
        assert detail["specimen"]["specimen_no"] == specimen["specimen_no"]
        assert detail["examination"]["examination_no"] == exam["examination_no"]
        assert detail["reports"][0]["report_no"] == "RPT-T"
        types_order = [d["target_type"] for d in detail["dispositions"]]
        assert set(types_order) == {"specimen_hold", "examination_review_flag", "report_withdrawal_review"}
        full = service.incidents.incident_detail(incident["id"])
        assert full["resources"][0]["resource_ref"] == "RB-77"
        assert full["rule_versions"][0]["rules"][0]["rule_id"] == "reagent_batch:RB-77"
        assert full["evidence"][0]["reference"] == "BLANK-1"
        assert any(d["decision_type"] == "candidate_confirmed" for d in full["decisions"])
