from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.clock import FrozenClock
from app.core.errors import ConflictError, ValidationError
from app.database import get_connection, transaction
from app.forensics.service import ForensicService

BASE = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)


def standard_rules(service: ForensicService, *, window_minutes: int = 60) -> None:
    service.impact_rules.create_rule({
        "rule_code": "TIME-NEAR", "rule_name": "污染时间窗邻近", "rule_type": "time_proximity",
        "discipline": "", "params": {"window_minutes": window_minutes}, "created_by": "质量负责人",
    })
    service.impact_rules.create_rule({
        "rule_code": "REAGENT-SHARE", "rule_name": "同一试剂批次", "rule_type": "reagent_batch",
        "discipline": "", "params": {}, "created_by": "质量负责人",
    })
    service.impact_rules.create_rule({
        "rule_code": "EQUIPMENT-SHARE", "rule_name": "同一设备", "rule_type": "equipment",
        "discipline": "", "params": {}, "created_by": "质量负责人",
    })
    service.impact_rules.create_rule({
        "rule_code": "BENCH-SLOT", "rule_name": "同一工作台时段", "rule_type": "workbench_slot",
        "discipline": "", "params": {}, "created_by": "质量负责人",
    })


def completed_tox_exam(
    service: ForensicService,
    clock: FrozenClock,
    suffix: str,
    when: datetime,
    *,
    uses: list[dict] | None = None,
    conforming: int = 8,
) -> dict:
    clock.current = when
    source = service.forensic_cases.create_agency({
        "agency_code": f"TORG-{suffix}", "agency_name": "毒物鉴定中心", "jurisdiction_code": "CN",
        "contact_address": "司法路 9 号", "licensed_on": "2025-01-01", "accreditation_no": None, "restrictions": {},
    })
    case = service.forensic_cases.create_forensic_case({
        "case_no": f"TCASE-{suffix}", "case_name": "毒物成分鉴定", "discipline": "法医毒物",
        "entrusted_matter": "血液酒精与毒物筛查", "agency_id": source["id"], "case_source": "委托",
        "accepted_on": when.date().isoformat(), "passport": {}, "created_by": "登记员",
    })
    case = service.forensic_cases.transition(case["id"], {
        "target_status": "accepted", "reason": "资料齐全", "expected_version": 1, "actor": "审核员",
    })
    location = service.custody.create_location({
        "location_code": f"TVAULT-{suffix}", "facility": "检材保管室", "room": "冷藏区",
        "rack": "R1", "shelf": "S1", "capacity_units": 1000, "reference_value": 4, "humidity_percent": 40,
    })
    specimen = service.custody.create_specimen({
        "specimen_no": f"TSP-{suffix}", "case_id": case["id"], "parent_specimen_id": None,
        "received_year": when.year, "initial_quantity": 100, "integrity_percent": 100,
        "packaging": "密封采血管", "sealed_on": when.date().isoformat(), "created_by": "登记员",
    })
    service.custody.place_specimen({
        "specimen_id": specimen["id"], "location_id": location["id"], "quantity": 100,
        "container_code": f"TBOX-{suffix}", "idempotency_key": f"tplace-{suffix}", "actor": "保管员",
    })
    protocol = service.examinations.create_protocol({
        "protocol_code": f"TOX-PROTO-{suffix}", "discipline": "法医毒物", "observation_target": 10,
        "checkpoint_count": 1, "reference_value": 0, "turnaround_days": 14,
        "conclusion_rule": "空白对照与平行样满足质控阈值", "created_by": "技术负责人",
    })
    exam = service.examinations.schedule_examination({
        "examination_no": f"TEX-{suffix}", "specimen_id": specimen["id"], "protocol_id": protocol["id"],
        "examination_type": "补充检验", "sample_quantity": 5, "scheduled_for": when.date().isoformat(),
        "requested_by": "检验员", "idempotency_key": f"tsched-{suffix}",
    })
    service.examinations.start_examination(exam["id"], {"performed_by": "检验员", "expected_version": 1})
    service.examinations.add_observation(exam["id"], {
        "checkpoint_no": 1, "items_checked": 10, "conforming_count": conforming,
        "exception_count": 1, "unusable_count": 10 - conforming - 1, "pending_count": 0,
        "sequence_no": 1, "observed_by": "检验员",
    })
    completed = service.examinations.complete_examination(exam["id"], {"performed_by": "检验员", "expected_version": 2})
    for use in uses or []:
        service.impact.record_resource_use(exam["id"], use)
    return completed


def make_event(service: ForensicService, *, resources=None, evidence=None, window_minutes=60, event_no="QE-0001") -> dict:
    standard_rules(service, window_minutes=window_minutes)
    return service.impact.create_event({
        "event_no": event_no, "title": "毒物实验室空白对照污染", "event_type": "blank_contamination",
        "contaminant": "乙醇", "discipline": "法医毒物",
        "window_start": datetime(2026, 10, 1, 8, 10, tzinfo=UTC),
        "window_end": datetime(2026, 10, 1, 8, 20, tzinfo=UTC),
        "description": "10 月 1 日早班空白对照检出乙醇",
        "resources": resources or [], "evidence": evidence or [], "created_by": "质量负责人",
    })


def test_registration_generates_candidates_with_hit_paths(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        completed_tox_exam(service, clock, "A", datetime(2026, 10, 1, 8, 0, tzinfo=UTC), uses=[
            {"resource_type": "reagent_batch", "resource_ref": "RB-20261001",
             "used_from": datetime(2026, 10, 1, 8, 0, tzinfo=UTC), "used_to": datetime(2026, 10, 1, 8, 30, tzinfo=UTC),
             "source_key": "rb-A-1", "recorded_by": "检验员"},
        ])
        # 另一时段、不共享资源的检验不应命中
        completed_tox_exam(service, clock, "B", datetime(2026, 9, 15, 8, 0, tzinfo=UTC))
        event = make_event(service, resources=[
            {"resource_type": "reagent_batch", "resource_ref": "RB-20261001",
             "observed_at": datetime(2026, 10, 1, 8, 12, tzinfo=UTC), "note": "同一配制批次", "evidence": {}},
        ])
        candidates = [c for c in event["candidates"] if c["status"] == "pending"]
        assert len(candidates) == 1
        candidate = candidates[0]
        rule_codes = {path["rule_code"] for path in candidate["hit_paths"]}
        assert rule_codes == {"TIME-NEAR", "REAGENT-SHARE"}
        reagent_path = next(p for p in candidate["hit_paths"] if p["rule_type"] == "reagent_batch")
        assert reagent_path["resource_ref"] == "RB-20261001"
        assert reagent_path["rule_version"] == 1
        assert candidate["examination"]["examination_no"] == "TEX-A"
        assert event["evaluations"][0]["status"] == "completed"
        assert len(event["rules_used"]) == 4


def test_confirm_atomically_freezes_specimen_flags_review_and_requests_withdrawal(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        exam = completed_tox_exam(service, clock, "C", datetime(2026, 10, 1, 8, 0, tzinfo=UTC), uses=[
            {"resource_type": "equipment", "resource_ref": "GC-MS-02",
             "used_from": datetime(2026, 10, 1, 8, 5, tzinfo=UTC), "used_to": datetime(2026, 10, 1, 8, 25, tzinfo=UTC),
             "source_key": "eq-C-1", "recorded_by": "检验员"},
        ])
        # 报告已先签发
        report = service.impact.register_report(exam["id"], {
            "report_no": "RPT-C-1", "document_ref": "docs/RPT-C-1.pdf", "conclusion_digest": "sha256:abc",
            "issued_by": "授权签字人", "issued_at": datetime(2026, 10, 1, 10, 0, tzinfo=UTC),
        })
        event = make_event(service, resources=[
            {"resource_type": "equipment", "resource_ref": "GC-MS-02", "note": "同机台", "evidence": {}},
        ])
        candidate = next(c for c in event["candidates"] if c["examination"]["examination_no"] == "TEX-C")

        decided = service.impact.decide_candidate(event["id"], candidate["id"], {
            "action": "confirm", "reason": "确认同一设备同一时段运行", "expected_version": 1, "actor": "调查员",
        })

        assert decided["status"] == "confirmed"
        assert decided["disposition"]["status"] == "active"
        specimen = service.repository.require_specimen(decided["specimen"]["id"])
        assert specimen["status"] == "held"
        holds = service.repository.active_holds(specimen["id"])
        assert len(holds) == 1 and holds[0]["hold_type"] == "质量"
        # 冻结立即阻断领用
        with pytest.raises(ConflictError):
            service.custody.withdraw({
                "specimen_id": specimen["id"], "quantity": 1, "movement_type": "领用",
                "idempotency_key": "withdraw-blocked-1", "actor": "保管员", "reason": "试图领用",
            })
        # 待复核标志阻断继续签发
        with pytest.raises(ConflictError):
            service.impact.register_report(exam["id"], {
                "report_no": "RPT-C-2", "issued_by": "授权签字人",
                "issued_at": datetime(2026, 10, 1, 11, 0, tzinfo=UTC),
            })
        # 已签发报告产生撤回审查，原报告行不改写
        detail = service.impact.event_detail(event["id"])
        assert len(detail["withdrawal_reviews"]) == 1
        review = detail["withdrawal_reviews"][0]
        assert review["status"] == "requested"
        assert review["report"]["report_no"] == "RPT-C-1"
        untouched = connection.execute("SELECT * FROM examination_reports WHERE id=?", (report["id"],)).fetchone()
        assert dict(untouched)["conclusion_digest"] == "sha256:abc"
        assert len(detail["review_flags"]) == 1 and detail["review_flags"][0]["status"] == "pending"

        resolved = service.impact.decide_withdrawal_review(review["id"], {
            "approve": True, "actor": "质量负责人", "note": "污染成立，撤回原意见",
        })
        assert resolved["status"] == "withdrawn"

        # 重复确认不会产生第二份处置
        with pytest.raises(ConflictError):
            service.impact.decide_candidate(event["id"], candidate["id"], {
                "action": "confirm", "reason": "再次确认", "expected_version": 2, "actor": "调查员",
            })
        disposition_count = connection.execute(
            "SELECT COUNT(*) FROM impact_dispositions WHERE event_id=? AND status='active'", (event["id"],)
        ).fetchone()[0]
        assert disposition_count == 1


def test_exclude_requires_reason_and_reopen_reverses_disposition(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        exam = completed_tox_exam(service, clock, "D", datetime(2026, 10, 1, 8, 0, tzinfo=UTC))
        event = make_event(service)
        candidate = next(c for c in event["candidates"] if c["examination"]["examination_no"] == "TEX-D")
        with pytest.raises(ValidationError):
            service.impact.decide_candidate(event["id"], candidate["id"], {
                "action": "exclude", "reason": "", "expected_version": 1, "actor": "调查员",
            })
        excluded = service.impact.decide_candidate(event["id"], candidate["id"], {
            "action": "exclude", "reason": "该检验使用独立批号试剂且设备未共用", "expected_version": 1, "actor": "调查员",
        })
        assert excluded["status"] == "excluded"
        assert excluded["decisions"][0]["action"] == "exclude"
        # 全部候选有结论后允许关闭事件
        closed = service.impact.close_event(event["id"], {
            "expected_version": 2, "actor": "质量负责人", "summary": "排除误报，关闭",
        })
        assert closed["status"] == "closed"

    # 确认后重新调查会撤销处置（解冻、清标志）
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, FrozenClock(BASE))
        exam2 = completed_tox_exam(service, FrozenClock(BASE), "E", datetime(2026, 10, 1, 8, 0, tzinfo=UTC))
        event2 = make_event(service, event_no="QE-0002")
        candidate2 = next(c for c in event2["candidates"] if c["examination"]["examination_no"] == "TEX-E")
        service.impact.decide_candidate(event2["id"], candidate2["id"], {
            "action": "confirm", "reason": "确认影响", "expected_version": 1, "actor": "调查员",
        })
        reopened = service.impact.decide_candidate(event2["id"], candidate2["id"], {
            "action": "reopen", "reason": "新证据表明未受影响", "expected_version": 2, "actor": "质量负责人",
        })
        assert reopened["status"] == "pending"
        specimen = service.repository.require_specimen(exam2["specimen_id"])
        assert specimen["status"] == "stored"
        assert service.repository.active_holds(specimen["id"]) == []
        flag = connection.execute(
            "SELECT status FROM examination_review_flags WHERE examination_id=?", (exam2["id"],)
        ).fetchone()
        assert flag["status"] == "cleared"
        disposition = connection.execute(
            "SELECT status FROM impact_dispositions WHERE event_id=? AND examination_id=?",
            (event2["id"], exam2["id"]),
        ).fetchone()
        assert disposition["status"] == "reversed"


def test_repeated_evaluation_is_deterministic_and_creates_no_second_disposition(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        completed_tox_exam(service, clock, "F", datetime(2026, 10, 1, 8, 0, tzinfo=UTC), uses=[
            {"resource_type": "workbench", "resource_ref": "BENCH-A3",
             "used_from": datetime(2026, 10, 1, 8, 12, tzinfo=UTC), "used_to": datetime(2026, 10, 1, 8, 18, tzinfo=UTC),
             "source_key": "wb-F-1", "recorded_by": "检验员"},
        ])
        event = make_event(service, resources=[
            {"resource_type": "workbench", "resource_ref": "BENCH-A3", "note": "同一台位时段", "evidence": {}},
        ])
        assert event["evaluations"][0]["trigger"] == "registration"
        before_rows = connection.execute(
            "SELECT COUNT(*) FROM impact_evaluations WHERE event_id=?", (event["id"],)
        ).fetchone()[0]
        again = service.impact.request_evaluation(event["id"], "调查员")
        assert again.get("unchanged") is True
        after_rows = connection.execute(
            "SELECT COUNT(*) FROM impact_evaluations WHERE event_id=?", (event["id"],)
        ).fetchone()[0]
        assert before_rows == after_rows
        candidate = next(c for c in event["candidates"] if c["examination"]["examination_no"] == "TEX-F")
        service.impact.decide_candidate(event["id"], candidate["id"], {
            "action": "confirm", "reason": "台位时段重合", "expected_version": 1, "actor": "调查员",
        })
        # 再评估一次：处置仍只有一份
        service.impact.request_evaluation(event["id"], "调查员")
        active = connection.execute(
            "SELECT COUNT(*) FROM impact_dispositions WHERE event_id=? AND status='active'", (event["id"],)
        ).fetchone()[0]
        assert active == 1


def test_late_resource_record_deterministically_expands_candidates(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        completed_tox_exam(service, clock, "G", datetime(2026, 10, 1, 8, 0, tzinfo=UTC))
        # 次日检验，时间邻近规则不命中，等待迟到的设备日志
        late_exam = completed_tox_exam(service, clock, "H", datetime(2026, 10, 2, 9, 0, tzinfo=UTC))
        event = make_event(
            service,
            window_minutes=30,
            resources=[{"resource_type": "equipment", "resource_ref": "GC-MS-07", "note": "晚到记录", "evidence": {}}],
        )
        initial_numbers = {c["examination"]["examination_no"] for c in event["candidates"]}
        assert "TEX-H" not in initial_numbers
        eval_count_before = connection.execute(
            "SELECT COUNT(*) FROM impact_evaluations WHERE event_id=?", (event["id"],)
        ).fetchone()[0]

        result = service.impact.record_resource_use(late_exam["id"], {
            "resource_type": "equipment", "resource_ref": "GC-MS-07",
            "used_from": datetime(2026, 10, 1, 8, 14, tzinfo=UTC), "used_to": datetime(2026, 10, 1, 8, 19, tzinfo=UTC),
            "source_key": "eq-H-late-1", "recorded_by": "设备管理员",
        })
        assert result["replayed"] is False

        detail = service.impact.event_detail(event["id"])
        late_candidate = next(c for c in detail["candidates"] if c["examination"]["examination_no"] == "TEX-H")
        assert any(p["rule_code"] == "EQUIPMENT-SHARE" and p["resource_ref"] == "GC-MS-07" for p in late_candidate["hit_paths"])
        triggers = [row["trigger"] for row in detail["evaluations"]]
        assert triggers[-1] == "late_resource"
        eval_count_after = len(detail["evaluations"])
        assert eval_count_after == eval_count_before + 1

        # 同一迟到记录重复投递是幂等的，不会再次触发评估或产生重复候选
        replay = service.impact.record_resource_use(late_exam["id"], {
            "resource_type": "equipment", "resource_ref": "GC-MS-07",
            "used_from": datetime(2026, 10, 1, 8, 14, tzinfo=UTC), "used_to": datetime(2026, 10, 1, 8, 19, tzinfo=UTC),
            "source_key": "eq-H-late-1", "recorded_by": "设备管理员",
        })
        assert replay["replayed"] is True
        stable = service.impact.event_detail(event["id"])
        assert len(stable["evaluations"]) == eval_count_after
        assert sum(1 for c in stable["candidates"] if c["examination"]["examination_no"] == "TEX-H") == 1


def test_event_optimistic_version_blocks_concurrent_overwrite(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        completed_tox_exam(service, clock, "I", datetime(2026, 10, 1, 8, 0, tzinfo=UTC))
        event = make_event(service)
        # 先成功补充资源，版本推进到 2
        updated = service.impact.add_resources(event["id"], {
            "resources": [{"resource_type": "equipment", "resource_ref": "GC-MS-01", "note": "", "evidence": {}}],
            "expected_version": 1, "actor": "调查员",
        })
        assert updated["version"] == 2
        # 基于旧版本并发追加必须失败
        with pytest.raises(ConflictError) as exc:
            service.impact.add_resources(event["id"], {
                "resources": [{"resource_type": "equipment", "resource_ref": "GC-MS-02", "note": "", "evidence": {}}],
                "expected_version": 1, "actor": "另一调查员",
            })
        assert exc.value.context["current_version"] == 2
        # 候选决定同样受事件版本保护
        candidate = service.impact.list_candidates(event["id"])[0]
        with pytest.raises(ConflictError):
            service.impact.decide_candidate(event["id"], candidate["id"], {
                "action": "exclude", "reason": "旧版本请求", "expected_version": 1, "actor": "调查员",
            })
        # 版本链完整可追溯
        versions = service.impact.event_detail(event["id"])["versions"]
        assert [v["version"] for v in versions] == [1, 2]
        assert versions[1]["change_type"] == "resources_added"


def test_rule_versioning_deactivates_previous_version(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        completed_tox_exam(service, clock, "J", datetime(2026, 10, 1, 8, 0, tzinfo=UTC))
        standard_rules(service)
        # 发布时间窗规则 v2：邻近距离收紧到 0 分钟，事件窗 09:10-09:20 与 08:00-08:30 不相交
        v2 = service.impact_rules.create_rule({
            "rule_code": "TIME-NEAR", "rule_name": "污染时间窗邻近（收紧）", "rule_type": "time_proximity",
            "discipline": "", "params": {"window_minutes": 0}, "created_by": "质量负责人",
        })
        assert v2["version"] == 2 and v2["active"] == 1
        old = connection.execute("SELECT active FROM impact_rules WHERE rule_code='TIME-NEAR' AND version=1").fetchone()
        assert old["active"] == 0
        event = service.impact.create_event({
            "event_no": "QE-V2", "title": "规则版本切换验证", "event_type": "blank_contamination",
            "contaminant": "", "discipline": "法医毒物",
            "window_start": datetime(2026, 10, 1, 9, 10, tzinfo=UTC),
            "window_end": datetime(2026, 10, 1, 9, 20, tzinfo=UTC),
            "description": "", "resources": [], "evidence": [], "created_by": "质量负责人",
        })
        assert event["candidates"] == []
        used = event["rules_used"]
        time_rule = next(r for r in used if r["rule_code"] == "TIME-NEAR")
        assert time_rule["rule_version"] == 2


def test_restart_resumes_unfinished_evaluation(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        completed_tox_exam(service, clock, "K", datetime(2026, 10, 1, 8, 0, tzinfo=UTC))
        event = make_event(service)
        timestamp = "2026-10-01T08:31:00+00:00"
        connection.execute(
            "INSERT INTO impact_evaluations(event_id,trigger,event_version,rule_fingerprint,status,attempts,"
            "created_at,started_at) VALUES(?,?,?,?,'running',1,?,?)",
            (event["id"], "manual", 1, "crashed-fingerprint", timestamp, timestamp),
        )
        result = service.impact.reconcile_on_startup()
        assert result["recovered_evaluations"] == 1
        assert event["id"] in result["events"]
        stale = connection.execute(
            "SELECT status,error_message FROM impact_evaluations WHERE rule_fingerprint='crashed-fingerprint'"
        ).fetchone()
        assert stale["status"] == "failed"
        # 既有候选结果仍然可用
        candidates = service.impact.list_candidates(event["id"])
        assert any(c["examination"]["examination_no"] == "TEX-K" for c in candidates)


def test_event_detail_traces_rule_resource_examination_specimen_report_and_decisions(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        exam = completed_tox_exam(service, clock, "L", datetime(2026, 10, 1, 8, 0, tzinfo=UTC), uses=[
            {"resource_type": "reagent_batch", "resource_ref": "RB-LINK",
             "used_from": datetime(2026, 10, 1, 8, 8, tzinfo=UTC), "used_to": datetime(2026, 10, 1, 8, 28, tzinfo=UTC),
             "source_key": "rb-L-1", "recorded_by": "检验员"},
        ])
        service.impact.register_report(exam["id"], {
            "report_no": "RPT-L-1", "document_ref": "docs/RPT-L-1.pdf", "conclusion_digest": "sha256:lll",
            "issued_by": "授权签字人", "issued_at": datetime(2026, 10, 1, 9, 0, tzinfo=UTC),
        })
        event = service.impact.create_event({
            "event_no": "QE-LINK", "title": "全链路追溯验证", "event_type": "blank_contamination",
            "contaminant": "甲醇", "discipline": "法医毒物",
            "window_start": datetime(2026, 10, 1, 8, 10, tzinfo=UTC),
            "window_end": datetime(2026, 10, 1, 8, 20, tzinfo=UTC),
            "description": "",
            "resources": [{"resource_type": "reagent_batch", "resource_ref": "RB-LINK",
                           "observed_at": datetime(2026, 10, 1, 8, 11, tzinfo=UTC), "note": "同批试剂", "evidence": {}}],
            "evidence": [{
                "evidence_type": "document", "reference": "EVD-BLANK-01", "summary": "空白对照色谱图",
                "collected_at": datetime(2026, 10, 1, 8, 25, tzinfo=UTC), "recorded_by": "质量负责人", "metadata": {},
            }],
            "created_by": "质量负责人",
        })
        standard_rules(service)
        service.impact.request_evaluation(event["id"], "质量负责人")
        candidate = next(c for c in service.impact.list_candidates(event["id"]) if c["examination"]["examination_no"] == "TEX-L")
        service.impact.decide_candidate(event["id"], candidate["id"], {
            "action": "confirm", "reason": "链路完整确认", "expected_version": 1, "actor": "调查员",
        })
        detail = service.impact.event_detail(event["id"])
        assert detail["resources"][0]["resource_ref"] == "RB-LINK"
        assert detail["evidence_items"][0]["reference"] == "EVD-BLANK-01"
        assert detail["rules_used"], "应可追溯评估使用的规则"
        cand = next(c for c in detail["candidates"] if c["examination"]["examination_no"] == "TEX-L")
        assert cand["specimen"]["specimen_no"] == "TSP-L"
        assert cand["forensic_case"]["case_no"] == "TCASE-L"
        assert cand["decisions"][0]["action"] == "confirm"
        assert cand["disposition"]["status"] == "active"
        assert detail["review_flags"][0]["examination_id"] == exam["id"]
        assert detail["withdrawal_reviews"][0]["report"]["report_no"] == "RPT-L-1"
        assert {v["change_type"] for v in detail["versions"]} >= {"created", "candidate_confirmed"}


def test_review_flag_clear_restores_report_issuance_and_rule_publish_reruns(client):
    clock = FrozenClock(BASE)
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, clock)
        exam = completed_tox_exam(service, clock, "N", datetime(2026, 10, 1, 8, 0, tzinfo=UTC))
        # 先登记事件时尚无任何规则，候选为空
        event = service.impact.create_event({
            "event_no": "QE-RULEPUB", "title": "规则发布后重算", "event_type": "blank_contamination",
            "contaminant": "乙醇", "discipline": "法医毒物",
            "window_start": datetime(2026, 10, 1, 8, 10, tzinfo=UTC),
            "window_end": datetime(2026, 10, 1, 8, 20, tzinfo=UTC),
            "description": "", "resources": [], "evidence": [], "created_by": "质量负责人",
        })
        assert event["candidates"] == []
        # 发布时间窗规则后自动重算开放事件
        service.impact_rules.create_rule({
            "rule_code": "TIME-NEAR", "rule_name": "时间邻近", "rule_type": "time_proximity",
            "discipline": "", "params": {"window_minutes": 60}, "created_by": "质量负责人",
        })
        detail = service.impact.event_detail(event["id"])
        assert any(c["examination"]["examination_no"] == "TEX-N" for c in detail["candidates"])
        assert detail["evaluations"][-1]["trigger"] == "rule_published"

        candidate = next(c for c in detail["candidates"] if c["examination"]["examination_no"] == "TEX-N")
        service.impact.decide_candidate(event["id"], candidate["id"], {
            "action": "confirm", "reason": "确认影响", "expected_version": 1, "actor": "调查员",
        })
        # 待复核期间不能签发
        with pytest.raises(ConflictError):
            service.impact.register_report(exam["id"], {
                "report_no": "RPT-N-1", "issued_by": "授权签字人",
                "issued_at": datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
            })
        flag_id = service.impact.event_detail(event["id"])["review_flags"][0]["id"]
        with pytest.raises(ValidationError):
            service.impact.clear_review_flag(flag_id, {"actor": "复核员", "note": ""})
        cleared = service.impact.clear_review_flag(flag_id, {"actor": "复核员", "note": "重新检验结果有效"})
        assert cleared["status"] == "cleared"
        # 复核完成后恢复签发
        report = service.impact.register_report(exam["id"], {
            "report_no": "RPT-N-1", "issued_by": "授权签字人",
            "issued_at": datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
        })
        assert report["report_no"] == "RPT-N-1"


def test_http_quality_event_flow(client, admin):
    headers = admin["headers"]
    with transaction(immediate=True) as connection:
        service = ForensicService(connection, FrozenClock(BASE))
        exam = completed_tox_exam(service, FrozenClock(BASE), "M", datetime(2026, 10, 1, 8, 0, tzinfo=UTC), uses=[
            {"resource_type": "reagent_batch", "resource_ref": "RB-HTTP",
             "used_from": datetime(2026, 10, 1, 8, 5, tzinfo=UTC), "used_to": datetime(2026, 10, 1, 8, 25, tzinfo=UTC),
             "source_key": "rb-M-1", "recorded_by": "检验员"},
        ])
        exam_id = exam["id"]

    rule = client.post("/api/forensics/impact-rules", headers=headers, json={
        "rule_code": "HTTP-REAGENT", "rule_name": "同批试剂", "rule_type": "reagent_batch",
        "discipline": "", "params": {}, "created_by": "质量负责人",
    })
    assert rule.status_code == 201, rule.text
    created = client.post("/api/forensics/quality-events", headers=headers, json={
        "event_no": "QE-HTTP-1", "title": "空白污染", "event_type": "blank_contamination",
        "contaminant": "乙醇", "discipline": "法医毒物",
        "window_start": "2026-10-01T08:10:00Z", "window_end": "2026-10-01T08:20:00Z",
        "description": "", "resources": [
            {"resource_type": "reagent_batch", "resource_ref": "RB-HTTP", "note": "同批", "evidence": {}}
        ],
        "evidence": [], "created_by": "质量负责人",
    })
    assert created.status_code == 201, created.text
    event_id = created.json()["id"]
    candidates = client.get(f"/api/forensics/quality-events/{event_id}/candidates", headers=headers)
    assert candidates.status_code == 200
    candidate = next(c for c in candidates.json() if c["examination"]["examination_no"] == "TEX-M")
    decision = client.post(
        f"/api/forensics/quality-events/{event_id}/candidates/{candidate['id']}/decision",
        headers=headers,
        json={"action": "confirm", "reason": "HTTP 链路确认", "expected_version": 1, "actor": "调查员"},
    )
    assert decision.status_code == 200, decision.text
    body = decision.json()
    assert body["disposition"]["status"] == "active"
    assert body["specimen"]["id"]
    reviews = client.get("/api/forensics/withdrawal-reviews", headers=headers)
    assert reviews.status_code == 200
    assert exam_id  # 种子检验可被事件候选追溯
