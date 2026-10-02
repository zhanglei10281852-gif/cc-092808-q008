from __future__ import annotations

from datetime import UTC, datetime

import pytest


def _setup_case(client, headers, suffix="1") -> dict:
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": f"API-ORG-{suffix}", "agency_name": "公安分局", "jurisdiction_code": "CN",
        "contact_address": "司法路", "restrictions": {}})
    assert agency.status_code == 201, agency.text
    case = client.post("/api/forensics/cases", headers=headers, json={
        "case_no": f"API-CASE-{suffix}", "case_name": "毒物鉴定", "discipline": "法医毒物",
        "entrusted_matter": "成分分析", "agency_id": agency.json()["id"], "case_source": "委托",
        "accepted_on": "2026-09-01", "passport": {}, "created_by": "登记员"})
    assert case.status_code == 201, case.text
    accepted = client.post(f"/api/forensics/cases/{case.json()['id']}/transition", headers=headers, json={
        "target_status": "accepted", "reason": "齐全", "expected_version": 1, "actor": "审核员"})
    assert accepted.status_code == 200, accepted.text
    loc = client.post("/api/forensics/locations", headers=headers, json={
        "location_code": f"API-L-{suffix}", "facility": "库", "room": "室", "rack": "R", "shelf": "S",
        "capacity_units": 1000, "reference_value": 4, "humidity_percent": 40})
    assert loc.status_code == 201, loc.text
    sp = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": f"API-SP-{suffix}", "case_id": accepted.json()["id"], "received_year": 2026,
        "initial_quantity": 100, "integrity_percent": 100, "packaging": "", "created_by": "登记员"})
    assert sp.status_code == 201, sp.text
    place = client.post("/api/forensics/placements", headers=headers, json={
        "specimen_id": sp.json()["id"], "location_id": loc.json()["id"], "quantity": 100,
        "container_code": f"API-BOX-{suffix}", "idempotency_key": f"api-place-{suffix}", "actor": "保管员"})
    assert place.status_code == 201, place.text
    proto = client.post("/api/forensics/protocols", headers=headers, json={
        "protocol_code": f"API-TOX-{suffix}", "discipline": "法医毒物", "observation_target": 10,
        "checkpoint_count": 1, "reference_value": 1, "turnaround_days": 1,
        "conclusion_rule": "按内标判定", "created_by": "负责人"})
    assert proto.status_code == 201, proto.text
    exam = client.post("/api/forensics/examinations", headers=headers, json={
        "examination_no": f"API-EX-{suffix}", "specimen_id": sp.json()["id"],
        "protocol_id": proto.json()["id"], "examination_type": "补充检验", "sample_quantity": 2,
        "scheduled_for": "2026-09-10", "requested_by": "检验员",
        "idempotency_key": f"api-sched-{suffix}"})
    assert exam.status_code == 201, exam.text
    started = client.post(f"/api/forensics/examinations/{exam.json()['id']}/start", headers=headers, json={
        "performed_by": "检验员", "expected_version": 1})
    assert started.status_code == 200, started.text
    obs = client.post(f"/api/forensics/examinations/{exam.json()['id']}/observations", headers=headers, json={
        "checkpoint_no": 1, "items_checked": 10, "conforming_count": 9, "exception_count": 1,
        "unusable_count": 0, "pending_count": 0, "sequence_no": 1, "observed_by": "检验员"})
    assert obs.status_code == 201, obs.text
    done = client.post(f"/api/forensics/examinations/{exam.json()['id']}/complete", headers=headers, json={
        "performed_by": "检验员", "expected_version": 2})
    assert done.status_code == 200, done.text
    return {"case_id": accepted.json()["id"], "specimen_id": sp.json()["id"], "examination_id": exam.json()["id"]}


def test_full_incident_lifecycle_over_http(client, admin):
    headers = admin["headers"]
    target = _setup_case(client, headers, "1")
    other = _setup_case(client, headers, "2")

    # 资源台账：目标检验使用污染批次 RB-77，另一检验使用 RB-99
    for exam_id, ref in [(target["examination_id"], "RB-77"), (other["examination_id"], "RB-99")]:
        resp = client.post(f"/api/forensics/examinations/{exam_id}/resources", headers=headers, json={
            "resource_type": "reagent_batch", "resource_ref": ref,
            "used_from": "2026-09-15T10:00:00Z", "used_to": "2026-09-15T12:00:00Z",
            "source": "on_time", "recorded_by": "检验员"})
        assert resp.status_code == 201, resp.text

    # 目标检验已签发报告
    report = client.post(f"/api/forensics/examinations/{target['examination_id']}/reports", headers=headers, json={
        "report_no": "API-RPT-1", "opinion_text": "未检出", "result": {"结论": "阴性"},
        "issued_by": "授权签字人", "issued_at": "2026-09-16T09:00:00Z"})
    assert report.status_code == 201, report.text

    # 登记质量事件
    incident = client.post("/api/forensics/incidents", headers=headers, json={
        "incident_no": "API-QE-1", "title": "空白对照污染", "description": "RB-77",
        "window_start": "2026-09-14T00:00:00Z", "window_end": "2026-09-17T00:00:00Z",
        "created_by": "质量负责人",
        "resources": [{"resource_type": "reagent_batch", "resource_ref": "RB-77",
                       "note": "可疑批次", "created_by": "质量负责人"}],
        "evidence": [{"evidence_type": "空白对照", "reference": "BLANK-API-1",
                      "detail": {"ct": 30}, "created_by": "质量负责人"}]})
    assert incident.status_code == 201, incident.text
    inc = incident.json()
    assert inc["candidate_counts"] == {"candidate": 1, "excluded": 0, "confirmed": 0}
    assert inc["candidates"][0]["examination_id"] == target["examination_id"]
    assert inc["evaluations"][0]["status"] == "completed"

    # 候选详情带命中路径与追踪链
    cid = inc["candidates"][0]["id"]
    detail = client.get(f"/api/forensics/impact-candidates/{cid}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["hit_paths"][0]["resource_ref"] == "RB-77"
    assert detail.json()["reports"][0]["report_no"] == "API-RPT-1"

    # 确认影响
    confirmed = client.post(f"/api/forensics/impact-candidates/{cid}/decision", headers=headers, json={
        "action": "confirm", "actor": "质量负责人", "reason": "资源与时间窗均吻合"})
    assert confirmed.status_code == 200, confirmed.text
    body = confirmed.json()
    assert body["status"] == "confirmed"
    assert len(body["dispositions"]) == 3
    assert body["withdrawal_reviews"][0]["status"] == "pending"
    assert body["review_flags"][0]["status"] == "pending"

    # 检材被冻结
    specimen = client.get(f"/api/forensics/specimens/{target['specimen_id']}", headers=headers)
    assert specimen.json()["status"] == "held"

    # 待复核检验不能再签发
    blocked = client.post(f"/api/forensics/examinations/{target['examination_id']}/reports", headers=headers, json={
        "report_no": "API-RPT-1B", "opinion_text": "补充", "result": {}, "issued_by": "签字人"})
    assert blocked.status_code == 409

    # 撤回审查结论：撤回原意见，原报告仍保持原文
    review_id = body["withdrawal_reviews"][0]["id"]
    decision = client.post(f"/api/forensics/withdrawal-reviews/{review_id}/decision", headers=headers, json={
        "decision": "withdraw", "actor": "技术负责人", "reason": "污染成立"})
    assert decision.status_code == 200, decision.text
    unchanged = client.get(f"/api/forensics/examinations/{target['examination_id']}", headers=headers)
    assert unchanged.json()["reports"][0]["opinion_text"] == "未检出"

    # 事件追踪视图聚合规则、资源、检验、处置、人工决定
    full = client.get(f"/api/forensics/incidents/{inc['id']}", headers=headers)
    assert full.status_code == 200
    payload = full.json()
    assert payload["open_dispositions"]["specimen_holds"] == 1
    assert payload["open_dispositions"]["withdrawal_reviews"] == 0
    decision_types = {d["decision_type"] for d in payload["decisions"]}
    assert {"rules_published", "candidate_confirmed", "withdrawal_review_decided"} <= decision_types

    # 清除待复核标志后检验可再次签发
    flag_id = body["review_flags"][0]["id"]
    cleared = client.post(f"/api/forensics/review-flags/{flag_id}/clear", headers=headers, json={
        "actor": "质量负责人", "note": "复检完成结果一致"})
    assert cleared.status_code == 200, cleared.text


def test_late_information_expands_candidates_over_http(client, admin):
    headers = admin["headers"]
    a = _setup_case(client, headers, "3")
    b = _setup_case(client, headers, "4")
    client.post(f"/api/forensics/examinations/{a['examination_id']}/resources", headers=headers, json={
        "resource_type": "reagent_batch", "resource_ref": "RB-77",
        "used_from": "2026-09-15T10:00:00Z", "used_to": "2026-09-15T12:00:00Z",
        "source": "on_time", "recorded_by": "检验员"})
    inc = client.post("/api/forensics/incidents", headers=headers, json={
        "incident_no": "API-QE-2", "title": "污染", "description": "",
        "window_start": "2026-09-14T00:00:00Z", "window_end": "2026-09-17T00:00:00Z",
        "created_by": "质量负责人",
        "resources": [{"resource_type": "reagent_batch", "resource_ref": "RB-77",
                       "note": "", "created_by": "质量负责人"}], "evidence": []})
    assert inc.json()["candidate_counts"]["candidate"] == 1

    # 迟到设备记录：先补登设备资源到事件，再给检验 b 补录该设备的迟到台账
    added = client.post(f"/api/forensics/incidents/{inc.json()['id']}/resources", headers=headers, json={
        "resource_type": "equipment", "resource_ref": "GC-9", "note": "迟到设备",
        "created_by": "质量负责人"})
    assert added.status_code == 201
    late = client.post(f"/api/forensics/examinations/{b['examination_id']}/resources", headers=headers, json={
        "resource_type": "equipment", "resource_ref": "GC-9",
        "used_from": "2026-09-15T14:00:00Z", "used_to": "2026-09-15T15:00:00Z",
        "source": "late", "recorded_by": "设备管理员"})
    assert late.status_code == 201, late.text
    assert late.json()["affected_incident_ids"] == [inc.json()["id"]]
    full = client.get(f"/api/forensics/incidents/{inc.json()['id']}", headers=headers).json()
    assert full["candidate_counts"]["candidate"] == 2


def test_evaluations_run_endpoint_resumes_pending_work(client, admin):
    headers = admin["headers"]
    a = _setup_case(client, headers, "5")
    client.post(f"/api/forensics/examinations/{a['examination_id']}/resources", headers=headers, json={
        "resource_type": "workbench", "resource_ref": "WB-1",
        "used_from": "2026-09-15T10:00:00Z", "used_to": "2026-09-15T11:00:00Z",
        "source": "on_time", "recorded_by": "检验员"})
    inc = client.post("/api/forensics/incidents", headers=headers, json={
        "incident_no": "API-QE-3", "title": "污染", "description": "",
        "window_start": "2026-09-14T00:00:00Z", "window_end": "2026-09-17T00:00:00Z",
        "created_by": "质量负责人",
        "resources": [{"resource_type": "workbench", "resource_ref": "WB-1",
                       "note": "", "created_by": "质量负责人"}], "evidence": []})
    assert inc.json()["evaluations"][0]["status"] == "completed"
    # 无待处理任务时运行端点返回空
    run = client.post("/api/forensics/incidents-evaluations/run", headers=headers)
    assert run.status_code == 200
    assert run.json()["processed"] == 0


def test_incident_endpoints_require_authentication(client):
    assert client.get("/api/forensics/incidents").status_code == 401
    assert client.post("/api/forensics/incidents", json={}).status_code == 401


def test_excluded_false_positive_recorded_over_http(client, admin):
    headers = admin["headers"]
    a = _setup_case(client, headers, "6")
    client.post(f"/api/forensics/examinations/{a['examination_id']}/resources", headers=headers, json={
        "resource_type": "reagent_batch", "resource_ref": "RB-77",
        "used_from": "2026-09-15T10:00:00Z", "used_to": "2026-09-15T12:00:00Z",
        "source": "on_time", "recorded_by": "检验员"})
    inc = client.post("/api/forensics/incidents", headers=headers, json={
        "incident_no": "API-QE-4", "title": "污染", "description": "",
        "window_start": "2026-09-14T00:00:00Z", "window_end": "2026-09-17T00:00:00Z",
        "created_by": "质量负责人",
        "resources": [{"resource_type": "reagent_batch", "resource_ref": "RB-77",
                       "note": "", "created_by": "质量负责人"}], "evidence": []}).json()
    cid = inc["candidates"][0]["id"]
    excluded = client.post(f"/api/forensics/impact-candidates/{cid}/decision", headers=headers, json={
        "action": "exclude", "actor": "调查员", "reason": "该检验使用独立进样针，有隔离记录"})
    assert excluded.status_code == 200
    assert excluded.json()["status"] == "excluded"
    # 可关闭
    current = client.get(f"/api/forensics/incidents/{inc['id']}", headers=headers).json()
    closed = client.post(f"/api/forensics/incidents/{inc['id']}/close", headers=headers, json={
        "expected_version": current["version"], "actor": "质量负责人", "reason": "误报排除"})
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
