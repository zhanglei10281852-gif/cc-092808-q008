from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from app.core.errors import NotFoundError


JSON_COLUMNS = {
    "case_profile_json": "passport",
    "contact_json": "restrictions",
    "detail_json": "detail",
    "payload_json": "payload",
    "rules_json": "rules",
    "hit_paths_json": "hit_paths",
    "result_json": "result",
}


def record(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    for column, target in JSON_COLUMNS.items():
        if column in data:
            raw = data.pop(column)
            try:
                data[target] = json.loads(raw or "{}")
            except json.JSONDecodeError:
                data[target] = {}
    return data


def records(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [record(row) or {} for row in rows]


class ForensicRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def require_agency(self, agency_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM submitting_agencies WHERE id=?", (agency_id,)).fetchone())
        if item is None:
            raise NotFoundError("来源记录不存在")
        return item

    def require_forensic_case(self, case_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM forensic_cases WHERE id=?", (case_id,)).fetchone())
        if item is None:
            raise NotFoundError("鉴定案件不存在")
        return item

    def forensic_case_by_number(self, case_no: str) -> dict[str, Any] | None:
        return record(self.connection.execute("SELECT * FROM forensic_cases WHERE case_no=?", (case_no,)).fetchone())

    def forensic_case_detail(self, case_id: int) -> dict[str, Any]:
        item = self.require_forensic_case(case_id)
        if item.get("agency_id"):
            item["source"] = self.require_agency(int(item["agency_id"]))
        item["lots"] = records(self.connection.execute(
            "SELECT * FROM specimens WHERE case_id=? ORDER BY created_at,specimen_no", (case_id,)
        ).fetchall())
        item["events"] = records(self.connection.execute(
            "SELECT * FROM case_events WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall())
        return item

    def list_forensic_cases(self, *, status: str | None, crop: str | None, limit: int, offset: int) -> tuple[list[dict], int]:
        where: list[str] = []
        params: list[Any] = []
        if status:
            where.append("status=?")
            params.append(status)
        if crop:
            where.append("discipline LIKE ?")
            params.append(f"%{crop.strip()}%")
        clause = " WHERE " + " AND ".join(where) if where else ""
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM forensic_cases{clause}", params).fetchone()[0])
        params.extend([limit, offset])
        rows = self.connection.execute(
            f"SELECT * FROM forensic_cases{clause} ORDER BY accepted_on DESC,case_no LIMIT ? OFFSET ?", params
        ).fetchall()
        return records(rows), total

    def require_location(self, location_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM storage_locations WHERE id=?", (location_id,)).fetchone())
        if item is None:
            raise NotFoundError("库位不存在")
        return item

    def location_usage(self, location_id: int) -> float:
        row = self.connection.execute(
            "SELECT COALESCE(SUM(quantity),0) FROM specimen_placements WHERE location_id=? AND removed_at IS NULL",
            (location_id,),
        ).fetchone()
        return float(row[0])

    def location_detail(self, location_id: int) -> dict[str, Any]:
        item = self.require_location(location_id)
        item["used_grams"] = self.location_usage(location_id)
        item["available_grams"] = round(float(item["capacity_units"]) - item["used_grams"], 6)
        item["placements"] = records(self.connection.execute(
            "SELECT p.*,l.specimen_no FROM specimen_placements p JOIN specimens l ON l.id=p.specimen_id "
            "WHERE p.location_id=? AND p.removed_at IS NULL ORDER BY p.container_code", (location_id,)
        ).fetchall())
        return item

    def require_specimen(self, specimen_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM specimens WHERE id=?", (specimen_id,)).fetchone())
        if item is None:
            raise NotFoundError("检材不存在")
        return item

    def active_holds(self, specimen_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM specimen_holds WHERE specimen_id=? AND released_at IS NULL ORDER BY id", (specimen_id,)
        ).fetchall())

    def specimen_detail(self, specimen_id: int) -> dict[str, Any]:
        item = self.require_specimen(specimen_id)
        item["forensic_case"] = self.require_forensic_case(int(item["case_id"]))
        item["placements"] = records(self.connection.execute(
            "SELECT p.*,s.location_code FROM specimen_placements p JOIN storage_locations s ON s.id=p.location_id "
            "WHERE p.specimen_id=? ORDER BY p.id", (specimen_id,)
        ).fetchall())
        item["movements"] = records(self.connection.execute(
            "SELECT * FROM custody_events WHERE specimen_id=? ORDER BY id", (specimen_id,)
        ).fetchall())
        item["holds"] = records(self.connection.execute(
            "SELECT * FROM specimen_holds WHERE specimen_id=? ORDER BY id", (specimen_id,)
        ).fetchall())
        item["latest_examination"] = record(self.connection.execute(
            "SELECT * FROM examinations WHERE specimen_id=? AND status='completed' ORDER BY completed_at DESC,id DESC LIMIT 1",
            (specimen_id,),
        ).fetchone())
        return item

    def require_placement(self, placement_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM specimen_placements WHERE id=?", (placement_id,)).fetchone())
        if item is None:
            raise NotFoundError("容器摆放记录不存在")
        return item

    def custody_event_by_key(self, key: str) -> dict[str, Any] | None:
        return record(self.connection.execute("SELECT * FROM custody_events WHERE idempotency_key=?", (key,)).fetchone())

    def require_protocol(self, protocol_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM examination_protocols WHERE id=?", (protocol_id,)).fetchone())
        if item is None:
            raise NotFoundError("检验规程不存在")
        return item

    def protocol_latest(self, code: str) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM examination_protocols WHERE protocol_code=? ORDER BY version DESC LIMIT 1", (code,)
        ).fetchone())

    def require_examination(self, examination_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM examinations WHERE id=?", (examination_id,)).fetchone())
        if item is None:
            raise NotFoundError("检验任务不存在")
        return item

    def examination_detail(self, examination_id: int) -> dict[str, Any]:
        item = self.require_examination(examination_id)
        item["specimen"] = self.require_specimen(int(item["specimen_id"]))
        item["protocol"] = self.require_protocol(int(item["protocol_id"]))
        item["counts"] = records(self.connection.execute(
            "SELECT * FROM examination_observations WHERE examination_id=? ORDER BY checkpoint_no,sequence_no", (examination_id,)
        ).fetchall())
        item["resources"] = self.examination_resources(examination_id)
        item["reports"] = self.reports_for_examination(examination_id)
        item["active_review_flags"] = records(self.connection.execute(
            "SELECT f.*,i.incident_no FROM examination_review_flags f "
            "JOIN quality_incidents i ON i.id=f.incident_id "
            "WHERE f.examination_id=? AND f.status='pending' ORDER BY f.id", (examination_id,)
        ).fetchall())
        return item

    def require_policy(self, policy_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM review_policies WHERE id=?", (policy_id,)).fetchone())
        if item is None:
            raise NotFoundError("复核策略不存在")
        return item

    def applicable_policy(self, discipline: str, risk_level: str, on_date: str) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM review_policies WHERE discipline=? AND risk_level=? AND effective_from<=? "
            "AND (effective_to IS NULL OR effective_to>=?) ORDER BY version DESC LIMIT 1",
            (discipline, risk_level, on_date, on_date),
        ).fetchone())

    def require_alert(self, alert_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM quality_alerts WHERE id=?", (alert_id,)).fetchone())
        if item is None:
            raise NotFoundError("质量告警不存在")
        return item

    def require_release(self, request_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM release_requests WHERE id=?", (request_id,)).fetchone())
        if item is None:
            raise NotFoundError("领用申请不存在")
        return item

    # ---- 质量事件影响追踪 ----
    def require_incident(self, incident_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM quality_incidents WHERE id=?", (incident_id,)).fetchone())
        if item is None:
            raise NotFoundError("质量事件不存在")
        return item

    def incident_by_number(self, incident_no: str) -> dict[str, Any] | None:
        return record(self.connection.execute("SELECT * FROM quality_incidents WHERE incident_no=?", (incident_no,)).fetchone())

    def list_incidents(self, *, status: str | None, limit: int, offset: int) -> tuple[list[dict], int]:
        where = " WHERE status=?" if status else ""
        params: list[Any] = [status] if status else []
        total = int(self.connection.execute(f"SELECT COUNT(*) FROM quality_incidents{where}", params).fetchone()[0])
        rows = self.connection.execute(
            f"SELECT * FROM quality_incidents{where} ORDER BY id DESC LIMIT ? OFFSET ?", (*params, limit, offset)
        ).fetchall()
        return records(rows), total

    def incident_rule_version(self, incident_id: int, version: int) -> dict[str, Any]:
        item = record(self.connection.execute(
            "SELECT * FROM incident_rule_versions WHERE incident_id=? AND version=?", (incident_id, version)
        ).fetchone())
        if item is None:
            raise NotFoundError("事件规则版本不存在")
        return item

    def incident_active_rules(self, incident_id: int) -> dict[str, Any] | None:
        incident = self.require_incident(incident_id)
        if incident.get("active_rule_version") is None:
            return None
        return self.incident_rule_version(incident_id, int(incident["active_rule_version"]))

    def incident_evidence(self, incident_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM incident_evidence WHERE incident_id=? ORDER BY id", (incident_id,)
        ).fetchall())

    def incident_resources(self, incident_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM incident_resources WHERE incident_id=? ORDER BY id", (incident_id,)
        ).fetchall())

    def incident_rule_versions(self, incident_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM incident_rule_versions WHERE incident_id=? ORDER BY version", (incident_id,)
        ).fetchall())

    def incident_evaluations(self, incident_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM impact_evaluations WHERE incident_id=? ORDER BY id", (incident_id,)
        ).fetchall())

    def require_evaluation(self, evaluation_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM impact_evaluations WHERE id=?", (evaluation_id,)).fetchone())
        if item is None:
            raise NotFoundError("影响评估不存在")
        return item

    def require_candidate(self, candidate_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM impact_candidates WHERE id=?", (candidate_id,)).fetchone())
        if item is None:
            raise NotFoundError("影响候选不存在")
        return item

    def candidate_by_examination(self, incident_id: int, examination_id: int) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM impact_candidates WHERE incident_id=? AND examination_id=?", (incident_id, examination_id)
        ).fetchone())

    def incident_candidates(self, incident_id: int, *, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.connection.execute(
                "SELECT * FROM impact_candidates WHERE incident_id=? AND status=? ORDER BY id", (incident_id, status)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM impact_candidates WHERE incident_id=? ORDER BY id", (incident_id,)
            ).fetchall()
        return records(rows)

    def candidate_dispositions(self, candidate_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM impact_dispositions WHERE candidate_id=? ORDER BY id", (candidate_id,)
        ).fetchall())

    def incident_decisions(self, incident_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM incident_decisions WHERE incident_id=? ORDER BY id", (incident_id,)
        ).fetchall())

    def examination_resources(self, examination_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM examination_resources WHERE examination_id=? ORDER BY id", (examination_id,)
        ).fetchall())

    def examination_resource_by_key(
        self, examination_id: int, resource_type: str, resource_ref: str, used_from: str
    ) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM examination_resources WHERE examination_id=? AND resource_type=? AND resource_ref=? AND used_from=?",
            (examination_id, resource_type, resource_ref, used_from),
        ).fetchone())

    def require_report(self, report_id: int) -> dict[str, Any]:
        item = record(self.connection.execute("SELECT * FROM examination_reports WHERE id=?", (report_id,)).fetchone())
        if item is None:
            raise NotFoundError("鉴定意见报告不存在")
        return item

    def report_by_number(self, report_no: str) -> dict[str, Any] | None:
        return record(self.connection.execute("SELECT * FROM examination_reports WHERE report_no=?", (report_no,)).fetchone())

    def reports_for_examination(self, examination_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM examination_reports WHERE examination_id=? ORDER BY id", (examination_id,)
        ).fetchall())

    def active_review_flag(self, incident_id: int, examination_id: int) -> dict[str, Any] | None:
        return record(self.connection.execute(
            "SELECT * FROM examination_review_flags WHERE incident_id=? AND examination_id=? AND status='pending'",
            (incident_id, examination_id),
        ).fetchone())

    def open_incidents_matching_resource(self, resource_type: str, resource_ref: str) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT i.* FROM quality_incidents i JOIN incident_resources r ON r.incident_id=i.id "
            "WHERE i.status!='closed' AND r.resource_type=? AND r.resource_ref=? ORDER BY i.id",
            (resource_type, resource_ref),
        ).fetchall())

    def release_detail(self, request_id: int) -> dict[str, Any]:
        item = self.require_release(request_id)
        item["items"] = records(self.connection.execute(
            "SELECT i.*,a.case_no,a.discipline FROM release_items i "
            "JOIN forensic_cases a ON a.id=i.case_id WHERE i.request_id=? ORDER BY i.id", (request_id,)
        ).fetchall())
        return item

    def count_table(self, table: str) -> int:
        allowed = {
            "forensic_cases", "specimens", "storage_locations", "examinations",
            "review_schedules", "quality_alerts", "release_requests",
            "quality_incidents", "impact_candidates", "impact_evaluations",
        }
        if table not in allowed:
            raise ValueError("不允许统计该数据表")
        return int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
