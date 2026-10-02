from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, ValidationError
from app.forensics.repository import ForensicRepository, record, records

EVALUATION_BATCH_SIZE = 200
EVALUATION_LEASE_SECONDS = 60


class IncidentService:
    """质量事件影响追踪：登记事件与规则、确定性评估候选、人工决定与原子处置。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)

    # ------------------------------------------------------------------
    # 数据面：检验资源使用台账与已签发报告
    # ------------------------------------------------------------------
    def register_examination_resource(self, examination_id: int, data: dict[str, Any]) -> dict[str, Any]:
        examination = self.repository.require_examination(examination_id)
        resource_type = data["resource_type"]
        resource_ref = data["resource_ref"].strip()
        used_from = to_storage(data["used_from"])
        used_to = to_storage(data["used_to"])
        timestamp = to_storage(self.clock.now())
        previous = self.repository.examination_resource_by_key(examination_id, resource_type, resource_ref, used_from)
        replayed = False
        if previous:
            replayed = True
            row = previous
        else:
            try:
                cursor = self.connection.execute(
                    "INSERT INTO examination_resources(examination_id,resource_type,resource_ref,used_from,used_to,"
                    "source,recorded_by,recorded_at) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        examination_id, resource_type, resource_ref, used_from, used_to,
                        data.get("source", "on_time"), data["recorded_by"], timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("该检验的同一资源使用时段已经登记") from exc
            row = record(self.connection.execute(
                "SELECT * FROM examination_resources WHERE id=?", (cursor.lastrowid,)
            ).fetchone()) or {}
        # 迟到信息确定性扩展相关未关闭事件的候选
        affected_incidents: list[int] = []
        if data.get("source") == "late":
            timestamp_late = to_storage(self.clock.now())
            affected_incidents = self._enqueue_for_resource(resource_type, resource_ref, "late_usage", timestamp_late)
            for incident_id in affected_incidents:
                self.run_incident_evaluations(incident_id, worker=f"late_usage:{data['recorded_by']}")
        return {
            "resource": row,
            "replayed": replayed,
            "examination_no": examination["examination_no"],
            "affected_incident_ids": affected_incidents,
        }

    def issue_report(self, examination_id: int, data: dict[str, Any]) -> dict[str, Any]:
        examination = self.repository.require_examination(examination_id)
        if examination["status"] != "completed":
            raise ConflictError("只有已完成的检验可以签发鉴定意见")
        if self.repository.report_by_number(data["report_no"]):
            raise ConflictError("报告编号已经存在")
        # 报告签发前若检验已被标志待复核，则阻止签发（受影响结果不能继续复核签发）
        pending = self.connection.execute(
            "SELECT id FROM examination_review_flags WHERE examination_id=? AND status='pending' LIMIT 1",
            (examination_id,),
        ).fetchone()
        if pending:
            raise ConflictError("该检验结果已被质量事件标志为待复核，不能继续签发", context={
                "review_flag_id": pending[0]
            })
        timestamp = to_storage(self.clock.now())
        issued_at = to_storage(data["issued_at"]) if data.get("issued_at") else timestamp
        cursor = self.connection.execute(
            "INSERT INTO examination_reports(report_no,examination_id,opinion_text,result_json,issued_by,issued_at,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                data["report_no"], examination_id, data["opinion_text"],
                json.dumps(data.get("result", {}), ensure_ascii=False, sort_keys=True),
                data["issued_by"], issued_at, timestamp,
            ),
        )
        return self.repository.require_report(int(cursor.lastrowid))

    # ------------------------------------------------------------------
    # 事件登记与规则版本
    # ------------------------------------------------------------------
    def create_incident(self, data: dict[str, Any]) -> dict[str, Any]:
        if self.repository.incident_by_number(data["incident_no"]):
            raise ConflictError("质量事件编号已经存在")
        window_start = to_storage(data["window_start"])
        window_end = to_storage(data["window_end"])
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO quality_incidents(incident_no,title,description,window_start,window_end,window_slack_minutes,"
            "status,version,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,'open',1,?,?,?)",
            (
                data["incident_no"], data["title"], data.get("description", ""), window_start, window_end,
                int(data.get("rule_window_slack_minutes", 0)), data["created_by"], timestamp, timestamp,
            ),
        )
        incident_id = int(cursor.lastrowid)
        for evidence in data.get("evidence", []):
            self.connection.execute(
                "INSERT INTO incident_evidence(incident_id,evidence_type,reference,detail_json,created_by,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    incident_id, evidence["evidence_type"], evidence["reference"],
                    json.dumps(evidence.get("detail", {}), ensure_ascii=False, sort_keys=True),
                    evidence.get("created_by") or data["created_by"], timestamp,
                ),
            )
        # 登记时按初始资源生成第 1 版规则
        resources = self._normalize_resources(data.get("resources", []))
        self._insert_resources(incident_id, resources, rule_version=1, actor=data["created_by"], timestamp=timestamp)
        self._publish_rules(incident_id, version=1, resources=resources, actor=data["created_by"],
                            note="事件登记时生成初始规则", timestamp=timestamp)
        self._decision(incident_id, None, "rules_published", data["created_by"],
                       "事件登记时生成初始规则", {"version": 1}, timestamp)
        self._enqueue_evaluation(incident_id, rule_version=1, trigger="register", timestamp=timestamp)
        self.run_incident_evaluations(incident_id, worker=f"register:{data['created_by']}")
        return self.incident_detail(incident_id)

    def update_rules(self, incident_id: int, data: dict[str, Any]) -> dict[str, Any]:
        incident = self.repository.require_incident(incident_id)
        if incident["status"] == "closed":
            raise ConflictError("已关闭的事件不能修改规则")
        if int(incident["version"]) != int(data["expected_version"]):
            raise ConflictError("质量事件版本冲突", context={"current_version": incident["version"]})
        timestamp = to_storage(self.clock.now())
        window_start = to_storage(data["window_start"]) if data.get("window_start") else incident["window_start"]
        window_end = to_storage(data["window_end"]) if data.get("window_end") else incident["window_end"]
        if window_end <= window_start:
            raise ValidationError("污染时间窗结束时间必须晚于开始时间")
        slack = (
            int(data["rule_window_slack_minutes"])
            if data.get("rule_window_slack_minutes") is not None
            else int(incident["window_slack_minutes"])
        )
        new_resources = self._normalize_resources(data["resources"]) if data.get("resources") is not None else None
        if new_resources is not None:
            self._insert_resources(incident_id, new_resources,
                                   rule_version=int(incident["active_rule_version"] or 0) + 1,
                                   actor=data["actor"], timestamp=timestamp)
        current = self.repository.incident_resources(incident_id)
        next_version = int(incident["active_rule_version"] or 0) + 1
        self.connection.execute(
            "UPDATE quality_incidents SET window_start=?,window_end=?,window_slack_minutes=?,"
            "version=version+1,updated_at=? WHERE id=? AND version=?",
            (window_start, window_end, slack, timestamp, incident_id, data["expected_version"]),
        )
        self._publish_rules(incident_id, version=next_version, resources=current, actor=data["actor"],
                            note=data.get("note", "发布新版本规则"), timestamp=timestamp)
        self._decision(incident_id, None, "rules_published", data["actor"], data.get("note", ""),
                       {"version": next_version}, timestamp)
        self._enqueue_evaluation(incident_id, rule_version=next_version, trigger="rule_update", timestamp=timestamp)
        self.run_incident_evaluations(incident_id, worker=f"rules:{data['actor']}")
        return self.incident_detail(incident_id)

    def add_incident_resource(self, incident_id: int, data: dict[str, Any]) -> dict[str, Any]:
        """质量人员补登一个可疑资源标识（迟到的设备/试剂批次信息）。重复登记幂等，不产生新版本。"""
        incident = self.repository.require_incident(incident_id)
        if incident["status"] == "closed":
            raise ConflictError("已关闭的事件不能补充资源")
        resources = self._normalize_resources([data])
        resource_type, resource_ref = resources[0]["resource_type"], resources[0]["resource_ref"]
        already = self.connection.execute(
            "SELECT id FROM incident_resources WHERE incident_id=? AND resource_type=? AND resource_ref=?",
            (incident_id, resource_type, resource_ref),
        ).fetchone()
        if already:
            # 相同资源标识重复补登是确定性的无操作，不再生成规则版本或评估
            return self.incident_detail(incident_id)
        timestamp = to_storage(self.clock.now())
        next_version = int(incident["active_rule_version"] or 0) + 1
        self._insert_resources(incident_id, resources, rule_version=next_version,
                               actor=data["created_by"], timestamp=timestamp)
        current = self.repository.incident_resources(incident_id)
        self.connection.execute(
            "UPDATE quality_incidents SET version=version+1,updated_at=? WHERE id=?", (timestamp, incident_id)
        )
        self._publish_rules(incident_id, version=next_version, resources=current, actor=data["created_by"],
                            note=f"补充资源 {data['resource_type']}:{data['resource_ref']}", timestamp=timestamp)
        self._decision(incident_id, None, "rules_published", data["created_by"],
                       f"补充资源 {data['resource_type']}:{data['resource_ref']}",
                       {"version": next_version}, timestamp)
        self._enqueue_evaluation(incident_id, rule_version=next_version, trigger="late_resource", timestamp=timestamp)
        self.run_incident_evaluations(incident_id, worker=f"late_resource:{data['created_by']}")
        return self.incident_detail(incident_id)

    # ------------------------------------------------------------------
    # 影响评估（可恢复、确定性、分批）
    # ------------------------------------------------------------------
    def _publish_rules(
        self, incident_id: int, *, version: int, resources: list[dict[str, Any]],
        actor: str, note: str, timestamp: str,
    ) -> None:
        self.connection.execute(
            "UPDATE incident_rule_versions SET status='superseded' WHERE incident_id=? AND status='active'",
            (incident_id,),
        )
        rules = self._build_rules(resources)
        self.connection.execute(
            "INSERT INTO incident_rule_versions(incident_id,version,rules_json,status,note,created_by,created_at) "
            "VALUES(?,?,?,'active',?,?,?)",
            (incident_id, version, json.dumps(rules, ensure_ascii=False, sort_keys=True), note, actor, timestamp),
        )
        self.connection.execute(
            "UPDATE quality_incidents SET active_rule_version=?,updated_at=? WHERE id=?",
            (version, timestamp, incident_id),
        )

    def _build_rules(self, resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "rule_id": f"{item['resource_type']}:{item['resource_ref']}",
                "resource_type": item["resource_type"],
                "resource_ref": item["resource_ref"],
            }
            for item in resources
        ]

    def _insert_resources(
        self, incident_id: int, resources: list[dict[str, Any]], *,
        rule_version: int, actor: str, timestamp: str,
    ) -> None:
        for item in resources:
            self.connection.execute(
                "INSERT INTO incident_resources(incident_id,resource_type,resource_ref,note,added_rule_version,"
                "created_by,created_at) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(incident_id,resource_type,resource_ref) DO UPDATE SET note=excluded.note",
                (
                    incident_id, item["resource_type"], item["resource_ref"], item.get("note", ""),
                    rule_version, actor, timestamp,
                ),
            )

    def _enqueue_evaluation(self, incident_id: int, *, rule_version: int, trigger: str, timestamp: str) -> dict[str, Any]:
        key = f"incident-{incident_id}-rules-v{rule_version}-{trigger}"
        self.connection.execute(
            "INSERT OR IGNORE INTO impact_evaluations(incident_id,rule_version,trigger,deduplication_key,status,"
            "cursor_rule,cursor_key,created_at,updated_at) VALUES(?,?,?,?,'pending',0,0,?,?)",
            (incident_id, rule_version, trigger, key, timestamp, timestamp),
        )
        return record(self.connection.execute(
            "SELECT * FROM impact_evaluations WHERE deduplication_key=?", (key,)
        ).fetchone()) or {}

    def _enqueue_for_resource(self, resource_type: str, resource_ref: str, trigger: str, timestamp: str) -> list[int]:
        """迟到台账数据：为引用该资源且未关闭的事件确定性地创建评估。"""
        incidents = self.repository.open_incidents_matching_resource(resource_type, resource_ref)
        affected: list[int] = []
        for incident in incidents:
            version = int(incident["active_rule_version"])
            # 资源标识参与去重键，同一批迟到数据重复登记不会产生第二份有效评估
            key = f"incident-{incident['id']}-rules-v{version}-{trigger}-{resource_type}:{resource_ref}"
            self.connection.execute(
                "INSERT OR IGNORE INTO impact_evaluations(incident_id,rule_version,trigger,deduplication_key,status,"
                "cursor_rule,cursor_key,created_at,updated_at) VALUES(?,?,?,?,'pending',0,0,?,?)",
                (incident["id"], version, trigger, key, timestamp, timestamp),
            )
            affected.append(int(incident["id"]))
        return affected

    def run_pending_evaluations(
        self, *, worker: str = "scheduler", batch_size: int = EVALUATION_BATCH_SIZE, max_batches: int = 10,
    ) -> list[dict[str, Any]]:
        """推进未完成评估；每轮至多 max_batches 批，未完成评估保留游标，稍后或服务重启后可继续。"""
        results: list[dict[str, Any]] = []
        for _ in range(max(1, max_batches)):
            evaluation = self._claim_due_evaluation(worker)
            if evaluation is None:
                break
            results.append(self.run_evaluation(int(evaluation["id"]), worker=worker, batch_size=batch_size))
        return results

    def run_incident_evaluations(
        self, incident_id: int, *, worker: str = "inline", batch_size: int = EVALUATION_BATCH_SIZE,
    ) -> list[dict[str, Any]]:
        """同步推进某事件全部评估（大批次，单次 API 调用内完成）；游标保证可重复续跑。"""
        results: list[dict[str, Any]] = []
        for _ in range(10_000):
            row = self.connection.execute(
                "SELECT * FROM impact_evaluations WHERE incident_id=? AND status='pending' ORDER BY id LIMIT 1",
                (incident_id,),
            ).fetchone()
            if row is None:
                break
            evaluation = self.run_evaluation(int(row["id"]), worker=worker, batch_size=batch_size)
            results.append(evaluation)
            if evaluation["status"] != "completed":
                break
        return results

    def _claim_due_evaluation(self, worker: str) -> dict[str, Any] | None:
        timestamp = to_storage(self.clock.now())
        stale = to_storage(self.clock.now() - timedelta(seconds=EVALUATION_LEASE_SECONDS))
        # 崩溃或服务重启后，超过租约仍处于 running 的评估回到 pending，按游标续跑
        self.connection.execute(
            "UPDATE impact_evaluations SET status='pending',locked_by=NULL,locked_at=NULL,updated_at=? "
            "WHERE status='running' AND (locked_at IS NULL OR locked_at<?)",
            (timestamp, stale),
        )
        row = self.connection.execute(
            "SELECT * FROM impact_evaluations WHERE status='pending' ORDER BY id LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        cursor = self.connection.execute(
            "UPDATE impact_evaluations SET status='running',attempts=attempts+1,locked_by=?,locked_at=?,updated_at=? "
            "WHERE id=? AND status='pending' RETURNING *",
            (worker, timestamp, timestamp, row["id"]),
        )
        claimed = cursor.fetchone()
        return record(claimed) if claimed else None

    def run_evaluation(self, evaluation_id: int, *, worker: str = "manual", batch_size: int = EVALUATION_BATCH_SIZE) -> dict[str, Any]:
        evaluation = self.repository.require_evaluation(evaluation_id)
        incident = self.repository.require_incident(int(evaluation["incident_id"]))
        rules_snapshot = self.repository.incident_rule_version(
            int(incident["id"]), int(evaluation["rule_version"])
        )["rules"]
        timestamp = to_storage(self.clock.now())
        if evaluation["status"] == "completed":
            # 已完成评估重放是确定性无操作，不重新扫描、不清空统计
            return evaluation
        if evaluation["status"] == "pending":
            self.connection.execute(
                "UPDATE impact_evaluations SET status='running',attempts=attempts+1,locked_by=?,locked_at=?,updated_at=? "
                "WHERE id=?",
                (worker, timestamp, timestamp, evaluation_id),
            )
            evaluation = self.repository.require_evaluation(evaluation_id)
        # 时间窗宽限（分钟）：仅放宽资源使用区间与污染窗的重叠判定
        window_start, window_end = self._effective_window(incident)
        rule_index = int(evaluation["cursor_rule"])
        cursor_key = int(evaluation["cursor_key"])
        scanned = int(evaluation["scanned_count"])
        budget = max(1, batch_size)
        added_total = int(evaluation["added_count"])
        matched_total = int(evaluation["matched_count"])
        completed = False
        partial = False
        while rule_index < len(rules_snapshot) and budget > 0:
            rule = rules_snapshot[rule_index]
            limit = max(1, min(budget, batch_size))
            batch = self.connection.execute(
                "SELECT r.*,e.examination_no,e.specimen_id,e.status AS examination_status,e.completed_at "
                "FROM examination_resources r JOIN examinations e ON e.id=r.examination_id "
                "WHERE r.resource_type=? AND r.resource_ref=? AND r.id>? "
                "AND r.used_from<=? AND r.used_to>=? ORDER BY r.id LIMIT ?",
                (
                    rule["resource_type"], rule["resource_ref"], cursor_key,
                    window_end, window_start, limit,
                ),
            ).fetchall()
            if not batch:
                rule_index += 1
                cursor_key = 0
                continue
            for usage in batch:
                cursor_key = int(usage["id"])
                scanned += 1
                budget -= 1
                hit_path = self._build_hit_path(rule, incident, window_start, window_end, dict(usage))
                added = self._upsert_candidate(
                    int(incident["id"]), int(usage["examination_id"]),
                    int(evaluation["rule_version"]), hit_path, timestamp,
                )
                matched_total += 1
                if added:
                    added_total += 1
            # 取满查询额度时当前规则可能仍有后续记录，保留游标下一轮续跑
            if len(batch) >= limit:
                partial = True
                break
        if rule_index >= len(rules_snapshot) and not partial:
            completed = True
        if completed:
            result = {
                "scanned_count": scanned,
                "matched_hits": matched_total,
                "new_candidates": added_total,
                "candidate_total": len(self.repository.incident_candidates(int(incident["id"]))),
            }
            self.connection.execute(
                "UPDATE impact_evaluations SET status='completed',cursor_rule=?,cursor_key=?,scanned_count=?,"
                "matched_count=?,added_count=?,result_json=?,locked_by=NULL,locked_at=NULL,updated_at=? WHERE id=?",
                (
                    rule_index, cursor_key, scanned, matched_total, added_total,
                    json.dumps(result, ensure_ascii=False, sort_keys=True), timestamp, evaluation_id,
                ),
            )
        else:
            # 部分完成：退回 pending，游标已持久化，等待下一轮或服务重启后续跑
            self.connection.execute(
                "UPDATE impact_evaluations SET status='pending',cursor_rule=?,cursor_key=?,scanned_count=?,"
                "matched_count=?,added_count=?,locked_by=NULL,locked_at=NULL,updated_at=? WHERE id=?",
                (
                    rule_index, cursor_key, scanned, matched_total, added_total, timestamp, evaluation_id,
                ),
            )
        return self.repository.require_evaluation(evaluation_id)

    def _effective_window(self, incident: dict[str, Any]) -> tuple[str, str]:
        slack_minutes = int(incident.get("window_slack_minutes") or 0)
        if slack_minutes <= 0:
            return incident["window_start"], incident["window_end"]
        start = datetime.fromisoformat(incident["window_start"]) - timedelta(minutes=slack_minutes)
        end = datetime.fromisoformat(incident["window_end"]) + timedelta(minutes=slack_minutes)
        return to_storage(start), to_storage(end)

    def _build_hit_path(
        self, rule: dict[str, Any], incident: dict[str, Any],
        window_start: str, window_end: str, usage: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "rule_id": rule["rule_id"],
            "rule_version": None,  # 由候选写入时填充
            "resource_type": rule["resource_type"],
            "resource_ref": rule["resource_ref"],
            "examination_resource_id": usage["id"],
            "examination_id": usage["examination_id"],
            "used_from": usage["used_from"],
            "used_to": usage["used_to"],
            "incident_window_start": incident["window_start"],
            "incident_window_end": incident["window_end"],
            "matched_window_start": window_start,
            "matched_window_end": window_end,
            "resource_source": usage["source"],
        }

    def _upsert_candidate(
        self, incident_id: int, examination_id: int, rule_version: int,
        hit_path: dict[str, Any], timestamp: str,
    ) -> bool:
        """返回 True 表示新建候选；已存在则合并命中路径，保留人工决定。"""
        existing = self.repository.candidate_by_examination(incident_id, examination_id)
        path = dict(hit_path)
        path["rule_version"] = rule_version
        if existing is None:
            self.connection.execute(
                "INSERT INTO impact_candidates(incident_id,examination_id,status,first_rule_version,last_rule_version,"
                "hit_paths_json,version,created_at,updated_at) VALUES(?,?,'candidate',?,?,?,1,?,?)",
                (
                    incident_id, examination_id, rule_version, rule_version,
                    json.dumps([path], ensure_ascii=False, sort_keys=True), timestamp, timestamp,
                ),
            )
            return True
        paths = existing.get("hit_paths", [])
        paths = [item for item in paths if not (
            item.get("rule_id") == path["rule_id"] and item.get("examination_resource_id") == path["examination_resource_id"]
        )]
        paths.append(path)
        paths.sort(key=lambda item: (item["rule_id"], item["examination_resource_id"]))
        new_last = max(int(existing["last_rule_version"]), rule_version)
        # 新版本规则（迟到信息触发）再次命中已排除候选时重新开放；已确认与同版本重放都不改状态
        if existing["status"] == "excluded" and rule_version > int(existing["last_rule_version"]):
            self.connection.execute(
                "UPDATE impact_candidates SET status='candidate',last_rule_version=?,hit_paths_json=?,"
                "decided_by=NULL,decided_at=NULL,decision_reason=NULL,version=version+1,updated_at=? WHERE id=?",
                (new_last, json.dumps(paths, ensure_ascii=False, sort_keys=True), timestamp, existing["id"]),
            )
        else:
            self.connection.execute(
                "UPDATE impact_candidates SET last_rule_version=?,hit_paths_json=?,version=version+1,updated_at=? WHERE id=?",
                (new_last, json.dumps(paths, ensure_ascii=False, sort_keys=True), timestamp, existing["id"]),
            )
        return False

    # ------------------------------------------------------------------
    # 人工决定：排除误报 / 确认影响（原子处置）
    # ------------------------------------------------------------------
    def decide_candidate(self, candidate_id: int, data: dict[str, Any]) -> dict[str, Any]:
        candidate = self.repository.require_candidate(candidate_id)
        incident_id = int(candidate["incident_id"])
        incident = self.repository.require_incident(incident_id)
        if incident["status"] == "closed":
            raise ConflictError("事件已关闭，不能再改变候选决定")
        if data.get("expected_candidate_version") is not None and int(
            candidate["version"]
        ) != int(data["expected_candidate_version"]):
            raise ConflictError("检验候选版本冲突", context={"current_version": candidate["version"]})
        timestamp = to_storage(self.clock.now())
        if data["action"] == "exclude":
            if candidate["status"] != "candidate":
                raise ConflictError("只有待定候选可以排除为误报")
            updated = self.connection.execute(
                "UPDATE impact_candidates SET status='excluded',decided_by=?,decided_at=?,decision_reason=?,"
                "version=version+1,updated_at=? WHERE id=? AND status='candidate'",
                (data["actor"], timestamp, data["reason"], timestamp, candidate_id),
            )
            if updated.rowcount != 1:
                raise ConflictError("检验候选已被其他调查员处理")
            self._decision(incident_id, candidate_id, "candidate_excluded", data["actor"], data["reason"], {}, timestamp)
            return self.candidate_detail(candidate_id)
        if candidate["status"] != "candidate":
            raise ConflictError("只有待定候选可以确认影响")
        # 确认影响：候选转 confirmed，原子创建全部处置
        examination = self.repository.require_examination(int(candidate["examination_id"]))
        specimen = self.repository.require_specimen(int(examination["specimen_id"]))
        # 1) 冻结相关剩余检材（复用质量冻结，幂等）
        hold_id = self._ensure_specimen_hold(specimen, candidate_id, incident_id, data["actor"], timestamp)
        # 2) 标志检验结果待复核（幂等）
        flag_id = self._ensure_review_flag(candidate, examination, data["actor"], timestamp)
        # 3) 已签发意见只创建撤回审查，不改写原报告（幂等）
        review_ids = self._ensure_withdrawal_reviews(candidate, examination, data["actor"], timestamp)
        updated = self.connection.execute(
            "UPDATE impact_candidates SET status='confirmed',decided_by=?,decided_at=?,decision_reason=?,"
            "version=version+1,updated_at=? WHERE id=? AND status='candidate'",
            (data["actor"], timestamp, data["reason"], timestamp, candidate_id),
        )
        if updated.rowcount != 1:
            raise ConflictError("检验候选已被其他调查员处理")
        self.connection.execute(
            "UPDATE quality_incidents SET status='actioned',updated_at=? WHERE id=? AND status='open'",
            (timestamp, incident_id),
        )
        self._decision(incident_id, candidate_id, "candidate_confirmed", data["actor"], data["reason"], {
            "hold_id": hold_id, "review_flag_id": flag_id, "withdrawal_review_ids": review_ids,
        }, timestamp)
        return self.candidate_detail(candidate_id)

    def _ensure_specimen_hold(
        self, specimen: dict[str, Any], candidate_id: int, incident_id: int, actor: str, timestamp: str,
    ) -> int | None:
        if float(specimen["available_quantity"]) <= 0 or specimen["status"] in {"depleted", "disposed"}:
            return None
        hold = self.connection.execute(
            "SELECT h.id FROM specimen_holds h JOIN impact_dispositions d "
            "ON d.target_type='specimen_hold' AND d.target_id=h.id "
            "WHERE d.incident_id=? AND h.specimen_id=? AND h.released_at IS NULL",
            (incident_id, specimen["id"]),
        ).fetchone()
        if hold:
            return int(hold[0])
        existing = self.connection.execute(
            "SELECT id FROM specimen_holds WHERE specimen_id=? AND hold_type='质量' AND released_at IS NULL",
            (specimen["id"],),
        ).fetchone()
        if existing:
            hold_id = int(existing[0])
        else:
            cursor = self.connection.execute(
                "INSERT INTO specimen_holds(specimen_id,hold_type,reason,imposed_by,imposed_at) VALUES(?,?,?,?,?)",
                (specimen["id"], "质量", f"质量事件 #{incident_id} 确认影响，剩余检材冻结待查", actor, timestamp),
            )
            hold_id = int(cursor.lastrowid)
            self.connection.execute(
                "UPDATE specimens SET status='held',version=version+1,updated_at=? WHERE id=? "
                "AND status NOT IN ('depleted','disposed')",
                (timestamp, specimen["id"]),
            )
        self.connection.execute(
            "INSERT INTO impact_dispositions(incident_id,candidate_id,target_type,target_id,created_by,created_at) "
            "VALUES(?,?, 'specimen_hold', ?,?,?) "
            "ON CONFLICT(incident_id,target_type,target_id) DO UPDATE SET status='active'",
            (incident_id, candidate_id, hold_id, actor, timestamp),
        )
        return hold_id

    def _ensure_review_flag(
        self, candidate: dict[str, Any], examination: dict[str, Any], actor: str, timestamp: str,
    ) -> int:
        incident_id = int(candidate["incident_id"])
        examination_id = int(examination["id"])
        existing = self.connection.execute(
            "SELECT id FROM examination_review_flags WHERE incident_id=? AND examination_id=?",
            (incident_id, examination_id),
        ).fetchone()
        if existing:
            self.connection.execute(
                "UPDATE examination_review_flags SET status='pending',candidate_id=?,cleared_by=NULL,cleared_at=NULL,"
                "clearance_note=NULL WHERE id=?",
                (candidate["id"], existing[0]),
            )
            flag_id = int(existing[0])
        else:
            cursor = self.connection.execute(
                "INSERT INTO examination_review_flags(incident_id,examination_id,candidate_id,status,created_by,created_at) "
                "VALUES(?,?,?, 'pending',?,?)",
                (incident_id, examination_id, candidate["id"], actor, timestamp),
            )
            flag_id = int(cursor.lastrowid)
        self.connection.execute(
            "INSERT INTO impact_dispositions(incident_id,candidate_id,target_type,target_id,created_by,created_at) "
            "VALUES(?,?, 'examination_review_flag', ?,?,?) "
            "ON CONFLICT(incident_id,target_type,target_id) DO UPDATE SET status='active'",
            (incident_id, candidate["id"], flag_id, actor, timestamp),
        )
        return flag_id

    def _ensure_withdrawal_reviews(
        self, candidate: dict[str, Any], examination: dict[str, Any], actor: str, timestamp: str,
    ) -> list[int]:
        incident_id = int(candidate["incident_id"])
        reports = self.repository.reports_for_examination(int(examination["id"]))
        review_ids: list[int] = []
        for report in reports:
            existing = self.connection.execute(
                "SELECT id FROM report_withdrawal_reviews WHERE incident_id=? AND report_id=?",
                (incident_id, report["id"]),
            ).fetchone()
            if existing:
                review_ids.append(int(existing[0]))
                continue
            cursor = self.connection.execute(
                "INSERT INTO report_withdrawal_reviews(incident_id,report_id,candidate_id,status,opened_by,opened_at) "
                "VALUES(?,?,?, 'pending',?,?)",
                (incident_id, report["id"], candidate["id"], actor, timestamp),
            )
            review_id = int(cursor.lastrowid)
            review_ids.append(review_id)
            self.connection.execute(
                "INSERT INTO impact_dispositions(incident_id,candidate_id,target_type,target_id,created_by,created_at) "
                "VALUES(?,?, 'report_withdrawal_review', ?,?,?)",
                (incident_id, candidate["id"], review_id, actor, timestamp),
            )
        return review_ids

    def decide_withdrawal_review(self, review_id: int, data: dict[str, Any]) -> dict[str, Any]:
        review = record(self.connection.execute(
            "SELECT * FROM report_withdrawal_reviews WHERE id=?", (review_id,)
        ).fetchone())
        if not review:
            raise ValidationError("撤回审查不存在")
        if review["status"] != "pending":
            raise ConflictError("该撤回审查已经作出结论")
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE report_withdrawal_reviews SET status=?,decided_by=?,decided_at=?,decision_reason=? WHERE id=?",
            (data["decision"], data["actor"], timestamp, data["reason"], review_id),
        )
        self._decision(int(review["incident_id"]), int(review["candidate_id"]),
                       "withdrawal_review_decided", data["actor"], data["reason"],
                       {"review_id": review_id, "report_id": review["report_id"], "decision": data["decision"]},
                       timestamp)
        return record(self.connection.execute(
            "SELECT * FROM report_withdrawal_reviews WHERE id=?", (review_id,)
        ).fetchone()) or {}

    def clear_review_flag(self, flag_id: int, data: dict[str, Any]) -> dict[str, Any]:
        flag = record(self.connection.execute(
            "SELECT * FROM examination_review_flags WHERE id=?", (flag_id,)
        ).fetchone())
        if not flag:
            raise ValidationError("待复核标志不存在")
        if flag["status"] != "pending":
            raise ConflictError("该待复核标志已经清除")
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE examination_review_flags SET status='cleared',cleared_by=?,cleared_at=?,clearance_note=? WHERE id=?",
            (data["actor"], timestamp, data["note"], flag_id),
        )
        self._decision(int(flag["incident_id"]), int(flag["candidate_id"]),
                       "review_flag_cleared", data["actor"], data["note"], {"flag_id": flag_id}, timestamp)
        return record(self.connection.execute(
            "SELECT * FROM examination_review_flags WHERE id=?", (flag_id,)
        ).fetchone()) or {}

    def close_incident(self, incident_id: int, data: dict[str, Any]) -> dict[str, Any]:
        incident = self.repository.require_incident(incident_id)
        if int(incident["version"]) != int(data["expected_version"]):
            raise ConflictError("质量事件版本冲突", context={"current_version": incident["version"]})
        pending_candidates = self.connection.execute(
            "SELECT COUNT(*) FROM impact_candidates WHERE incident_id=? AND status='candidate'", (incident_id,)
        ).fetchone()[0]
        if pending_candidates:
            raise ConflictError("仍有未决定的检验候选，不能关闭事件", context={"pending_candidates": int(pending_candidates)})
        pending_evaluations = self.connection.execute(
            "SELECT COUNT(*) FROM impact_evaluations WHERE incident_id=? AND status!='completed'", (incident_id,)
        ).fetchone()[0]
        if pending_evaluations:
            raise ConflictError("影响评估尚未完成，不能关闭事件")
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "UPDATE quality_incidents SET status='closed',closed_by=?,closed_at=?,version=version+1,updated_at=? "
            "WHERE id=? AND version=?",
            (data["actor"], timestamp, timestamp, incident_id, data["expected_version"]),
        )
        if cursor.rowcount != 1:
            raise ConflictError("质量事件版本冲突")
        self._decision(incident_id, None, "incident_closed", data["actor"], data["reason"], {}, timestamp)
        return self.incident_detail(incident_id)

    # ------------------------------------------------------------------
    # 追踪视图：事件 -> 规则 -> 资源 -> 检验 -> 检材 -> 报告 -> 人工决定
    # ------------------------------------------------------------------
    def candidate_detail(self, candidate_id: int) -> dict[str, Any]:
        candidate = self.repository.require_candidate(candidate_id)
        examination = self.repository.examination_detail(int(candidate["examination_id"]))
        specimen = self.repository.require_specimen(int(examination["specimen_id"]))
        forensic_case = self.repository.require_forensic_case(int(specimen["case_id"]))
        reports = self.repository.reports_for_examination(int(examination["id"]))
        dispositions = self._hydrate_dispositions(self.repository.candidate_dispositions(candidate_id))
        flags = records(self.connection.execute(
            "SELECT * FROM examination_review_flags WHERE incident_id=? AND examination_id=?",
            (candidate["incident_id"], candidate["examination_id"]),
        ).fetchall())
        reviews = records(self.connection.execute(
            "SELECT w.*,r.report_no FROM report_withdrawal_reviews w JOIN examination_reports r ON r.id=w.report_id "
            "WHERE w.incident_id=? AND w.candidate_id=? ORDER BY w.id",
            (candidate["incident_id"], candidate_id),
        ).fetchall())
        candidate["examination"] = {
            "id": examination["id"],
            "examination_no": examination["examination_no"],
            "status": examination["status"],
            "conformity_percent": examination["conformity_percent"],
            "completed_at": examination["completed_at"],
            "protocol_id": examination["protocol_id"],
        }
        candidate["specimen"] = {"id": specimen["id"], "specimen_no": specimen["specimen_no"], "status": specimen["status"]}
        candidate["forensic_case"] = {"id": forensic_case["id"], "case_no": forensic_case["case_no"],
                                      "discipline": forensic_case["discipline"]}
        candidate["reports"] = [{"id": item["id"], "report_no": item["report_no"], "issued_at": item["issued_at"]}
                                for item in reports]
        candidate["review_flags"] = flags
        candidate["withdrawal_reviews"] = reviews
        candidate["dispositions"] = dispositions
        return candidate

    def _hydrate_dispositions(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for item in rows:
            hydrated = dict(item)
            if item["target_type"] == "specimen_hold":
                target = record(self.connection.execute(
                    "SELECT h.*,s.specimen_no FROM specimen_holds h JOIN specimens s ON s.id=h.specimen_id WHERE h.id=?",
                    (item["target_id"],),
                ).fetchone())
            elif item["target_type"] == "examination_review_flag":
                target = record(self.connection.execute(
                    "SELECT * FROM examination_review_flags WHERE id=?", (item["target_id"],)
                ).fetchone())
            else:
                target = record(self.connection.execute(
                    "SELECT w.*,r.report_no FROM report_withdrawal_reviews w "
                    "JOIN examination_reports r ON r.id=w.report_id WHERE w.id=?",
                    (item["target_id"],),
                ).fetchone())
            hydrated["target"] = target
            result.append(hydrated)
        return result

    def incident_detail(self, incident_id: int) -> dict[str, Any]:
        incident = self.repository.require_incident(incident_id)
        incident["evidence"] = self.repository.incident_evidence(incident_id)
        incident["resources"] = self.repository.incident_resources(incident_id)
        incident["rule_versions"] = self.repository.incident_rule_versions(incident_id)
        incident["evaluations"] = self.repository.incident_evaluations(incident_id)
        candidates = self.repository.incident_candidates(incident_id)
        incident["candidates"] = [self._candidate_summary(item) for item in candidates]
        incident["decisions"] = [self._decision_payload(item) for item in
                                 self.repository.incident_decisions(incident_id)]
        counts = {"candidate": 0, "excluded": 0, "confirmed": 0}
        for item in candidates:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        incident["candidate_counts"] = counts
        pending_flags = self.connection.execute(
            "SELECT COUNT(*) FROM examination_review_flags WHERE incident_id=? AND status='pending'", (incident_id,)
        ).fetchone()[0]
        pending_reviews = self.connection.execute(
            "SELECT COUNT(*) FROM report_withdrawal_reviews WHERE incident_id=? AND status='pending'", (incident_id,)
        ).fetchone()[0]
        active_holds = self.connection.execute(
            "SELECT COUNT(*) FROM impact_dispositions d JOIN specimen_holds h ON h.id=d.target_id "
            "WHERE d.incident_id=? AND d.target_type='specimen_hold' AND d.status='active' AND h.released_at IS NULL",
            (incident_id,),
        ).fetchone()[0]
        incident["open_dispositions"] = {
            "specimen_holds": int(active_holds),
            "review_flags": int(pending_flags),
            "withdrawal_reviews": int(pending_reviews),
        }
        return incident

    def _candidate_summary(self, candidate: dict[str, Any]) -> dict[str, Any]:
        examination = self.repository.require_examination(int(candidate["examination_id"]))
        specimen = self.repository.require_specimen(int(examination["specimen_id"]))
        forensic_case = self.repository.require_forensic_case(int(specimen["case_id"]))
        reports = self.repository.reports_for_examination(int(examination["id"]))
        return {
            "id": candidate["id"],
            "examination_id": candidate["examination_id"],
            "examination_no": examination["examination_no"],
            "status": candidate["status"],
            "first_rule_version": candidate["first_rule_version"],
            "last_rule_version": candidate["last_rule_version"],
            "hit_paths": candidate.get("hit_paths", []),
            "decided_by": candidate["decided_by"],
            "decided_at": candidate["decided_at"],
            "decision_reason": candidate["decision_reason"],
            "specimen_no": specimen["specimen_no"],
            "specimen_id": specimen["id"],
            "case_no": forensic_case["case_no"],
            "report_count": len(reports),
        }

    def _decision_payload(self, row: dict[str, Any]) -> dict[str, Any]:
        payload = dict(row)
        if "payload" not in payload:
            raw = payload.pop("payload_json", "{}")
            try:
                payload["payload"] = json.loads(raw or "{}")
            except json.JSONDecodeError:
                payload["payload"] = {}
        return payload

    def _decision(
        self, incident_id: int, candidate_id: int | None, decision_type: str,
        actor: str, reason: str, payload: dict[str, Any], timestamp: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO incident_decisions(incident_id,candidate_id,decision_type,actor,reason,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                incident_id, candidate_id, decision_type, actor, reason,
                json.dumps(payload, ensure_ascii=False, sort_keys=True), timestamp,
            ),
        )

    def _normalize_resources(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for raw in items:
            key = (raw["resource_type"], raw["resource_ref"].strip())
            if key in seen:
                raise ValidationError("同一事件不能重复登记相同资源标识")
            seen.add(key)
            normalized.append({
                "resource_type": raw["resource_type"],
                "resource_ref": raw["resource_ref"].strip(),
                "note": raw.get("note", ""),
            })
        return normalized
