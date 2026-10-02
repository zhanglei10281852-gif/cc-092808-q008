from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.forensics.repository import ForensicRepository, record, records

RESOURCE_TYPES = ("reagent_batch", "equipment", "workbench")
RESOURCE_LABELS = {"reagent_batch": "试剂批次", "equipment": "设备", "workbench": "工作台"}
RULE_RESOURCE_MAP = {
    "reagent_batch": "reagent_batch",
    "equipment": "equipment",
    "workbench_slot": "workbench",
}


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _loads(raw: str | None, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default


class ImpactRuleService:
    """影响评估规则采用同号递增版本，发布新版本自动停用旧版本，保证规则可版本化。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()

    def create_rule(self, data: dict[str, Any]) -> dict[str, Any]:
        rule_type = data["rule_type"]
        if rule_type not in RULE_RESOURCE_MAP and rule_type != "time_proximity":
            raise ValidationError("不支持的影响评估规则类型")
        params = data.get("params") or {}
        if rule_type == "time_proximity":
            minutes = params.get("window_minutes", 60)
            if not isinstance(minutes, int) or not 0 <= minutes <= 24 * 60:
                raise ValidationError("时间窗邻近规则的 window_minutes 必须是 0 到 1440 之间的整数")
            params = {"window_minutes": minutes}
        timestamp = to_storage(self.clock.now())
        latest = self.connection.execute(
            "SELECT id,version FROM impact_rules WHERE rule_code=? ORDER BY version DESC LIMIT 1",
            (data["rule_code"],),
        ).fetchone()
        version = int(latest["version"]) + 1 if latest else 1
        if latest:
            self.connection.execute("UPDATE impact_rules SET active=0 WHERE id=?", (latest["id"],))
        cursor = self.connection.execute(
            "INSERT INTO impact_rules(rule_code,version,rule_name,rule_type,discipline,params_json,active,created_by,created_at) "
            "VALUES(?,?,?,?,?,? ,1,?,?)",
            (
                data["rule_code"], version, data["rule_name"], rule_type, data.get("discipline", "").strip(),
                json.dumps(params, ensure_ascii=False, sort_keys=True), data["created_by"], timestamp,
            ),
        )
        rule = self.require_rule(int(cursor.lastrowid))
        # 规则版本发布后，对专业匹配的开放事件确定性重算（输入指纹改变即扩展候选）
        open_events = self.connection.execute(
            "SELECT id FROM quality_events WHERE status!='closed' AND (discipline='' OR discipline=? OR ?='') "
            "ORDER BY id",
            (rule["discipline"], rule["discipline"]),
        ).fetchall()
        for row in open_events:
            ImpactService(self.connection, self.clock).run_evaluation(
                int(row["id"]), trigger="rule_published", actor=data["created_by"]
            )
        return rule

    def require_rule(self, rule_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM impact_rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise NotFoundError("影响评估规则不存在")
        item = dict(row)
        item["params"] = _loads(item.pop("params_json"), {})
        return item

    def list_rules(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        clause = " WHERE active=1" if active_only else ""
        rows = self.connection.execute(
            f"SELECT * FROM impact_rules{clause} ORDER BY rule_code,version", ()
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["params"] = _loads(item.pop("params_json"), {})
            items.append(item)
        return items

    def active_rules_for(self, discipline: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM impact_rules WHERE active=1 AND (discipline='' OR discipline=?) ORDER BY id",
            (discipline,),
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["params"] = _loads(item.pop("params_json"), {})
            items.append(item)
        return items


class ImpactService:
    """质量事件影响追踪与处置：登记、评估、候选、人工决定与原子处置。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)
        self.rules = ImpactRuleService(connection, self.clock)

    # ------------------------------------------------------------------ 事件登记

    def create_event(self, data: dict[str, Any]) -> dict[str, Any]:
        window_start = to_storage(data["window_start"])
        window_end = to_storage(data["window_end"])
        if window_end < window_start:
            raise ValidationError("污染时间窗的结束时间不能早于开始时间")
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO quality_events(event_no,title,event_type,contaminant,discipline,window_start,window_end,"
                "description,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'open',?,?,?)",
                (
                    data["event_no"], data["title"], data.get("event_type", "blank_contamination"),
                    data.get("contaminant", ""), data.get("discipline", ""), window_start, window_end,
                    data.get("description", ""), data["created_by"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("质量事件编号已经存在") from exc
        event_id = int(cursor.lastrowid)
        self.connection.execute(
            "INSERT INTO quality_event_versions(event_id,version,change_type,summary,patch_json,changed_by,created_at) "
            "VALUES(?,1,'created','登记质量事件与污染时间窗',?,?,?)",
            (event_id, json.dumps({"window_start": window_start, "window_end": window_end}, ensure_ascii=False), data["created_by"], timestamp),
        )
        for raw in data.get("resources", []):
            self._insert_resource(event_id, raw, 1, data["created_by"], timestamp)
        for raw in data.get("evidence", []):
            self._insert_evidence(event_id, raw, 1, data["created_by"], timestamp)
        detail = self.event_detail(event_id)
        # 登记后即按当前生效规则生成带命中路径的检验候选
        self.run_evaluation(event_id, trigger="registration", actor=data["created_by"])
        return self.event_detail(event_id)

    def _insert_resource(self, event_id: int, raw: dict[str, Any], event_version: int, actor: str, timestamp: str) -> None:
        resource_type = raw["resource_type"]
        if resource_type not in RESOURCE_TYPES:
            raise ValidationError("资源类型必须是 reagent_batch、equipment 或 workbench")
        resource_ref = str(raw["resource_ref"]).strip()
        if not resource_ref:
            raise ValidationError("资源标识不能为空")
        try:
            self.connection.execute(
                "INSERT INTO quality_event_resources(event_id,resource_type,resource_ref,observed_at,note,evidence_json,"
                "event_version,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    event_id, resource_type, resource_ref,
                    to_storage(raw["observed_at"]) if raw.get("observed_at") else None,
                    raw.get("note", ""), json.dumps(raw.get("evidence", {}), ensure_ascii=False, sort_keys=True),
                    event_version, actor, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("同一事件不能重复登记相同资源标识", context={
                "resource_type": resource_type, "resource_ref": resource_ref,
            }) from exc

    def _insert_evidence(self, event_id: int, raw: dict[str, Any], event_version: int, actor: str, timestamp: str) -> None:
        if not str(raw.get("reference", "")).strip():
            raise ValidationError("证据必须包含可追溯的引用编号或链接")
        self.connection.execute(
            "INSERT INTO quality_event_evidence(event_id,evidence_type,reference,summary,collected_at,recorded_by,"
            "metadata_json,event_version,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                event_id, raw.get("evidence_type", "other"), raw["reference"], raw.get("summary", ""),
                to_storage(raw["collected_at"]) if raw.get("collected_at") else None,
                raw.get("recorded_by", actor), json.dumps(raw.get("metadata", {}), ensure_ascii=False, sort_keys=True),
                event_version, timestamp,
            ),
        )

    def add_resources(self, event_id: int, data: dict[str, Any]) -> dict[str, Any]:
        event = self.require_event(event_id)
        self._check_version(event, data["expected_version"])
        if event["status"] == "closed":
            raise ConflictError("质量事件已关闭，不能再补充资源")
        resources = data.get("resources") or []
        if not resources:
            raise ValidationError("至少登记一项资源")
        timestamp = to_storage(self.clock.now())
        new_version = self._bump_event(
            event_id, "resources_added",
            "补充资源标识：" + "、".join(f"{RESOURCE_LABELS[r['resource_type']]} {r['resource_ref']}" for r in resources),
            {"resources": resources}, data["actor"], timestamp,
            expected_version=int(event["version"]),
        )
        for raw in resources:
            self._insert_resource(event_id, raw, new_version, data["actor"], timestamp)
        # 新资源可能扩展命中集合，基于同一版本生成一次评估
        self.run_evaluation(event_id, trigger="resource_update", actor=data["actor"])
        return self.event_detail(event_id)

    def add_evidence(self, event_id: int, data: dict[str, Any]) -> dict[str, Any]:
        event = self.require_event(event_id)
        self._check_version(event, data["expected_version"])
        timestamp = to_storage(self.clock.now())
        new_version = self._bump_event(
            event_id, "evidence_added", f"补充证据：{data['reference']}", {"reference": data["reference"]},
            data["actor"], timestamp, expected_version=int(event["version"]),
        )
        self._insert_evidence(event_id, data, new_version, data["actor"], timestamp)
        return self.event_detail(event_id)

    def close_event(self, event_id: int, data: dict[str, Any]) -> dict[str, Any]:
        event = self.require_event(event_id)
        self._check_version(event, data["expected_version"])
        pending = self.connection.execute(
            "SELECT COUNT(*) FROM impact_candidates WHERE event_id=? AND status='pending' AND active_match=1",
            (event_id,),
        ).fetchone()[0]
        if pending:
            raise ConflictError("仍有未决定的命中候选，不能关闭事件", context={"pending": int(pending)})
        timestamp = to_storage(self.clock.now())
        self._bump_event(
            event_id, "closed", data.get("summary", "质量事件关闭"), {}, data["actor"], timestamp,
            status="closed", expected_version=int(event["version"]),
        )
        return self.event_detail(event_id)

    def require_event(self, event_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM quality_events WHERE id=?", (event_id,)).fetchone()
        if row is None:
            raise NotFoundError("质量事件不存在")
        return dict(row)

    def _check_version(self, event: dict[str, Any], expected_version: int) -> None:
        if int(event["version"]) != int(expected_version):
            raise ConflictError("质量事件已被其他调查更新，请基于最新版本操作", context={
                "current_version": event["version"],
            })

    def _bump_event(
        self, event_id: int, change_type: str, summary: str, patch: dict[str, Any], actor: str, timestamp: str,
        *, status: str | None = None, expected_version: int | None = None,
    ) -> int:
        if expected_version is not None:
            # 条件更新兜底并发覆盖：版本已被其他调查推进时整笔事务回滚
            if status is None:
                cursor = self.connection.execute(
                    "UPDATE quality_events SET version=version+1,updated_at=? WHERE id=? AND version=? RETURNING version",
                    (timestamp, event_id, expected_version),
                )
            else:
                cursor = self.connection.execute(
                    "UPDATE quality_events SET status=?,version=version+1,updated_at=? WHERE id=? AND version=? RETURNING version",
                    (status, timestamp, event_id, expected_version),
                )
            row = cursor.fetchone()
            if row is None:
                current = self.require_event(event_id)
                raise ConflictError("质量事件已被其他调查更新，请基于最新版本操作", context={
                    "current_version": current["version"],
                })
            new_version = int(row[0])
        elif status is None:
            cursor = self.connection.execute(
                "UPDATE quality_events SET version=version+1,updated_at=? WHERE id=? RETURNING version",
                (timestamp, event_id),
            )
            new_version = int(cursor.fetchone()[0])
        else:
            cursor = self.connection.execute(
                "UPDATE quality_events SET status=?,version=version+1,updated_at=? WHERE id=? RETURNING version",
                (status, timestamp, event_id),
            )
            new_version = int(cursor.fetchone()[0])
        self.connection.execute(
            "INSERT INTO quality_event_versions(event_id,version,change_type,summary,patch_json,changed_by,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (event_id, new_version, change_type, summary, json.dumps(patch, ensure_ascii=False, sort_keys=True), actor, timestamp),
        )
        return new_version

    # ------------------------------------------------------- 检验资源使用（可迟到）

    def record_resource_use(self, examination_id: int, data: dict[str, Any]) -> dict[str, Any]:
        self.repository.require_examination(examination_id)
        resource_type = data["resource_type"]
        if resource_type not in RESOURCE_TYPES:
            raise ValidationError("资源类型必须是 reagent_batch、equipment 或 workbench")
        used_from = to_storage(data["used_from"]) if data.get("used_from") else None
        used_to = to_storage(data["used_to"]) if data.get("used_to") else None
        if used_from and used_to and used_to < used_from:
            raise ValidationError("资源使用结束时间不能早于开始时间")
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO examination_resource_uses(examination_id,resource_type,resource_ref,used_from,used_to,"
                "source_key,recorded_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    examination_id, resource_type, data["resource_ref"].strip(), used_from, used_to,
                    data["source_key"], data["recorded_by"], timestamp,
                ),
            )
        except sqlite3.IntegrityError:
            existing = self.connection.execute(
                "SELECT * FROM examination_resource_uses WHERE examination_id=? AND source_key=?",
                (examination_id, data["source_key"]),
            ).fetchone()
            if existing:
                return dict(existing) | {"replayed": True}
            raise ConflictError("检验资源记录冲突")
        use_row = dict(self.connection.execute(
            "SELECT * FROM examination_resource_uses WHERE id=?", (cursor.lastrowid,)
        ).fetchone())
        # 迟到记录确定性触发：所有包含同一资源标识的开放事件都重新评估
        linked = self.connection.execute(
            "SELECT DISTINCT e.id FROM quality_events e JOIN quality_event_resources r ON r.event_id=e.id "
            "WHERE r.resource_type=? AND r.resource_ref=? AND e.status!='closed'",
            (resource_type, data["resource_ref"].strip()),
        ).fetchall()
        for row in linked:
            self.run_evaluation(int(row[0]), trigger="late_resource", actor=data["recorded_by"])
        return use_row | {"replayed": False}

    def list_resource_uses(self, examination_id: int) -> list[dict[str, Any]]:
        return records(self.connection.execute(
            "SELECT * FROM examination_resource_uses WHERE examination_id=? ORDER BY id", (examination_id,)
        ).fetchall())

    # ------------------------------------------------------------- 影响评估

    def request_evaluation(self, event_id: int, actor: str) -> dict[str, Any]:
        event = self.require_event(event_id)
        if event["status"] == "closed":
            raise ConflictError("质量事件已关闭，不能再重新评估")
        return self.run_evaluation(event_id, trigger="manual", actor=actor)

    def _rule_fingerprint(self, event: dict[str, Any], rules: list[dict[str, Any]], resources: list[dict[str, Any]]) -> str:
        # 纳入检验资源使用与检验任务的数据快照：迟到的设备/试剂记录会确定性改变指纹，
        # 从而扩展候选；输入不变时重复评估则稳定复用，不产生第二份处置。
        resource_keys = sorted((r["resource_type"], r["resource_ref"]) for r in resources)
        use_snapshot: list[Any] = []
        for resource_type, resource_ref in resource_keys:
            row = self.connection.execute(
                "SELECT COUNT(*) AS c,COALESCE(MAX(id),0) AS m FROM examination_resource_uses "
                "WHERE resource_type=? AND resource_ref=?",
                (resource_type, resource_ref),
            ).fetchone()
            use_snapshot.append([resource_type, resource_ref, int(row["c"]), int(row["m"])])
        exam_row = self.connection.execute(
            "SELECT COUNT(*) AS c,COALESCE(MAX(id),0) AS m FROM examinations WHERE status!='cancelled'"
        ).fetchone()
        payload = {
            "window": [event["window_start"], event["window_end"]],
            "resources": resource_keys,
            "rules": sorted(
                (r["id"], r["rule_code"], r["version"], r["rule_type"], r["discipline"], _canonical(r["params"]))
                for r in rules
            ),
            "resource_uses": use_snapshot,
            "examinations": [int(exam_row["c"]), int(exam_row["m"])],
        }
        return _sha256(_canonical(payload))

    def run_evaluation(self, event_id: int, *, trigger: str = "manual", actor: str = "system") -> dict[str, Any]:
        event = self.require_event(event_id)
        timestamp = to_storage(self.clock.now())
        resources = records(self.connection.execute(
            "SELECT * FROM quality_event_resources WHERE event_id=? ORDER BY id", (event_id,)
        ).fetchall())
        rules = self.rules.active_rules_for(event.get("discipline", ""))
        fingerprint = self._rule_fingerprint(event, rules, resources)
        # 重复评估：输入指纹与上次完成评估一致时直接复用，不产生第二份候选/处置
        last = self.connection.execute(
            "SELECT * FROM impact_evaluations WHERE event_id=? ORDER BY id DESC LIMIT 1", (event_id,)
        ).fetchone()
        if last and dict(last)["status"] == "completed" and dict(last)["rule_fingerprint"] == fingerprint:
            return dict(last) | {"unchanged": True}

        cursor = self.connection.execute(
            "INSERT INTO impact_evaluations(event_id,trigger,event_version,rule_fingerprint,status,attempts,"
            "created_at,started_at) VALUES(?,?,?,?,'running',1,?,?)",
            (event_id, trigger, int(event["version"]), fingerprint, timestamp, timestamp),
        )
        evaluation_id = int(cursor.lastrowid)
        self.connection.executemany(
            "INSERT INTO impact_evaluation_rules(evaluation_id,rule_id,rule_code,rule_version,rule_type) "
            "VALUES(?,?,?,?,?)",
            [
                (evaluation_id, rule["id"], rule["rule_code"], rule["version"], rule["rule_type"])
                for rule in rules
            ],
        )
        matches = self._compute_matches(event, resources, rules)
        candidates_hash = _sha256(_canonical(sorted(
            [exam_id, sorted([self._path_identity(path) for path in paths])] for exam_id, paths in matches
        )))
        matched_ids = {exam_id for exam_id, paths in matches}
        for exam_id, paths in sorted(matches):
            self._upsert_candidate(event_id, exam_id, paths, int(event["version"]), timestamp, active=True)
        # 历史候选若已不在命中集合中，标记为非当前命中（保留审计轨迹，不自动改写人工决定）
        if matched_ids:
            placeholders = ",".join("?" for _ in matched_ids)
            self.connection.execute(
                f"UPDATE impact_candidates SET active_match=0,updated_at=? WHERE event_id=? AND active_match=1 "
                f"AND examination_id NOT IN ({placeholders})",
                (timestamp, event_id, *sorted(matched_ids)),
            )
        else:
            self.connection.execute(
                "UPDATE impact_candidates SET active_match=0,updated_at=? WHERE event_id=? AND active_match=1",
                (timestamp, event_id),
            )
        self.connection.execute(
            "UPDATE impact_evaluations SET status='completed',candidates_hash=?,candidate_count=?,completed_at=? WHERE id=?",
            (candidates_hash, len(matched_ids), timestamp, evaluation_id),
        )
        return dict(self.connection.execute(
            "SELECT * FROM impact_evaluations WHERE id=?", (evaluation_id,)
        ).fetchone()) | {"unchanged": False}

    def _path_identity(self, path: dict[str, Any]) -> list[Any]:
        return [
            path["rule_code"], path["rule_version"], path["rule_type"],
            path.get("resource_type") or "", path.get("resource_ref") or "",
        ]

    def _compute_matches(
        self, event: dict[str, Any], resources: list[dict[str, Any]], rules: list[dict[str, Any]],
    ) -> list[tuple[int, list[dict[str, Any]]]]:
        window_start = from_storage(event["window_start"])
        window_end = from_storage(event["window_end"])
        examinations = self.connection.execute(
            "SELECT * FROM examinations WHERE status!='cancelled' ORDER BY id"
        ).fetchall()
        resource_refs: dict[str, set[str]] = {kind: set() for kind in RESOURCE_TYPES}
        for item in resources:
            resource_refs[item["resource_type"]].add(item["resource_ref"])
        result: dict[int, list[dict[str, Any]]] = {}
        for row in examinations:
            exam = dict(row)
            exam_id = int(exam["id"])
            interval = self._exam_interval(exam)
            paths: list[dict[str, Any]] = []
            for rule in rules:
                rule_type = rule["rule_type"]
                if rule_type == "time_proximity":
                    margin = timedelta(minutes=int(rule["params"].get("window_minutes", 60)))
                    if self._overlaps(interval[0], interval[1], window_start - margin, window_end + margin):
                        paths.append(self._hit_path(rule, None, None, interval, event, "检验执行时间落入污染时间窗邻近范围"))
                    continue
                kind = RULE_RESOURCE_MAP[rule_type]
                refs = resource_refs.get(kind, set())
                if not refs:
                    continue
                uses = self.connection.execute(
                    "SELECT * FROM examination_resource_uses WHERE examination_id=? AND resource_type=? "
                    "AND resource_ref IN ({}) ORDER BY resource_ref,id".format(",".join("?" for _ in refs)),
                    (exam_id, kind, *sorted(refs)),
                ).fetchall()
                for use_row in uses:
                    use = dict(use_row)
                    use_interval = self._use_interval(use, interval)
                    if self._overlaps(use_interval[0], use_interval[1], window_start, window_end):
                        paths.append(self._hit_path(
                            rule, kind, use["resource_ref"], use_interval, event,
                            f"{RESOURCE_LABELS[kind]} {use['resource_ref']} 在污染时间窗内被该检验使用",
                        ))
            if paths:
                result[exam_id] = paths
        return sorted(result.items())

    def _hit_path(
        self, rule: dict[str, Any], resource_type: str | None, resource_ref: str | None,
        interval: tuple[datetime, datetime], event: dict[str, Any], detail: str,
    ) -> dict[str, Any]:
        return {
            "rule_id": rule["id"],
            "rule_code": rule["rule_code"],
            "rule_version": rule["version"],
            "rule_type": rule["rule_type"],
            "resource_type": resource_type,
            "resource_ref": resource_ref,
            "exam_interval": {"start": interval[0].isoformat(), "end": interval[1].isoformat()},
            "contamination_window": {"start": event["window_start"], "end": event["window_end"]},
            "detail": detail,
        }

    @staticmethod
    def _overlaps(start_a: datetime, end_a: datetime, start_b: datetime, end_b: datetime) -> bool:
        return start_a <= end_b and end_a >= start_b

    @staticmethod
    def _exam_interval(exam: dict[str, Any]) -> tuple[datetime, datetime]:
        scheduled = datetime.fromisoformat(f"{exam['scheduled_for']}T00:00:00+00:00")
        start = from_storage(exam.get("started_at")) or scheduled
        end = from_storage(exam.get("completed_at")) or from_storage(exam.get("started_at")) or scheduled.replace(hour=23, minute=59, second=59)
        return start, end

    @staticmethod
    def _use_interval(use: dict[str, Any], fallback: tuple[datetime, datetime]) -> tuple[datetime, datetime]:
        start = from_storage(use.get("used_from")) or fallback[0]
        end = from_storage(use.get("used_to")) or fallback[1]
        return start, end

    def _upsert_candidate(
        self, event_id: int, examination_id: int, paths: list[dict[str, Any]], event_version: int,
        timestamp: str, *, active: bool,
    ) -> None:
        existing = self.connection.execute(
            "SELECT * FROM impact_candidates WHERE event_id=? AND examination_id=?",
            (event_id, examination_id),
        ).fetchone()
        payload = json.dumps(paths, ensure_ascii=False, sort_keys=True)
        if existing is None:
            self.connection.execute(
                "INSERT INTO impact_candidates(event_id,examination_id,status,hit_paths_json,active_match,"
                "first_event_version,last_event_version,first_seen_at,updated_at) "
                "VALUES(?,?,'pending',?,? ,?,?,?,?)",
                (event_id, examination_id, payload, 1 if active else 0, event_version, event_version, timestamp, timestamp),
            )
            return
        self.connection.execute(
            "UPDATE impact_candidates SET hit_paths_json=?,active_match=?,last_event_version=?,updated_at=? WHERE id=?",
            (payload, 1 if active else 0, event_version, timestamp, existing["id"]),
        )

    def reconcile_on_startup(self, *, actor: str = "startup") -> dict[str, Any]:
        """服务重启后继续未完成的影响计算：回收中断的评估行并重跑。"""
        recovered = 0
        stale = self.connection.execute(
            "SELECT id,event_id FROM impact_evaluations WHERE status IN ('pending','running') ORDER BY id"
        ).fetchall()
        event_ids: list[int] = []
        for row in stale:
            self.connection.execute(
                "UPDATE impact_evaluations SET status='failed',error_message=? WHERE id=? AND status IN ('pending','running')",
                ("服务重启，中断的评估由恢复流程重算", row["id"]),
            )
            event_ids.append(int(row["event_id"]))
            recovered += 1
        # 也处理已提交但评估行从未建立的持久任务（正常不会发生，作为兜底）
        for event_id in dict.fromkeys(event_ids):
            self.run_evaluation(event_id, trigger="startup_reconcile", actor=actor)
        return {"recovered_evaluations": recovered, "events": sorted(set(event_ids))}

    # ------------------------------------------------------------- 候选与人工决定

    def list_candidates(self, event_id: int, *, status: str | None = None) -> list[dict[str, Any]]:
        self.require_event(event_id)
        if status:
            rows = self.connection.execute(
                "SELECT * FROM impact_candidates WHERE event_id=? AND status=? ORDER BY id", (event_id, status)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM impact_candidates WHERE event_id=? ORDER BY id", (event_id,)
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = self._candidate_view(dict(row))
            items.append(item)
        return items

    def _candidate_view(self, candidate: dict[str, Any]) -> dict[str, Any]:
        candidate["hit_paths"] = _loads(candidate.pop("hit_paths_json"), [])
        exam = self.repository.require_examination(int(candidate["examination_id"]))
        specimen = self.repository.require_specimen(int(exam["specimen_id"]))
        forensic_case = self.repository.require_forensic_case(int(specimen["case_id"]))
        candidate["examination"] = {
            "id": exam["id"], "examination_no": exam["examination_no"], "status": exam["status"],
            "completed_at": exam.get("completed_at"), "conformity_percent": exam.get("conformity_percent"),
        }
        candidate["specimen"] = {"id": specimen["id"], "specimen_no": specimen["specimen_no"], "status": specimen["status"]}
        candidate["forensic_case"] = {"id": forensic_case["id"], "case_no": forensic_case["case_no"], "discipline": forensic_case["discipline"]}
        candidate["decisions"] = records(self.connection.execute(
            "SELECT * FROM impact_decisions WHERE candidate_id=? ORDER BY id", (candidate["id"],)
        ).fetchall())
        disposition = self.connection.execute(
            "SELECT * FROM impact_dispositions WHERE event_id=? AND candidate_id=? AND status='active' ORDER BY id DESC LIMIT 1",
            (candidate["event_id"], candidate["id"]),
        ).fetchone()
        candidate["disposition"] = dict(disposition) if disposition else None
        return candidate

    def decide_candidate(self, event_id: int, candidate_id: int, data: dict[str, Any]) -> dict[str, Any]:
        event = self.require_event(event_id)
        self._check_version(event, data["expected_version"])
        candidate_row = self.connection.execute(
            "SELECT * FROM impact_candidates WHERE id=? AND event_id=?", (candidate_id, event_id)
        ).fetchone()
        if candidate_row is None:
            raise NotFoundError("影响候选不存在")
        candidate = dict(candidate_row)
        action = data["action"]
        timestamp = to_storage(self.clock.now())
        if action == "exclude":
            if candidate["status"] != "pending":
                raise ConflictError("只有待决定的候选可以排除误报", context={"status": candidate["status"]})
            if not data.get("reason"):
                raise ValidationError("排除候选时必须填写理由")
            self._set_candidate_status(candidate_id, "excluded", data["actor"], timestamp)
            new_version = self._bump_event(
                event_id, "candidate_excluded",
                f"候选检验 {candidate['examination_id']} 被排除：{data['reason']}",
                {"candidate_id": candidate_id, "examination_id": candidate["examination_id"], "reason": data["reason"]},
                data["actor"], timestamp, expected_version=int(event["version"]),
            )
            self._insert_decision(event_id, candidate_id, "exclude", data, new_version, timestamp)
        elif action == "confirm":
            if candidate["status"] != "pending":
                raise ConflictError("候选已经做出过决定，不能重复确认", context={"status": candidate["status"]})
            if not int(candidate["active_match"]):
                raise ConflictError("候选当前不在命中集合内，请先重新评估")
            self._set_candidate_status(candidate_id, "confirmed", data["actor"], timestamp)
            new_version = self._bump_event(
                event_id, "candidate_confirmed",
                f"候选检验 {candidate['examination_id']} 确认受影响并执行处置",
                {"candidate_id": candidate_id, "examination_id": candidate["examination_id"], "reason": data.get("reason", "")},
                data["actor"], timestamp, expected_version=int(event["version"]),
            )
            self._insert_decision(event_id, candidate_id, "confirm", data, new_version, timestamp)
            self._apply_disposition(event_id, candidate, data["actor"], new_version, timestamp)
        elif action == "reopen":
            if candidate["status"] not in {"excluded", "confirmed"}:
                raise ConflictError("只有已排除或已确认的候选可以重新调查")
            self._set_candidate_status(candidate_id, "pending", None, timestamp)
            new_version = self._bump_event(
                event_id, "candidate_reopened",
                f"候选检验 {candidate['examination_id']} 重新进入调查",
                {"candidate_id": candidate_id, "examination_id": candidate["examination_id"]},
                data["actor"], timestamp, expected_version=int(event["version"]),
            )
            self._insert_decision(event_id, candidate_id, "reopen", data, new_version, timestamp)
            if candidate["status"] == "confirmed":
                self._reverse_disposition(event_id, candidate, data["actor"], timestamp)
        else:
            raise ValidationError("候选决定必须是 exclude、confirm 或 reopen")
        view = self._candidate_view(dict(self.connection.execute(
            "SELECT * FROM impact_candidates WHERE id=?", (candidate_id,)
        ).fetchone()))
        view["event_version"] = int(self.require_event(event_id)["version"])
        return view

    def _set_candidate_status(self, candidate_id: int, status: str, actor: str | None, timestamp: str) -> None:
        if status == "pending":
            self.connection.execute(
                "UPDATE impact_candidates SET status='pending',decided_by=NULL,decided_at=NULL,updated_at=? WHERE id=?",
                (timestamp, candidate_id),
            )
        else:
            self.connection.execute(
                "UPDATE impact_candidates SET status=?,decided_by=?,decided_at=?,updated_at=? WHERE id=?",
                (status, actor, timestamp, timestamp, candidate_id),
            )

    def _insert_decision(
        self, event_id: int, candidate_id: int, action: str, data: dict[str, Any], event_version: int, timestamp: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO impact_decisions(event_id,candidate_id,action,reason,decided_by,event_version,detail_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                event_id, candidate_id, action, data.get("reason", ""), data["actor"], event_version,
                json.dumps(data.get("detail", {}), ensure_ascii=False, sort_keys=True), timestamp,
            ),
        )

    # ------------------------------------------------------------- 原子处置

    def _apply_disposition(
        self, event_id: int, candidate: dict[str, Any], actor: str, event_version: int, timestamp: str,
    ) -> dict[str, Any]:
        examination = self.repository.require_examination(int(candidate["examination_id"]))
        specimen_id = int(examination["specimen_id"])
        # 唯一约束兜底：同一事件对同一检验永远只有一份有效处置
        try:
            cursor = self.connection.execute(
                "INSERT INTO impact_dispositions(event_id,candidate_id,examination_id,specimen_id,created_by,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (event_id, candidate["id"], examination["id"], specimen_id, actor, timestamp),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("该检验已存在有效处置，重复评估不会生成第二份处置") from exc
        disposition_id = int(cursor.lastrowid)

        # 效应一：原子冻结剩余检材（质量冻结，复用 specimen_holds，立即阻断领用与放行）
        active_hold = self.connection.execute(
            "SELECT id FROM specimen_holds WHERE specimen_id=? AND hold_type='质量' AND released_at IS NULL ORDER BY id LIMIT 1",
            (specimen_id,),
        ).fetchone()
        if active_hold:
            hold_id = int(active_hold[0])
            hold_status = "skipped"
        else:
            hold_cursor = self.connection.execute(
                "INSERT INTO specimen_holds(specimen_id,hold_type,reason,imposed_by,imposed_at) VALUES(?,?,?,?,?)",
                (specimen_id, "质量", f"质量事件影响冻结：事件 #{event_id} 检验 {examination['examination_no']}", actor, timestamp),
            )
            hold_id = int(hold_cursor.lastrowid)
            self.connection.execute(
                "UPDATE specimens SET status='held',version=version+1,updated_at=? WHERE id=? "
                "AND status NOT IN ('depleted','disposed')",
                (timestamp, specimen_id),
            )
            hold_status = "applied"
        self.connection.execute(
            "INSERT INTO disposition_effects(disposition_id,effect_type,target_id,status,detail_json,created_at) "
            "VALUES(?, 'specimen_hold', ?, ?, ?, ?)",
            (disposition_id, hold_id, hold_status,
             json.dumps({"specimen_id": specimen_id, "event_version": event_version}, ensure_ascii=False), timestamp),
        )

        # 效应二：检验结果标记待复核（重新确认时重新置位），并阻断继续签发
        flag_cursor = self.connection.execute(
            "INSERT INTO examination_review_flags(examination_id,event_id,disposition_id,status,reason,flagged_by,flagged_at) "
            "VALUES(?, ?, ?, 'pending', ?, ?, ?) "
            "ON CONFLICT(event_id,examination_id) DO UPDATE SET status='pending',disposition_id=excluded.disposition_id,"
            "reason=excluded.reason,flagged_by=excluded.flagged_by,flagged_at=excluded.flagged_at,"
            "cleared_by=NULL,cleared_at=NULL,clear_note=NULL",
            (examination["id"], event_id, disposition_id,
             f"质量事件 #{event_id} 确认污染影响，结果待复核", actor, timestamp),
        )
        self.connection.execute(
            "INSERT INTO disposition_effects(disposition_id,effect_type,target_id,status,detail_json,created_at) "
            "VALUES(?, 'review_flag', ?, ?, ?, ?)",
            (
                disposition_id, examination["id"],
                "applied" if flag_cursor.rowcount else "skipped",
                json.dumps({"examination_id": examination["id"]}, ensure_ascii=False), timestamp,
            ),
        )

        # 效应三：为已签发意见创建撤回审查，原报告记录不改写
        reports = self.connection.execute(
            "SELECT * FROM examination_reports WHERE examination_id=? ORDER BY id", (examination["id"],)
        ).fetchall()
        for report_row in reports:
            review_cursor = self.connection.execute(
                "INSERT INTO report_withdrawal_reviews(report_id,event_id,disposition_id,status,reason,requested_by,"
                "requested_at,created_at) VALUES(?, ?, ?, 'requested', ?, ?, ?, ?) "
                "ON CONFLICT(event_id,report_id) DO NOTHING",
                (
                    report_row["id"], event_id, disposition_id,
                    f"质量事件 #{event_id}：支撑报告的检验结果受污染影响，提请撤回审查", actor, timestamp, timestamp,
                ),
            )
            if review_cursor.rowcount:
                self.connection.execute(
                    "INSERT INTO disposition_effects(disposition_id,effect_type,target_id,status,detail_json,created_at) "
                    "VALUES(?, 'withdrawal_review', ?, 'applied', ?, ?)",
                    (
                        disposition_id, report_row["id"],
                        json.dumps({"report_id": report_row["id"], "report_no": report_row["report_no"]}, ensure_ascii=False),
                        timestamp,
                    ),
                )
        return {"disposition_id": disposition_id}

    def _reverse_disposition(self, event_id: int, candidate: dict[str, Any], actor: str, timestamp: str) -> None:
        disposition = self.connection.execute(
            "SELECT * FROM impact_dispositions WHERE candidate_id=? AND status='active' ORDER BY id DESC LIMIT 1",
            (candidate["id"],),
        ).fetchone()
        if disposition is None:
            return
        disposition = dict(disposition)
        self.connection.execute(
            "UPDATE impact_dispositions SET status='reversed',reversed_by=?,reversed_at=?,reverse_reason=? WHERE id=?",
            (actor, timestamp, "候选重新调查，撤销处置", disposition["id"]),
        )
        # 仅当没有其他生效处置引用同一检材时才解除冻结
        other_hold = self.connection.execute(
            "SELECT 1 FROM impact_dispositions WHERE id!=? AND status='active' AND specimen_id=? LIMIT 1",
            (disposition["id"], disposition["specimen_id"]),
        ).fetchone()
        hold_effect = self.connection.execute(
            "SELECT * FROM disposition_effects WHERE disposition_id=? AND effect_type='specimen_hold' AND status='applied'",
            (disposition["id"],),
        ).fetchone()
        if hold_effect and not other_hold:
            self.connection.execute(
                "UPDATE specimen_holds SET released_by=?,released_at=?,release_reason=? WHERE id=? AND released_at IS NULL",
                (actor, timestamp, "质量事件候选重新调查，撤销处置", hold_effect["target_id"]),
            )
            still_held = self.connection.execute(
                "SELECT 1 FROM specimen_holds WHERE specimen_id=? AND released_at IS NULL LIMIT 1",
                (disposition["specimen_id"],),
            ).fetchone()
            if not still_held:
                self.connection.execute(
                    "UPDATE specimens SET status=CASE WHEN available_quantity<=0 THEN 'depleted' ELSE 'stored' END,"
                    "version=version+1,updated_at=? WHERE id=? AND status='held'",
                    (timestamp, disposition["specimen_id"]),
                )
        # 待复核标志在没有其他生效处置时清除；撤回审查一经发起不自动撤回
        other_flag = self.connection.execute(
            "SELECT 1 FROM impact_dispositions d JOIN disposition_effects f ON f.disposition_id=d.id "
            "WHERE d.status='active' AND d.examination_id=? AND f.effect_type='review_flag' LIMIT 1",
            (disposition["examination_id"],),
        ).fetchone()
        if not other_flag:
            self.connection.execute(
                "UPDATE examination_review_flags SET status='cleared',cleared_by=?,cleared_at=?,clear_note=? "
                "WHERE disposition_id=? AND status='pending'",
                (actor, timestamp, "候选重新调查，撤销处置", disposition["id"]),
            )

    # ------------------------------------------------------------- 报告与撤回审查

    def register_report(self, examination_id: int, data: dict[str, Any]) -> dict[str, Any]:
        examination = self.repository.require_examination(examination_id)
        if examination["status"] != "completed":
            raise ConflictError("只有已完成的检验可以登记签发意见")
        if self.has_pending_review_flag(examination_id):
            raise ConflictError("检验结果处于待复核状态，不能继续签发意见")
        timestamp = to_storage(self.clock.now())
        issued_at = to_storage(data["issued_at"]) if data.get("issued_at") else timestamp
        try:
            cursor = self.connection.execute(
                "INSERT INTO examination_reports(report_no,examination_id,document_ref,conclusion_digest,issued_by,issued_at,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    data["report_no"], examination_id, data.get("document_ref", ""),
                    data.get("conclusion_digest", ""), data["issued_by"], issued_at, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("报告编号已经存在") from exc
        return dict(self.connection.execute(
            "SELECT * FROM examination_reports WHERE id=?", (cursor.lastrowid,)
        ).fetchone())

    def has_pending_review_flag(self, examination_id: int) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM examination_review_flags WHERE examination_id=? AND status='pending' LIMIT 1",
            (examination_id,),
        ).fetchone()
        return row is not None

    def clear_review_flag(self, flag_id: int, data: dict[str, Any]) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM examination_review_flags WHERE id=?", (flag_id,)).fetchone()
        if row is None:
            raise NotFoundError("待复核标志不存在")
        flag = dict(row)
        if flag["status"] != "pending":
            raise ConflictError("待复核标志已经清除")
        if not data.get("note"):
            raise ValidationError("清除待复核标志必须填写复核结论")
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE examination_review_flags SET status='cleared',cleared_by=?,cleared_at=?,clear_note=? WHERE id=?",
            (data["actor"], timestamp, data["note"], flag_id),
        )
        self._bump_event(
            int(flag["event_id"]), "review_flag_cleared",
            f"检验 {flag['examination_id']} 完成复核：{data['note']}",
            {"flag_id": flag_id, "examination_id": flag["examination_id"]},
            data["actor"], timestamp,
        )
        return dict(self.connection.execute(
            "SELECT * FROM examination_review_flags WHERE id=?", (flag_id,)
        ).fetchone())

    def list_withdrawal_reviews(self, *, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.connection.execute(
                "SELECT * FROM report_withdrawal_reviews WHERE status=? ORDER BY id", (status,)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM report_withdrawal_reviews ORDER BY id"
            ).fetchall()
        items = []
        for row in rows:
            items.append(self._withdrawal_view(dict(row)))
        return items

    def decide_withdrawal_review(self, review_id: int, data: dict[str, Any]) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM report_withdrawal_reviews WHERE id=?", (review_id,)).fetchone()
        if row is None:
            raise NotFoundError("撤回审查不存在")
        review = dict(row)
        if review["status"] != "requested":
            raise ConflictError("撤回审查已经做出决定")
        if not data.get("note"):
            raise ValidationError("撤回审查决定必须填写意见")
        timestamp = to_storage(self.clock.now())
        new_status = "withdrawn" if data["approve"] else "rejected"
        self.connection.execute(
            "UPDATE report_withdrawal_reviews SET status=?,decided_by=?,decided_at=?,decision_note=? WHERE id=?",
            (new_status, data["actor"], timestamp, data["note"], review_id),
        )
        # 原报告行不改写，只在审查记录上落结论
        return self._withdrawal_view(dict(self.connection.execute(
            "SELECT * FROM report_withdrawal_reviews WHERE id=?", (review_id,)
        ).fetchone()))

    def _withdrawal_view(self, review: dict[str, Any]) -> dict[str, Any]:
        report = self.connection.execute(
            "SELECT * FROM examination_reports WHERE id=?", (review["report_id"],)
        ).fetchone()
        review["report"] = dict(report) if report else None
        return review

    # ------------------------------------------------------------- 汇总追溯

    def list_events(self, *, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.connection.execute(
                "SELECT * FROM quality_events WHERE status=? ORDER BY id DESC", (status,)
            ).fetchall()
        else:
            rows = self.connection.execute("SELECT * FROM quality_events ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]

    def event_detail(self, event_id: int) -> dict[str, Any]:
        event = self.require_event(event_id)
        event["resources"] = records(self.connection.execute(
            "SELECT * FROM quality_event_resources WHERE event_id=? ORDER BY id", (event_id,)
        ).fetchall())
        for item in event["resources"]:
            item["evidence"] = _loads(item.pop("evidence_json"), {})
        event["evidence_items"] = records(self.connection.execute(
            "SELECT * FROM quality_event_evidence WHERE event_id=? ORDER BY id", (event_id,)
        ).fetchall())
        for item in event["evidence_items"]:
            item["metadata"] = _loads(item.pop("metadata_json"), {})
        event["versions"] = records(self.connection.execute(
            "SELECT * FROM quality_event_versions WHERE event_id=? ORDER BY id", (event_id,)
        ).fetchall())
        for item in event["versions"]:
            item["patch"] = _loads(item.pop("patch_json"), {})
        evaluations = records(self.connection.execute(
            "SELECT * FROM impact_evaluations WHERE event_id=? ORDER BY id", (event_id,)
        ).fetchall())
        rule_rows = self.connection.execute(
            "SELECT DISTINCT er.rule_id,er.rule_code,er.rule_version,er.rule_type,r.active,r.params_json "
            "FROM impact_evaluation_rules er LEFT JOIN impact_rules r ON r.id=er.rule_id "
            "WHERE er.evaluation_id IN (SELECT id FROM impact_evaluations WHERE event_id=?) "
            "ORDER BY er.rule_code,er.rule_version",
            (event_id,),
        ).fetchall()
        event["rules_used"] = [
            {
                "rule_id": row["rule_id"], "rule_code": row["rule_code"], "rule_version": row["rule_version"],
                "rule_type": row["rule_type"], "currently_active": int(row["active"]) if row["active"] is not None else 0,
                "params": _loads(row["params_json"], {}),
            }
            for row in rule_rows
        ]
        event["evaluations"] = [
            {key: value for key, value in evaluation.items()} for evaluation in evaluations
        ]
        event["candidates"] = self.list_candidates(event_id)
        review_rows = self.connection.execute(
            "SELECT w.* FROM report_withdrawal_reviews w WHERE w.event_id=? ORDER BY w.id", (event_id,)
        ).fetchall()
        event["withdrawal_reviews"] = [self._withdrawal_view(dict(row)) for row in review_rows]
        flags = self.connection.execute(
            "SELECT * FROM examination_review_flags WHERE event_id=? ORDER BY id", (event_id,)
        ).fetchall()
        event["review_flags"] = [dict(row) for row in flags]
        return event
