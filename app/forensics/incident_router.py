from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.forensics.incident_schemas import (
    CandidateDecision,
    ExaminationResourceCreate,
    IncidentClose,
    IncidentCreate,
    IncidentRulesUpdate,
    ReportIssue,
    ResourceRegister,
    ReviewFlagClear,
    WithdrawalDecision,
)
from app.forensics.service import ForensicService

router = APIRouter(prefix="/api/forensics", tags=["质量事件影响追踪"])


def _service() -> ForensicService:
    return ForensicService(get_connection())


# ---- 数据面：检验资源使用台账与鉴定意见签发 ----

@router.post("/examinations/{examination_id}/resources", status_code=201)
def register_examination_resource(
    examination_id: int, data: ExaminationResourceCreate, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("examination.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).incidents.register_examination_resource(
            examination_id, data.model_dump(mode="python")
        )


@router.get("/examinations/{examination_id}/resources")
def list_examination_resources(examination_id: int, principal: Principal = Depends(current_principal)) -> list[dict]:
    principal.require("examination.read")
    return _service().repository.examination_resources(examination_id)


@router.post("/examinations/{examination_id}/reports", status_code=201)
def issue_examination_report(
    examination_id: int, data: ReportIssue, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("quality.review")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).incidents.issue_report(examination_id, data.model_dump(mode="python"))


# ---- 质量事件登记 ----

@router.post("/incidents", status_code=201)
def create_incident(data: IncidentCreate, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality.incident.manage")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).incidents.create_incident(data.model_dump(mode="python"))


@router.get("/incidents")
def list_incidents(
    status: str | None = Query(default=None, pattern="^(open|actioned|closed)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("quality.incident.read")
    items, total = _service().repository.list_incidents(status=status, limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality.incident.read")
    return _service().incidents.incident_detail(incident_id)


@router.put("/incidents/{incident_id}/rules")
def update_incident_rules(
    incident_id: int, data: IncidentRulesUpdate, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("quality.incident.manage")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).incidents.update_rules(
            incident_id, data.model_dump(mode="python", exclude_unset=True)
        )


@router.post("/incidents/{incident_id}/resources", status_code=201)
def add_incident_resource(
    incident_id: int, data: ResourceRegister, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("quality.incident.manage")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).incidents.add_incident_resource(
            incident_id, data.model_dump(mode="python")
        )


@router.post("/incidents/{incident_id}/close")
def close_incident(
    incident_id: int, data: IncidentClose, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("quality.incident.manage")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).incidents.close_incident(
            incident_id, data.model_dump(mode="json")
        )


# ---- 影响评估（服务重启后可继续未完成计算）----

@router.post("/incidents-evaluations/run")
def run_pending_evaluations(principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality.incident.manage")
    with transaction(immediate=True) as connection:
        results = ForensicService(connection).incidents.run_pending_evaluations(worker=f"api:{principal.username}")
    return {"processed": len(results), "evaluations": results}


@router.get("/incidents-evaluations/{evaluation_id}")
def evaluation_detail(evaluation_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality.incident.read")
    return _service().repository.require_evaluation(evaluation_id)


# ---- 候选与人工决定 ----

@router.get("/incidents/{incident_id}/candidates")
def list_incident_candidates(
    incident_id: int,
    status: str | None = Query(default=None, pattern="^(candidate|excluded|confirmed)$"),
    principal: Principal = Depends(current_principal),
) -> list[dict]:
    principal.require("quality.incident.read")
    service = _service()
    service.repository.require_incident(incident_id)
    return [service.incidents.candidate_detail(item["id"])
            for item in service.repository.incident_candidates(incident_id, status=status)]


@router.get("/impact-candidates/{candidate_id}")
def candidate_detail(candidate_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality.incident.read")
    return _service().incidents.candidate_detail(candidate_id)


@router.post("/impact-candidates/{candidate_id}/decision")
def decide_candidate(
    candidate_id: int, data: CandidateDecision, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("quality.incident.manage")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).incidents.decide_candidate(
            candidate_id, data.model_dump(mode="python")
        )


@router.post("/review-flags/{flag_id}/clear")
def clear_review_flag(
    flag_id: int, data: ReviewFlagClear, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("quality.incident.manage")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).incidents.clear_review_flag(
            flag_id, data.model_dump(mode="python")
        )


@router.post("/withdrawal-reviews/{review_id}/decision")
def decide_withdrawal_review(
    review_id: int, data: WithdrawalDecision, principal: Principal = Depends(current_principal)
) -> dict:
    principal.require("quality.incident.manage")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).incidents.decide_withdrawal_review(
            review_id, data.model_dump(mode="python")
        )
