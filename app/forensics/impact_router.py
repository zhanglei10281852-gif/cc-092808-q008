from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.forensics.schemas import (
    CandidateDecision,
    EventClose,
    EventEvidenceAdd,
    EventResourcesAdd,
    ImpactRuleCreate,
    QualityEventCreate,
    ReportRegister,
    ResourceUseCreate,
    ReviewFlagClear,
    WithdrawalDecision,
)
from app.forensics.service import ForensicService


router = APIRouter(prefix="/api/forensics", tags=["质量事件影响追踪"])


def _service() -> ForensicService:
    return ForensicService(get_connection())


# ----------------------------------------------------------------- 影响规则

@router.post("/impact-rules", status_code=201)
def create_impact_rule(data: ImpactRuleCreate, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality_rule.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact_rules.create_rule(data.model_dump(mode="json"))


@router.get("/impact-rules")
def list_impact_rules(
    active_only: bool = Query(default=False),
    principal: Principal = Depends(current_principal),
) -> list[dict]:
    principal.require("quality_event.read")
    return _service().impact_rules.list_rules(active_only=active_only)


# ----------------------------------------------------------------- 质量事件

@router.post("/quality-events", status_code=201)
def create_quality_event(data: QualityEventCreate, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality_event.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.create_event(data.model_dump(mode="python"))


@router.get("/quality-events")
def list_quality_events(
    status: str | None = Query(default=None, pattern="^(open|investigating|closed)$"),
    principal: Principal = Depends(current_principal),
) -> list[dict]:
    principal.require("quality_event.read")
    return _service().impact.list_events(status=status)


@router.get("/quality-events/{event_id}")
def quality_event_detail(event_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality_event.read")
    return _service().impact.event_detail(event_id)


@router.post("/quality-events/{event_id}/resources")
def add_event_resources(
    event_id: int,
    data: EventResourcesAdd,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("quality_event.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.add_resources(event_id, data.model_dump(mode="python"))


@router.post("/quality-events/{event_id}/evidence")
def add_event_evidence(
    event_id: int,
    data: EventEvidenceAdd,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("quality_event.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.add_evidence(event_id, data.model_dump(mode="python"))


@router.post("/quality-events/{event_id}/evaluate")
def evaluate_event(event_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality_event.investigate")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.request_evaluation(event_id, principal.username)


@router.post("/quality-events/{event_id}/close")
def close_quality_event(
    event_id: int,
    data: EventClose,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("quality_event.investigate")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.close_event(event_id, data.model_dump(mode="json"))


@router.get("/quality-events/{event_id}/candidates")
def list_candidates(
    event_id: int,
    status: str | None = Query(default=None, pattern="^(pending|excluded|confirmed)$"),
    principal: Principal = Depends(current_principal),
) -> list[dict]:
    principal.require("quality_event.read")
    return _service().impact.list_candidates(event_id, status=status)


@router.post("/quality-events/{event_id}/candidates/{candidate_id}/decision")
def decide_candidate(
    event_id: int,
    candidate_id: int,
    data: CandidateDecision,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("quality_event.investigate")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.decide_candidate(
            event_id, candidate_id, data.model_dump(mode="json")
        )


# ------------------------------------------------------- 检验资源使用（可迟到）

@router.post("/examinations/{examination_id}/resource-uses", status_code=201)
def record_resource_use(
    examination_id: int,
    data: ResourceUseCreate,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("examination.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.record_resource_use(
            examination_id, data.model_dump(mode="python")
        )


@router.get("/examinations/{examination_id}/resource-uses")
def list_resource_uses(examination_id: int, principal: Principal = Depends(current_principal)) -> list[dict]:
    principal.require("examination.read")
    return _service().impact.list_resource_uses(examination_id)


# ------------------------------------------------------------- 报告与撤回审查

@router.post("/examinations/{examination_id}/reports", status_code=201)
def register_report(
    examination_id: int,
    data: ReportRegister,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("examination.write")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.register_report(examination_id, data.model_dump(mode="python"))


@router.get("/withdrawal-reviews")
def list_withdrawal_reviews(
    status: str | None = Query(default=None, pattern="^(requested|withdrawn|rejected)$"),
    principal: Principal = Depends(current_principal),
) -> list[dict]:
    principal.require("quality_event.read")
    return _service().impact.list_withdrawal_reviews(status=status)


@router.post("/withdrawal-reviews/{review_id}/decision")
def decide_withdrawal_review(
    review_id: int,
    data: WithdrawalDecision,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("quality_event.investigate")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.decide_withdrawal_review(review_id, data.model_dump(mode="json"))


@router.post("/review-flags/{flag_id}/clear")
def clear_review_flag(
    flag_id: int,
    data: ReviewFlagClear,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("quality_event.investigate")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.clear_review_flag(flag_id, data.model_dump(mode="json"))


@router.post("/quality-events/reconcile")
def reconcile_impact(principal: Principal = Depends(current_principal)) -> dict:
    principal.require("quality_event.investigate")
    with transaction(immediate=True) as connection:
        return ForensicService(connection).impact.reconcile_on_startup(actor=principal.username)
