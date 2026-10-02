from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class AcquisitionType(str, Enum):
    collection = "委托"
    introduction = "移送"
    exchange = "委派"
    donation = "指定"
    breeding = "援助"


class ForensicCaseStatus(str, Enum):
    draft = "draft"
    quarantine = "quarantine"
    accepted = "accepted"
    restricted = "restricted"
    retired = "retired"


class SpecimenStatus(str, Enum):
    pending = "pending"
    stored = "stored"
    held = "held"
    depleted = "depleted"
    disposed = "disposed"


class ExaminationType(str, Enum):
    intake = "受理初检"
    periodic = "补充检验"
    review = "异常复核"


class AgencyCreate(BaseModel):
    agency_code: str = Field(min_length=2, max_length=40)
    agency_name: str = Field(min_length=1, max_length=200)
    jurisdiction_code: str = Field(min_length=2, max_length=2)
    contact_address: str = Field(default="", max_length=300)
    licensed_on: date | None = None
    accreditation_no: str | None = Field(default=None, max_length=100)
    restrictions: dict[str, Any] = Field(default_factory=dict)

    @field_validator("agency_code")
    @classmethod
    def normalize_agency_code(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not normalized.replace("-", "").replace("_", "").isalnum():
            raise ValueError("机构编码只能包含字母、数字、连字符和下划线")
        return normalized

    @field_validator("jurisdiction_code")
    @classmethod
    def normalize_country(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not normalized.isalpha():
            raise ValueError("辖区代码必须为两个字母")
        return normalized


class ForensicCaseCreate(BaseModel):
    case_no: str = Field(min_length=3, max_length=50)
    case_name: str = Field(min_length=2, max_length=200)
    discipline: str = Field(min_length=1, max_length=100)
    entrusted_matter: str = Field(default="", max_length=150)
    agency_id: int | None = Field(default=None, gt=0)
    case_source: AcquisitionType
    accepted_on: date
    passport: dict[str, Any] = Field(default_factory=dict)
    created_by: str = Field(min_length=1, max_length=100)

    @field_validator("case_no")
    @classmethod
    def normalize_case_no(cls, value: str) -> str:
        normalized = value.strip().upper()
        if " " in normalized:
            raise ValueError("案件编号不能包含空格")
        return normalized

    @field_validator("case_name", "discipline", "entrusted_matter", "created_by")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class ForensicCasePatch(BaseModel):
    case_name: str | None = Field(default=None, min_length=2, max_length=200)
    discipline: str | None = Field(default=None, min_length=1, max_length=100)
    entrusted_matter: str | None = Field(default=None, max_length=150)
    agency_id: int | None = Field(default=None, gt=0)
    passport: dict[str, Any] | None = None
    expected_version: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=100)


class ForensicCaseTransition(BaseModel):
    target_status: ForensicCaseStatus
    reason: str = Field(default="", max_length=500)
    expected_version: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=100)


class LocationCreate(BaseModel):
    location_code: str = Field(min_length=2, max_length=60)
    facility: str = Field(min_length=1, max_length=100)
    room: str = Field(min_length=1, max_length=100)
    rack: str = Field(min_length=1, max_length=60)
    shelf: str = Field(min_length=1, max_length=60)
    capacity_units: float = Field(gt=0, le=10_000_000)
    reference_value: float = Field(ge=-196, le=50)
    humidity_percent: float = Field(ge=0, le=100)

    @field_validator("location_code")
    @classmethod
    def normalize_location_code(cls, value: str) -> str:
        return value.strip().upper()


class SpecimenCreate(BaseModel):
    specimen_no: str = Field(min_length=3, max_length=60)
    case_id: int = Field(gt=0)
    parent_specimen_id: int | None = Field(default=None, gt=0)
    received_year: int = Field(ge=1800, le=2200)
    initial_quantity: float = Field(gt=0, le=10_000_000)
    integrity_percent: float | None = Field(default=None, ge=0, le=100)
    packaging: str = Field(default="", max_length=500)
    sealed_on: date | None = None
    created_by: str = Field(min_length=1, max_length=100)

    @field_validator("specimen_no")
    @classmethod
    def normalize_specimen_no(cls, value: str) -> str:
        return value.strip().upper()


class PlacementCreate(BaseModel):
    specimen_id: int = Field(gt=0)
    location_id: int = Field(gt=0)
    quantity: float = Field(gt=0)
    container_code: str = Field(min_length=2, max_length=80)
    idempotency_key: str = Field(min_length=8, max_length=100)
    actor: str = Field(min_length=1, max_length=100)

    @field_validator("container_code")
    @classmethod
    def normalize_container_code(cls, value: str) -> str:
        return value.strip().upper()


class MovePlacement(BaseModel):
    target_location_id: int = Field(gt=0)
    expected_version: int = Field(gt=0)
    idempotency_key: str = Field(min_length=8, max_length=100)
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=2, max_length=300)


class WithdrawalCreate(BaseModel):
    specimen_id: int = Field(gt=0)
    quantity: float = Field(gt=0)
    movement_type: str = Field(pattern="^(取样|领用|报废)$")
    idempotency_key: str = Field(min_length=8, max_length=100)
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=2, max_length=300)


class HoldCreate(BaseModel):
    specimen_id: int = Field(gt=0)
    hold_type: str = Field(pattern="^(保全|质量|权限|争议)$")
    reason: str = Field(min_length=2, max_length=500)
    actor: str = Field(min_length=1, max_length=100)


class HoldRelease(BaseModel):
    reason: str = Field(min_length=2, max_length=500)
    actor: str = Field(min_length=1, max_length=100)


class ProtocolCreate(BaseModel):
    protocol_code: str = Field(min_length=2, max_length=40)
    discipline: str = Field(min_length=1, max_length=100)
    observation_target: int = Field(gt=0, le=100_000)
    checkpoint_count: int = Field(gt=0, le=100)
    reference_value: float = Field(ge=-20, le=60)
    turnaround_days: int = Field(gt=0, le=365)
    conclusion_rule: str = Field(min_length=5, max_length=1000)
    created_by: str = Field(min_length=1, max_length=100)

    @field_validator("protocol_code")
    @classmethod
    def normalize_protocol_code(cls, value: str) -> str:
        return value.strip().upper()


class ExaminationCreate(BaseModel):
    examination_no: str = Field(min_length=3, max_length=60)
    specimen_id: int = Field(gt=0)
    protocol_id: int = Field(gt=0)
    examination_type: ExaminationType
    sample_quantity: float = Field(gt=0)
    scheduled_for: date
    requested_by: str = Field(min_length=1, max_length=100)
    idempotency_key: str = Field(min_length=8, max_length=100)

    @field_validator("examination_no")
    @classmethod
    def normalize_examination_no(cls, value: str) -> str:
        return value.strip().upper()


class ExaminationStart(BaseModel):
    performed_by: str = Field(min_length=1, max_length=100)
    expected_version: int = Field(gt=0)


class ObservationCreate(BaseModel):
    checkpoint_no: int = Field(gt=0, le=100)
    items_checked: int = Field(gt=0, le=100_000)
    conforming_count: int = Field(ge=0)
    exception_count: int = Field(ge=0)
    unusable_count: int = Field(ge=0)
    pending_count: int = Field(default=0, ge=0)
    sequence_no: int = Field(gt=0, le=365)
    observed_by: str = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_total(self) -> "ObservationCreate":
        actual = self.conforming_count + self.exception_count + self.unusable_count + self.pending_count
        if actual != self.items_checked:
            raise ValueError("符合、疑点、不可用和待复核项数之和必须等于检查项数")
        return self


class ExaminationComplete(BaseModel):
    expected_version: int = Field(gt=0)
    performed_by: str = Field(min_length=1, max_length=100)


class ExaminationInvalidate(BaseModel):
    expected_version: int = Field(gt=0)
    reason: str = Field(min_length=3, max_length=500)
    actor: str = Field(min_length=1, max_length=100)


class PolicyCreate(BaseModel):
    discipline: str = Field(min_length=1, max_length=100)
    risk_level: str = Field(pattern="^(low|medium|high)$")
    interval_months: int = Field(gt=0, le=240)
    warning_days: int = Field(ge=0, le=365)
    minimum_conformity_percent: float = Field(ge=0, le=100)
    effective_from: date
    effective_to: date | None = None
    created_by: str = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_period(self) -> "PolicyCreate":
        if self.effective_to and self.effective_to < self.effective_from:
            raise ValueError("策略失效日期不能早于生效日期")
        return self


class ReadingCreate(BaseModel):
    location_id: int = Field(gt=0)
    observed_at: datetime
    reference_value: float = Field(ge=-196, le=80)
    humidity_percent: float = Field(ge=0, le=100)
    source_key: str = Field(min_length=3, max_length=100)


class AlertDecision(BaseModel):
    action: str = Field(pattern="^(acknowledge|resolve|dismiss)$")
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=500)


class ReleaseCreate(BaseModel):
    request_no: str = Field(min_length=3, max_length=60)
    requester: str = Field(min_length=1, max_length=200)
    purpose: str = Field(min_length=3, max_length=1000)
    items: list[dict[str, Any]] = Field(min_length=1, max_length=200)

    @field_validator("request_no")
    @classmethod
    def normalize_request_no(cls, value: str) -> str:
        return value.strip().upper()


class ReleaseDecision(BaseModel):
    approve: bool
    expected_version: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=500)


class Page(BaseModel):
    items: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class ImpactRuleCreate(BaseModel):
    rule_code: str = Field(min_length=2, max_length=60)
    rule_name: str = Field(min_length=2, max_length=200)
    rule_type: str = Field(pattern="^(time_proximity|reagent_batch|equipment|workbench_slot)$")
    discipline: str = Field(default="", max_length=100)
    params: dict[str, Any] = Field(default_factory=dict)
    created_by: str = Field(min_length=1, max_length=100)

    @field_validator("rule_code")
    @classmethod
    def normalize_rule_code(cls, value: str) -> str:
        return value.strip().upper()


class EventResourceInput(BaseModel):
    resource_type: str = Field(pattern="^(reagent_batch|equipment|workbench)$")
    resource_ref: str = Field(min_length=1, max_length=120)
    observed_at: datetime | None = None
    note: str = Field(default="", max_length=500)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("resource_ref")
    @classmethod
    def normalize_ref(cls, value: str) -> str:
        return value.strip()


class EventEvidenceInput(BaseModel):
    evidence_type: str = Field(default="other", pattern="^(document|reading|alert|observation|other)$")
    reference: str = Field(min_length=1, max_length=300)
    summary: str = Field(default="", max_length=1000)
    collected_at: datetime | None = None
    recorded_by: str | None = Field(default=None, min_length=1, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class QualityEventCreate(BaseModel):
    event_no: str = Field(min_length=3, max_length=60)
    title: str = Field(min_length=2, max_length=200)
    event_type: str = Field(default="blank_contamination", max_length=60)
    contaminant: str = Field(default="", max_length=200)
    discipline: str = Field(default="", max_length=100)
    window_start: datetime
    window_end: datetime
    description: str = Field(default="", max_length=2000)
    resources: list[EventResourceInput] = Field(default_factory=list, max_length=100)
    evidence: list[EventEvidenceInput] = Field(default_factory=list, max_length=100)
    created_by: str = Field(min_length=1, max_length=100)

    @field_validator("event_no")
    @classmethod
    def normalize_event_no(cls, value: str) -> str:
        return value.strip().upper()

    @model_validator(mode="after")
    def validate_window(self) -> "QualityEventCreate":
        if self.window_end < self.window_start:
            raise ValueError("污染时间窗结束时间不能早于开始时间")
        return self


class EventResourcesAdd(BaseModel):
    resources: list[EventResourceInput] = Field(min_length=1, max_length=100)
    expected_version: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=100)


class EventEvidenceAdd(BaseModel):
    evidence_type: str = Field(default="other", pattern="^(document|reading|alert|observation|other)$")
    reference: str = Field(min_length=1, max_length=300)
    summary: str = Field(default="", max_length=1000)
    collected_at: datetime | None = None
    recorded_by: str | None = Field(default=None, min_length=1, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)
    expected_version: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=100)


class EventClose(BaseModel):
    expected_version: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=100)
    summary: str = Field(default="", max_length=1000)


class ResourceUseCreate(BaseModel):
    resource_type: str = Field(pattern="^(reagent_batch|equipment|workbench)$")
    resource_ref: str = Field(min_length=1, max_length=120)
    used_from: datetime | None = None
    used_to: datetime | None = None
    source_key: str = Field(min_length=3, max_length=120)
    recorded_by: str = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_interval(self) -> "ResourceUseCreate":
        if self.used_from and self.used_to and self.used_to < self.used_from:
            raise ValueError("资源使用结束时间不能早于开始时间")
        return self


class CandidateDecision(BaseModel):
    action: str = Field(pattern="^(exclude|confirm|reopen)$")
    reason: str = Field(default="", max_length=1000)
    expected_version: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=100)
    detail: dict[str, Any] = Field(default_factory=dict)


class ReportRegister(BaseModel):
    report_no: str = Field(min_length=3, max_length=60)
    document_ref: str = Field(default="", max_length=300)
    conclusion_digest: str = Field(default="", max_length=500)
    issued_by: str = Field(min_length=1, max_length=100)
    issued_at: datetime | None = None

    @field_validator("report_no")
    @classmethod
    def normalize_report_no(cls, value: str) -> str:
        return value.strip().upper()


class WithdrawalDecision(BaseModel):
    approve: bool
    actor: str = Field(min_length=1, max_length=100)
    note: str = Field(min_length=2, max_length=1000)


class ReviewFlagClear(BaseModel):
    actor: str = Field(min_length=1, max_length=100)
    note: str = Field(min_length=2, max_length=1000)
