from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

RESOURCE_TYPES = {"reagent_batch", "equipment", "workbench"}
RESOURCE_TYPE_LABELS = {"reagent_batch": "试剂批次", "equipment": "设备", "workbench": "工作台"}


class EvidenceCreate(BaseModel):
    evidence_type: str = Field(min_length=1, max_length=60)
    reference: str = Field(min_length=1, max_length=200)
    detail: dict[str, Any] = Field(default_factory=dict)
    created_by: str = Field(default="", max_length=100)


class ResourceRegister(BaseModel):
    resource_type: str
    resource_ref: str = Field(min_length=1, max_length=120)
    note: str = Field(default="", max_length=500)
    created_by: str = Field(min_length=1, max_length=100)

    @field_validator("resource_type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if value not in RESOURCE_TYPES:
            raise ValueError("资源类型必须是 reagent_batch、equipment 或 workbench")
        return value

    @field_validator("resource_ref")
    @classmethod
    def strip_ref(cls, value: str) -> str:
        return value.strip()


class IncidentCreate(BaseModel):
    incident_no: str = Field(min_length=3, max_length=60)
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=2000)
    window_start: datetime
    window_end: datetime
    created_by: str = Field(min_length=1, max_length=100)
    resources: list[ResourceRegister] = Field(default_factory=list, max_length=100)
    evidence: list[EvidenceCreate] = Field(default_factory=list, max_length=100)
    rule_window_slack_minutes: int = Field(default=0, ge=0, le=7 * 24 * 60)

    @field_validator("incident_no")
    @classmethod
    def normalize_no(cls, value: str) -> str:
        return value.strip().upper()

    @model_validator(mode="after")
    def validate_window(self) -> "IncidentCreate":
        if self.window_end <= self.window_start:
            raise ValueError("污染时间窗结束时间必须晚于开始时间")
        return self


class IncidentRulesUpdate(BaseModel):
    """发布新版本的匹配规则；rules 为每项资源一条匹配规则，按时间窗与资源标识命中。"""

    expected_version: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=100)
    note: str = Field(default="", max_length=500)
    window_start: datetime | None = None
    window_end: datetime | None = None
    rule_window_slack_minutes: int | None = Field(default=None, ge=0, le=7 * 24 * 60)
    resources: list[ResourceRegister] | None = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def validate_window(self) -> "IncidentRulesUpdate":
        if self.window_start and self.window_end and self.window_end <= self.window_start:
            raise ValueError("污染时间窗结束时间必须晚于开始时间")
        return self


class CandidateDecision(BaseModel):
    action: str = Field(pattern="^(exclude|confirm)$")
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=2, max_length=1000)
    expected_candidate_version: int | None = Field(default=None, gt=0)


class WithdrawalDecision(BaseModel):
    decision: str = Field(pattern="^(withdraw|uphold)$")
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=2, max_length=1000)


class ReviewFlagClear(BaseModel):
    actor: str = Field(min_length=1, max_length=100)
    note: str = Field(min_length=2, max_length=1000)


class IncidentClose(BaseModel):
    expected_version: int = Field(gt=0)
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=2, max_length=1000)


class ExaminationResourceCreate(BaseModel):
    """登记检验使用的试剂批次/设备/工作台时段，迟到数据以 source=late 补录。"""

    resource_type: str
    resource_ref: str = Field(min_length=1, max_length=120)
    used_from: datetime
    used_to: datetime
    source: str = Field(default="on_time", pattern="^(on_time|late)$")
    recorded_by: str = Field(min_length=1, max_length=100)

    @field_validator("resource_type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if value not in RESOURCE_TYPES:
            raise ValueError("资源类型必须是 reagent_batch、equipment 或 workbench")
        return value

    @field_validator("resource_ref")
    @classmethod
    def strip_ref(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_period(self) -> "ExaminationResourceCreate":
        if self.used_to <= self.used_from:
            raise ValueError("资源使用结束时间必须晚于开始时间")
        return self


class ReportIssue(BaseModel):
    report_no: str = Field(min_length=3, max_length=60)
    opinion_text: str = Field(min_length=2, max_length=10000)
    result: dict[str, Any] = Field(default_factory=dict)
    issued_by: str = Field(min_length=1, max_length=100)
    issued_at: datetime | None = None

    @field_validator("report_no")
    @classmethod
    def normalize_no(cls, value: str) -> str:
        return value.strip().upper()
