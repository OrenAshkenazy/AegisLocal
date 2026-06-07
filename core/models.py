# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ExecutionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    SCAN_INCOMPLETE = "SCAN_INCOMPLETE"


class ProductionDecision(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK_STAGING = "BLOCK_STAGING"
    BLOCK_PRODUCTION = "BLOCK_PRODUCTION"
    SCAN_INVALID = "SCAN_INVALID"


class ErrorSource(str, Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    CONFIG = "config"


class FindingAction(str, Enum):
    FAIL = "FAIL"
    WARN = "WARN"
    INFO = "INFO"


class Finding(BaseModel):
    severity: Severity
    category: str
    description: str
    action: FindingAction = FindingAction.FAIL
    remediation: Optional[str] = None
    fix_available: Optional[bool] = None
    fixed_version: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    vulnerability_id: Optional[str] = None
    vulnerability_ids: Optional[List[str]] = None
    source_file: Optional[str] = None
    license_id: Optional[str] = None
    license_source: Optional[str] = None
    subject_type: Optional[str] = None
    subject_name: Optional[str] = None


class LicenseCoverage(BaseModel):
    dependencies_total: int = 0
    dependencies_with_license_metadata: int = 0
    dependencies_missing_license_metadata: int = 0
    models_total: int = 0
    models_with_license_metadata: int = 0
    models_missing_license_metadata: int = 0


class GroupedFinding(BaseModel):
    category: str
    severity: Severity
    failed_count: int = Field(..., ge=1)
    payload_ids: List[str] = Field(default_factory=list)


class DynamicEvidence(BaseModel):
    payload_id: str
    category: str
    severity: Severity
    prompt_excerpt: Optional[str] = None
    prompt_truncated: bool = False
    expected_behavior: Optional[str] = None
    judge_verdict: str
    judge_model: Optional[str] = None
    judge_reason: Optional[str] = None
    target_response_excerpt: Optional[str] = None
    response_truncated: bool = False


class DynamicFindingAssessment(BaseModel):
    payload_id: str
    category: str
    severity: Severity
    verdict: str
    confidence: str
    judge_agreement: str
    evidence_available: bool = False


class ExecutionError(BaseModel):
    source: ErrorSource
    message: str
    path: Optional[str] = None
    payload_id: Optional[str] = None
    detail: Optional[str] = None


class Payload(BaseModel):
    id: str = Field(..., min_length=1)
    category: str = Field(..., min_length=1)
    severity: Severity
    text: str = Field(..., min_length=1)
    expected_behavior: str = Field(..., min_length=1)
    tags: List[str] = Field(default_factory=list)


class ReportRisk(BaseModel):
    severity: Severity
    category: str
    description: str
    owner: str
    remediation: Optional[str] = None
    payload_ids: List[str] = Field(default_factory=list)
    subject_name: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    vulnerability_ids: List[str] = Field(default_factory=list)
    source_file: Optional[str] = None


class RiskAreas(BaseModel):
    application_supply_chain: List[ReportRisk] = Field(default_factory=list)
    model_behavior: List[ReportRisk] = Field(default_factory=list)
    model_license: List[ReportRisk] = Field(default_factory=list)
    scan_reliability: List[ReportRisk] = Field(default_factory=list)


class OwnerRemediation(BaseModel):
    owner: str
    actions: List[str] = Field(default_factory=list)


class ExecutiveSummary(BaseModel):
    decision: ProductionDecision
    reason: str
    top_risks: List[str] = Field(default_factory=list)
    next_actions: List[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    scan_type: str = "all"
    target_endpoint: Optional[HttpUrl] = None
    target_model: Optional[str] = None
    target_timeout_seconds: Optional[float] = None
    dynamic_concurrency: Optional[int] = None
    judge_endpoint: Optional[HttpUrl] = None
    judge_model: Optional[str] = None
    fallback_judge_endpoint: Optional[HttpUrl] = None
    fallback_judge_model: Optional[str] = None
    include_evidence: Optional[bool] = None
    security_result: SecurityResult
    production_decision: ProductionDecision
    executive_summary: ExecutiveSummary
    execution_status: ExecutionStatus
    status_message: str
    incomplete_reason: Optional[str] = None
    findings: RiskAreas = Field(default_factory=RiskAreas)
    dynamic_assessments: List[DynamicFindingAssessment] = Field(default_factory=list)
    dynamic_evidence: List[DynamicEvidence] = Field(default_factory=list)
    license_coverage: Optional[LicenseCoverage] = None
    owner_remediation: List[OwnerRemediation] = Field(default_factory=list)
    execution_errors: List[ExecutionError] = Field(default_factory=list)
    passed_audit: bool
    scan_duration_seconds: float = 0.0
    scanner_version: str = "unknown"
