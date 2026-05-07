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


class ErrorSource(str, Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    CONFIG = "config"


class Finding(BaseModel):
    severity: Severity
    category: str
    description: str
    remediation: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    vulnerability_id: Optional[str] = None
    source_file: Optional[str] = None


class GroupedFinding(BaseModel):
    category: str
    severity: Severity
    failed_count: int = Field(..., ge=1)
    payload_ids: List[str] = Field(default_factory=list)


class DynamicEvidence(BaseModel):
    payload_id: str
    category: str
    severity: Severity
    judge_verdict: str
    judge_model: Optional[str] = None
    target_response_excerpt: Optional[str] = None
    response_truncated: bool = False


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


class ScanReport(BaseModel):
    target_endpoint: HttpUrl
    target_model: str
    target_timeout_seconds: float
    dynamic_concurrency: int
    judge_endpoint: HttpUrl
    judge_model: str
    fallback_judge_endpoint: Optional[HttpUrl] = None
    fallback_judge_model: Optional[str] = None
    include_evidence: bool = False
    security_result: SecurityResult
    execution_status: ExecutionStatus
    status_message: str
    static_findings: List[Finding] = Field(default_factory=list)
    dynamic_findings: List[GroupedFinding] = Field(default_factory=list)
    dynamic_evidence: List[DynamicEvidence] = Field(default_factory=list)
    execution_errors: List[ExecutionError] = Field(default_factory=list)
    passed_audit: bool
