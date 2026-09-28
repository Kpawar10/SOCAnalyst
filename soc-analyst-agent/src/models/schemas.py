"""
Shared data contracts for the SOC pipeline.

IMPORTANT: every field pulled from an external system (SIEM, threat intel,
raw logs) is treated as untrusted string data. Nothing in these models is
ever interpolated into a prompt without being wrapped in the
<untrusted_data> guard — see src/agents/prompts.py.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertCategory(str, Enum):
    UNKNOWN = "unknown"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_EXFIL = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_BEACON = "c2_beacon"
    POLICY_VIOLATION = "policy_violation"
    FALSE_POSITIVE_LIKELY = "false_positive_likely"


class RawAlert(BaseModel):
    """What comes in off the wire from the SIEM. Treat all string fields as untrusted."""

    alert_id: str
    source: str  # e.g. "splunk", "datadog"
    received_at: datetime = Field(default_factory=datetime.utcnow)
    rule_name: str
    raw_severity: str
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    message: str
    raw_fields: dict[str, Any] = Field(default_factory=dict)


class TriageResult(BaseModel):
    alert_id: str
    category: AlertCategory
    severity: Severity
    priority_score: float  # 0-100, drives queue ordering
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    reasoning: str
    requires_investigation: bool = True


class ThreatIntelHit(BaseModel):
    indicator: str
    indicator_type: str  # ip, domain, hash, etc.
    malicious: bool
    confidence: float
    source: str
    tags: list[str] = Field(default_factory=list)


class UserActivitySnapshot(BaseModel):
    user: str
    recent_logins: list[dict[str, Any]] = Field(default_factory=list)
    is_privileged: bool = False
    anomalous_activity: bool = False
    notes: str = ""


class SimilarIncident(BaseModel):
    incident_id: str
    summary: str
    category: AlertCategory
    resolution: str
    similarity_score: float


class InvestigationResult(BaseModel):
    alert_id: str
    threat_intel_hits: list[ThreatIntelHit] = Field(default_factory=list)
    user_activity: Optional[UserActivitySnapshot] = None
    related_logs_summary: str
    similar_past_incidents: list[SimilarIncident] = Field(default_factory=list)
    assessed_confidence: float  # model's confidence this is a true positive, 0-1
    analyst_summary: str


class RemediationActionType(str, Enum):
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    SUSPEND_ACCOUNT = "suspend_account"
    RESET_CREDENTIALS = "reset_credentials"
    REVOKE_SESSION = "revoke_session"
    NO_ACTION = "no_action"
    ESCALATE_ONLY = "escalate_only"


class RemediationAction(BaseModel):
    action_type: RemediationActionType
    target: str  # IP, hostname, or username being acted on
    justification: str
    reversible: bool = True
    blast_radius: str  # human-readable description of what this affects


class RemediationPlan(BaseModel):
    alert_id: str
    actions: list[RemediationAction]
    overall_justification: str
    confidence: float


class PolicyViolation(BaseModel):
    rule_id: str
    description: str
    severity: Severity


class ReviewResult(BaseModel):
    alert_id: str
    approved_for_human_review: bool
    violations: list[PolicyViolation] = Field(default_factory=list)
    llm_notes: str
    requires_two_person_approval: bool = False


class PipelineState(BaseModel):
    """The LangGraph shared state object threaded through every node."""

    id: UUID = Field(default_factory=uuid4)
    raw_alert: RawAlert
    triage: Optional[TriageResult] = None
    investigation: Optional[InvestigationResult] = None
    remediation: Optional[RemediationPlan] = None
    review: Optional[ReviewResult] = None
    status: str = "ingested"
    errors: list[str] = Field(default_factory=list)

    class Config:
        arbitrary_types_allowed = True
