"""
Deterministic policy engine. This is plain Python, not an LLM call --
by design, it CANNOT be prompt-injected, because it never reads a prompt.
It only reads structured Pydantic fields.

Every rule here should be simple enough that a security reviewer can audit
it in a code review without needing to reason about model behavior.
"""
from __future__ import annotations

import ipaddress
import os

from src.models.schemas import (
    PolicyViolation,
    RemediationAction,
    RemediationActionType,
    RemediationPlan,
    Severity,
    InvestigationResult,
)

PRIVILEGED_ROLE_MARKERS = {"domain_admin", "admin", "root", "service_account"}


def _office_cidrs() -> list[ipaddress.IPv4Network]:
    raw = os.environ.get("OFFICE_CIDR_ALLOWLIST", "10.0.0.0/8,192.168.0.0/16")
    nets = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            nets.append(ipaddress.ip_network(chunk, strict=False))
        except ValueError:
            continue
    return nets


def _ip_in_office_range(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _office_cidrs())


def evaluate_policies(
    plan: RemediationPlan,
    investigation: InvestigationResult,
) -> list[PolicyViolation]:
    """Run every hard rule against the proposed plan. Returns violations (empty = clean)."""
    violations: list[PolicyViolation] = []

    for action in plan.actions:
        violations.extend(_rule_no_blocking_office_ips(action))
        violations.extend(_rule_privileged_account_needs_high_confidence(action, investigation))
        violations.extend(_rule_irreversible_actions_need_high_confidence(action, plan))
        violations.extend(_rule_low_confidence_no_action_required(action, investigation))

    violations.extend(_rule_blast_radius_must_be_described(plan))

    return violations


def _rule_no_blocking_office_ips(action: RemediationAction) -> list[PolicyViolation]:
    """Never propose blocking or isolating an address inside our own office CIDR ranges."""
    violations = []
    if action.action_type in (RemediationActionType.BLOCK_IP, RemediationActionType.ISOLATE_HOST):
        if _ip_in_office_range(action.target):
            violations.append(
                PolicyViolation(
                    rule_id="NO_BLOCK_OFFICE_IP",
                    description=(
                        f"Proposed {action.action_type.value} on '{action.target}', which falls inside "
                        "the office/internal CIDR allowlist. Blocking internal ranges risks a "
                        "self-inflicted outage and is never auto-approved."
                    ),
                    severity=Severity.CRITICAL,
                )
            )
    return violations


def _rule_privileged_account_needs_high_confidence(
    action: RemediationAction, investigation: InvestigationResult
) -> list[PolicyViolation]:
    """Suspending/resetting a privileged account requires high investigation confidence."""
    violations = []
    is_privileged_target = (
        investigation.user_activity is not None
        and investigation.user_activity.is_privileged
        and investigation.user_activity.user == action.target
    )
    if action.action_type in (
        RemediationActionType.SUSPEND_ACCOUNT,
        RemediationActionType.RESET_CREDENTIALS,
    ) and is_privileged_target:
        if investigation.assessed_confidence < 0.85:
            violations.append(
                PolicyViolation(
                    rule_id="PRIV_ACCOUNT_HIGH_CONFIDENCE_REQUIRED",
                    description=(
                        f"Action '{action.action_type.value}' targets privileged account "
                        f"'{action.target}' but investigation confidence "
                        f"({investigation.assessed_confidence:.2f}) is below the 0.85 threshold "
                        "required for actions against privileged accounts."
                    ),
                    severity=Severity.CRITICAL,
                )
            )
    return violations


def _rule_irreversible_actions_need_high_confidence(
    action: RemediationAction, plan: RemediationPlan
) -> list[PolicyViolation]:
    violations = []
    if not action.reversible and plan.confidence < 0.7:
        violations.append(
            PolicyViolation(
                rule_id="IRREVERSIBLE_ACTION_LOW_CONFIDENCE",
                description=(
                    f"Action '{action.action_type.value}' on '{action.target}' is marked "
                    f"irreversible, but overall plan confidence ({plan.confidence:.2f}) is "
                    "below 0.7. Irreversible actions require higher confidence."
                ),
                severity=Severity.HIGH,
            )
        )
    return violations


def _rule_low_confidence_no_action_required(
    action: RemediationAction, investigation: InvestigationResult
) -> list[PolicyViolation]:
    violations = []
    disruptive = {
        RemediationActionType.BLOCK_IP,
        RemediationActionType.ISOLATE_HOST,
        RemediationActionType.SUSPEND_ACCOUNT,
        RemediationActionType.RESET_CREDENTIALS,
    }
    if action.action_type in disruptive and investigation.assessed_confidence < 0.4:
        violations.append(
            PolicyViolation(
                rule_id="DISRUPTIVE_ACTION_BELOW_MIN_CONFIDENCE",
                description=(
                    f"Disruptive action '{action.action_type.value}' proposed with investigation "
                    f"confidence {investigation.assessed_confidence:.2f}, below the hard floor of 0.4."
                ),
                severity=Severity.CRITICAL,
            )
        )
    return violations


def _rule_blast_radius_must_be_described(plan: RemediationPlan) -> list[PolicyViolation]:
    violations = []
    for action in plan.actions:
        if not action.blast_radius or action.blast_radius.strip().lower() in ("", "unspecified", "unknown"):
            violations.append(
                PolicyViolation(
                    rule_id="BLAST_RADIUS_REQUIRED",
                    description=(
                        f"Action '{action.action_type.value}' on '{action.target}' has no "
                        "meaningful blast_radius description. A human reviewer cannot assess "
                        "impact without this."
                    ),
                    severity=Severity.MEDIUM,
                )
            )
    return violations
