"""
Unit tests for the deterministic policy engine. These run with no network,
no LLM, no database -- pure Python logic tests, which is exactly why the
guardrail layer is designed this way (see src/guardrails/policies.py).
"""
import os

os.environ.setdefault("OFFICE_CIDR_ALLOWLIST", "10.0.0.0/8,192.168.0.0/16")

from src.guardrails.policies import evaluate_policies
from src.models.schemas import (
    InvestigationResult,
    RemediationAction,
    RemediationActionType,
    RemediationPlan,
    UserActivitySnapshot,
)


def make_investigation(confidence=0.9, privileged_user=None):
    return InvestigationResult(
        alert_id="A1",
        related_logs_summary="test",
        assessed_confidence=confidence,
        analyst_summary="test",
        user_activity=(
            UserActivitySnapshot(user=privileged_user, is_privileged=True, notes="")
            if privileged_user
            else None
        ),
    )


def test_blocking_office_ip_is_flagged():
    plan = RemediationPlan(
        alert_id="A1",
        actions=[
            RemediationAction(
                action_type=RemediationActionType.BLOCK_IP,
                target="10.0.7.9",
                justification="scan source",
                reversible=True,
                blast_radius="single host",
            )
        ],
        overall_justification="test",
        confidence=0.9,
    )
    violations = evaluate_policies(plan, make_investigation())
    assert any(v.rule_id == "NO_BLOCK_OFFICE_IP" for v in violations)


def test_blocking_external_ip_is_clean():
    plan = RemediationPlan(
        alert_id="A1",
        actions=[
            RemediationAction(
                action_type=RemediationActionType.BLOCK_IP,
                target="185.220.101.47",
                justification="known C2",
                reversible=True,
                blast_radius="single external IP",
            )
        ],
        overall_justification="test",
        confidence=0.9,
    )
    violations = evaluate_policies(plan, make_investigation())
    assert not any(v.rule_id == "NO_BLOCK_OFFICE_IP" for v in violations)


def test_privileged_account_low_confidence_flagged():
    plan = RemediationPlan(
        alert_id="A1",
        actions=[
            RemediationAction(
                action_type=RemediationActionType.SUSPEND_ACCOUNT,
                target="svc_backup_admin",
                justification="weird login",
                reversible=True,
                blast_radius="one service account",
            )
        ],
        overall_justification="test",
        confidence=0.6,
    )
    violations = evaluate_policies(
        plan, make_investigation(confidence=0.5, privileged_user="svc_backup_admin")
    )
    assert any(v.rule_id == "PRIV_ACCOUNT_HIGH_CONFIDENCE_REQUIRED" for v in violations)


def test_privileged_account_high_confidence_passes():
    plan = RemediationPlan(
        alert_id="A1",
        actions=[
            RemediationAction(
                action_type=RemediationActionType.SUSPEND_ACCOUNT,
                target="svc_backup_admin",
                justification="confirmed by two independent detections",
                reversible=True,
                blast_radius="one service account",
            )
        ],
        overall_justification="test",
        confidence=0.95,
    )
    violations = evaluate_policies(
        plan, make_investigation(confidence=0.95, privileged_user="svc_backup_admin")
    )
    assert not any(v.rule_id == "PRIV_ACCOUNT_HIGH_CONFIDENCE_REQUIRED" for v in violations)


def test_irreversible_low_confidence_flagged():
    plan = RemediationPlan(
        alert_id="A1",
        actions=[
            RemediationAction(
                action_type=RemediationActionType.RESET_CREDENTIALS,
                target="j.martinez",
                justification="maybe phishing",
                reversible=False,
                blast_radius="one user",
            )
        ],
        overall_justification="test",
        confidence=0.5,
    )
    violations = evaluate_policies(plan, make_investigation(confidence=0.5))
    assert any(v.rule_id == "IRREVERSIBLE_ACTION_LOW_CONFIDENCE" for v in violations)


def test_missing_blast_radius_flagged():
    plan = RemediationPlan(
        alert_id="A1",
        actions=[
            RemediationAction(
                action_type=RemediationActionType.ISOLATE_HOST,
                target="WKSTN-4471",
                justification="malware",
                reversible=True,
                blast_radius="unspecified",
            )
        ],
        overall_justification="test",
        confidence=0.9,
    )
    violations = evaluate_policies(plan, make_investigation(confidence=0.9))
    assert any(v.rule_id == "BLAST_RADIUS_REQUIRED" for v in violations)


def test_disruptive_action_below_confidence_floor():
    plan = RemediationPlan(
        alert_id="A1",
        actions=[
            RemediationAction(
                action_type=RemediationActionType.ISOLATE_HOST,
                target="WKSTN-4471",
                justification="weak signal",
                reversible=True,
                blast_radius="one workstation",
            )
        ],
        overall_justification="test",
        confidence=0.2,
    )
    violations = evaluate_policies(plan, make_investigation(confidence=0.2))
    assert any(v.rule_id == "DISRUPTIVE_ACTION_BELOW_MIN_CONFIDENCE" for v in violations)
