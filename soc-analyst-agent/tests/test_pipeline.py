"""
End-to-end pipeline test with `call_json` mocked, so this runs fully offline
(no Anthropic API key, no Postgres, no Redis needed) -- suitable for CI.
"""
from __future__ import annotations

import os

os.environ.setdefault("USE_MOCK_THREAT_INTEL", "true")
os.environ.setdefault("USE_MOCK_SIEM", "true")
os.environ.setdefault("OFFICE_CIDR_ALLOWLIST", "10.0.0.0/8,192.168.0.0/16")

from unittest.mock import AsyncMock, patch

import pytest

from src.models.schemas import RawAlert

MOCK_TRIAGE_RESPONSE = {
    "category": "malware",
    "severity": "high",
    "priority_score": 85.0,
    "is_duplicate": False,
    "reasoning": "Encoded PowerShell spawned from Outlook with outbound connection to a low-reputation IP.",
    "requires_investigation": True,
}

MOCK_INVESTIGATION_RESPONSE = {
    "assessed_confidence": 0.9,
    "analyst_summary": "Confirmed malicious: threat intel flagged the destination IP and the process tree matches known phishing-loader behavior.",
    "related_logs_summary": "Outbound HTTPS connection immediately followed the encoded PowerShell execution.",
}

MOCK_REMEDIATION_RESPONSE = {
    "actions": [
        {
            "action_type": "isolate_host",
            "target": "WKSTN-4471",
            "justification": "Confirmed malware execution with C2 callback.",
            "reversible": True,
            "blast_radius": "Single workstation loses network access until cleared.",
        }
    ],
    "overall_justification": "High-confidence malware detection warrants immediate host isolation.",
    "confidence": 0.9,
}

MOCK_REVIEW_RESPONSE = {
    "approved_for_human_review": True,
    "llm_notes": "Plan is proportionate to the evidence and uses a reversible action.",
    "requires_two_person_approval": False,
}


def _fake_call_json(system_prompt, user_prompt, max_tokens=1200):
    if "Triage Agent" in system_prompt:
        return MOCK_TRIAGE_RESPONSE
    if "Investigation Agent" in system_prompt:
        return MOCK_INVESTIGATION_RESPONSE
    if "Remediation Agent" in system_prompt:
        return MOCK_REMEDIATION_RESPONSE
    if "Review Agent" in system_prompt:
        return MOCK_REVIEW_RESPONSE
    raise AssertionError(f"Unexpected system prompt: {system_prompt[:50]}")


@pytest.fixture
def sample_alert():
    return RawAlert(
        alert_id="TEST-0001",
        source="splunk",
        rule_name="Suspicious PowerShell Encoded Command",
        raw_severity="high",
        host="WKSTN-4471",
        src_ip="10.0.4.22",
        dst_ip="185.220.101.47",
        user="j.martinez",
        message="powershell.exe -enc ... spawned from outlook.exe",
    )


@pytest.mark.asyncio
async def test_full_pipeline_happy_path(sample_alert):
    with patch("src.agents.triage_agent.call_json", side_effect=_fake_call_json), \
         patch("src.agents.investigation_agent.call_json", side_effect=_fake_call_json), \
         patch("src.agents.remediation_agent.call_json", side_effect=_fake_call_json), \
         patch("src.agents.review_agent.call_json", side_effect=_fake_call_json), \
         patch("src.cache.redis_cache.is_recent_duplicate", new=AsyncMock(return_value=None)), \
         patch("src.cache.redis_cache.remember_alert_fingerprint", new=AsyncMock(return_value=None)), \
         patch("src.tools.threat_intel.cache_get_json", new=AsyncMock(return_value=None)), \
         patch("src.tools.threat_intel.cache_set_json", new=AsyncMock(return_value=None)), \
         patch("src.memory.vector_store.search_similar_incidents", new=AsyncMock(return_value=[])):

        from src.graph.pipeline import run_pipeline

        final_state = await run_pipeline(sample_alert)

    assert final_state.status == "approved_for_human_review"
    assert final_state.triage.category.value == "malware"
    assert final_state.investigation.assessed_confidence == 0.9
    assert final_state.remediation.actions[0].action_type.value == "isolate_host"
    assert final_state.review.approved_for_human_review is True
    assert len(final_state.review.violations) == 0


@pytest.mark.asyncio
async def test_pipeline_blocks_when_remediation_targets_office_ip(sample_alert):
    """The Remediation Agent proposes blocking an internal IP; the deterministic
    guardrail must catch it even though the LLM 'approved' it."""
    bad_remediation = {
        "actions": [
            {
                "action_type": "block_ip",
                "target": "10.0.4.22",  # inside office CIDR
                "justification": "source of suspicious activity",
                "reversible": True,
                "blast_radius": "internal network segment",
            }
        ],
        "overall_justification": "Blocking the source IP.",
        "confidence": 0.9,
    }
    naive_review = {
        "approved_for_human_review": True,  # LLM naively approves; hard rule must override
        "llm_notes": "Looks reasonable.",
        "requires_two_person_approval": False,
    }

    def fake_call_json(system_prompt, user_prompt, max_tokens=1200):
        if "Triage Agent" in system_prompt:
            return MOCK_TRIAGE_RESPONSE
        if "Investigation Agent" in system_prompt:
            return MOCK_INVESTIGATION_RESPONSE
        if "Remediation Agent" in system_prompt:
            return bad_remediation
        if "Review Agent" in system_prompt:
            return naive_review
        raise AssertionError

    with patch("src.agents.triage_agent.call_json", side_effect=fake_call_json), \
         patch("src.agents.investigation_agent.call_json", side_effect=fake_call_json), \
         patch("src.agents.remediation_agent.call_json", side_effect=fake_call_json), \
         patch("src.agents.review_agent.call_json", side_effect=fake_call_json), \
         patch("src.cache.redis_cache.is_recent_duplicate", new=AsyncMock(return_value=None)), \
         patch("src.cache.redis_cache.remember_alert_fingerprint", new=AsyncMock(return_value=None)), \
         patch("src.tools.threat_intel.cache_get_json", new=AsyncMock(return_value=None)), \
         patch("src.tools.threat_intel.cache_set_json", new=AsyncMock(return_value=None)), \
         patch("src.memory.vector_store.search_similar_incidents", new=AsyncMock(return_value=[])):

        from src.graph.pipeline import run_pipeline

        final_state = await run_pipeline(sample_alert)

    # Even though the LLM review said "approved", the deterministic policy
    # engine must have caught the office-IP block and flipped the outcome.
    assert final_state.status == "blocked_by_review"
    assert final_state.review.approved_for_human_review is False
    assert any(v.rule_id == "NO_BLOCK_OFFICE_IP" for v in final_state.review.violations)
