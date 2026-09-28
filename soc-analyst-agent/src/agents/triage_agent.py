from __future__ import annotations

import logging

from src.agents.llm_client import call_json
from src.agents.prompts import TRIAGE_SYSTEM_PROMPT, triage_user_prompt
from src.cache.redis_cache import is_recent_duplicate, remember_alert_fingerprint
from src.models.schemas import AlertCategory, PipelineState, Severity, TriageResult

logger = logging.getLogger(__name__)


async def triage_node(state: PipelineState) -> PipelineState:
    """Categorize, score, and dedupe the incoming alert."""
    alert = state.raw_alert

    # Fast deterministic dedupe check via Redis before spending an LLM call.
    fingerprint = f"{alert.rule_name}:{alert.host}:{alert.src_ip}:{alert.user}"
    duplicate_of = await is_recent_duplicate(fingerprint)

    result = call_json(
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        user_prompt=triage_user_prompt(alert.model_dump(mode="json")),
    )

    triage = TriageResult(
        alert_id=alert.alert_id,
        category=AlertCategory(result.get("category", "unknown")),
        severity=Severity(result.get("severity", "low")),
        priority_score=float(result.get("priority_score", 0)),
        is_duplicate=bool(duplicate_of) or bool(result.get("is_duplicate", False)),
        duplicate_of=duplicate_of,
        reasoning=result.get("reasoning", ""),
        requires_investigation=bool(result.get("requires_investigation", True)),
    )

    if not duplicate_of:
        await remember_alert_fingerprint(fingerprint, alert.alert_id)

    state.triage = triage
    state.status = "triaged"
    logger.info(
        "Triaged alert=%s category=%s severity=%s priority=%.1f duplicate=%s",
        alert.alert_id, triage.category, triage.severity, triage.priority_score, triage.is_duplicate,
    )
    return state
