from __future__ import annotations

import logging

from src.agents.llm_client import call_json
from src.agents.prompts import INVESTIGATION_SYSTEM_PROMPT, investigation_user_prompt
from src.memory.vector_store import search_similar_incidents
from src.models.schemas import InvestigationResult, PipelineState, SimilarIncident, ThreatIntelHit, UserActivitySnapshot
from src.tools.siem_client import fetch_related_logs
from src.tools.threat_intel import lookup_indicators
from src.tools.user_activity import fetch_user_activity

logger = logging.getLogger(__name__)


async def investigation_node(state: PipelineState) -> PipelineState:
    alert = state.raw_alert
    triage = state.triage
    assert triage is not None, "investigation_node requires triage to have run first"

    if not triage.requires_investigation:
        state.investigation = InvestigationResult(
            alert_id=alert.alert_id,
            related_logs_summary="Skipped - triage marked this as not requiring investigation.",
            assessed_confidence=0.0,
            analyst_summary="Triage determined this alert does not warrant investigation.",
        )
        state.status = "investigation_skipped"
        return state

    # --- Gather evidence from tools (these hit mocked or real integrations) ---
    indicators = [i for i in [alert.src_ip, alert.dst_ip, alert.host] if i]
    intel_hits: list[ThreatIntelHit] = await lookup_indicators(indicators)

    user_activity: UserActivitySnapshot | None = None
    if alert.user:
        user_activity = await fetch_user_activity(alert.user)

    related_logs = await fetch_related_logs(alert)

    similar: list[SimilarIncident] = await search_similar_incidents(
        query_text=f"{alert.rule_name} {alert.message}",
        category=triage.category,
        top_k=3,
    )

    # --- Synthesize with the LLM ---
    result = call_json(
        system_prompt=INVESTIGATION_SYSTEM_PROMPT,
        user_prompt=investigation_user_prompt(
            triage_json=triage.model_dump(mode="json"),
            threat_intel=[h.model_dump(mode="json") for h in intel_hits],
            user_activity=user_activity.model_dump(mode="json") if user_activity else None,
            related_logs=related_logs,
            similar_incidents=[s.model_dump(mode="json") for s in similar],
        ),
    )

    investigation = InvestigationResult(
        alert_id=alert.alert_id,
        threat_intel_hits=intel_hits,
        user_activity=user_activity,
        related_logs_summary=result.get("related_logs_summary", ""),
        similar_past_incidents=similar,
        assessed_confidence=float(result.get("assessed_confidence", 0.5)),
        analyst_summary=result.get("analyst_summary", ""),
    )

    state.investigation = investigation
    state.status = "investigated"
    logger.info(
        "Investigated alert=%s confidence=%.2f intel_hits=%d",
        alert.alert_id, investigation.assessed_confidence, len(intel_hits),
    )
    return state
