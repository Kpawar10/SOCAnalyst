from __future__ import annotations

import logging

from src.agents.llm_client import call_json
from src.agents.prompts import REMEDIATION_SYSTEM_PROMPT, remediation_user_prompt
from src.models.schemas import (
    PipelineState,
    RemediationAction,
    RemediationActionType,
    RemediationPlan,
)

logger = logging.getLogger(__name__)

# Below this confidence, we never propose anything more than escalation.
MIN_CONFIDENCE_FOR_ACTIVE_REMEDIATION = 0.4


async def remediation_node(state: PipelineState) -> PipelineState:
    investigation = state.investigation
    triage = state.triage
    assert investigation is not None and triage is not None

    if investigation.assessed_confidence < MIN_CONFIDENCE_FOR_ACTIVE_REMEDIATION:
        plan = RemediationPlan(
            alert_id=state.raw_alert.alert_id,
            actions=[
                RemediationAction(
                    action_type=RemediationActionType.ESCALATE_ONLY,
                    target=state.raw_alert.host or state.raw_alert.user or "unknown",
                    justification=(
                        f"Investigation confidence ({investigation.assessed_confidence:.2f}) is below the "
                        f"{MIN_CONFIDENCE_FOR_ACTIVE_REMEDIATION} threshold for automated remediation "
                        "proposals. Escalating to a human analyst for manual review instead."
                    ),
                    reversible=True,
                    blast_radius="None - informational escalation only.",
                )
            ],
            overall_justification="Low-confidence investigation; deferring to human judgement.",
            confidence=investigation.assessed_confidence,
        )
        state.remediation = plan
        state.status = "remediation_proposed"
        return state

    result = call_json(
        system_prompt=REMEDIATION_SYSTEM_PROMPT,
        user_prompt=remediation_user_prompt(
            investigation_json=investigation.model_dump(mode="json"),
            triage_json=triage.model_dump(mode="json"),
        ),
    )

    actions = [
        RemediationAction(
            action_type=RemediationActionType(a["action_type"]),
            target=a["target"],
            justification=a["justification"],
            reversible=bool(a.get("reversible", True)),
            blast_radius=a.get("blast_radius", "unspecified"),
        )
        for a in result.get("actions", [])
    ]

    plan = RemediationPlan(
        alert_id=state.raw_alert.alert_id,
        actions=actions,
        overall_justification=result.get("overall_justification", ""),
        confidence=float(result.get("confidence", investigation.assessed_confidence)),
    )

    state.remediation = plan
    state.status = "remediation_proposed"
    logger.info(
        "Proposed remediation for alert=%s: %s",
        state.raw_alert.alert_id, [a.action_type for a in actions],
    )
    return state
