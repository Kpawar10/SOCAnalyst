from __future__ import annotations

import logging

from src.agents.llm_client import call_json
from src.agents.prompts import REVIEW_SYSTEM_PROMPT, review_user_prompt
from src.guardrails.policies import evaluate_policies
from src.models.schemas import PipelineState, ReviewResult, Severity

logger = logging.getLogger(__name__)


async def review_node(state: PipelineState) -> PipelineState:
    plan = state.remediation
    investigation = state.investigation
    assert plan is not None and investigation is not None

    # --- Layer 1: deterministic hard rules (cannot be prompt-injected) ---
    hard_violations = evaluate_policies(plan, investigation)
    any_critical = any(v.severity == Severity.CRITICAL for v in hard_violations)

    # --- Layer 2: LLM semantic second opinion ---
    llm_result = call_json(
        system_prompt=REVIEW_SYSTEM_PROMPT,
        user_prompt=review_user_prompt(
            remediation_json=plan.model_dump(mode="json"),
            investigation_json=investigation.model_dump(mode="json"),
            hard_rule_violations=[v.model_dump(mode="json") for v in hard_violations],
        ),
    )

    # A critical hard-rule violation always wins, regardless of what the LLM says.
    approved = bool(llm_result.get("approved_for_human_review", True)) and not any_critical

    review = ReviewResult(
        alert_id=state.raw_alert.alert_id,
        approved_for_human_review=approved,
        violations=hard_violations,
        llm_notes=llm_result.get("llm_notes", ""),
        requires_two_person_approval=bool(
            llm_result.get("requires_two_person_approval", False)
        )
        or any(not a.reversible for a in plan.actions),
    )

    state.review = review
    state.status = "approved_for_human_review" if approved else "blocked_by_review"
    logger.info(
        "Reviewed alert=%s approved=%s violations=%d two_person=%s",
        state.raw_alert.alert_id, approved, len(hard_violations), review.requires_two_person_approval,
    )
    return state
