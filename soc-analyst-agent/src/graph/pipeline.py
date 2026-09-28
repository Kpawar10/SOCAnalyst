from __future__ import annotations

import logging

from langgraph.graph import END, StateGraph

from src.agents.investigation_agent import investigation_node
from src.agents.remediation_agent import remediation_node
from src.agents.review_agent import review_node
from src.agents.triage_agent import triage_node
from src.models.schemas import PipelineState

logger = logging.getLogger(__name__)


def _route_after_triage(state: PipelineState) -> str:
    """Skip straight to end if triage flagged this as a duplicate or not worth investigating."""
    if state.triage and state.triage.is_duplicate:
        logger.info("alert=%s is a duplicate of %s, ending pipeline", state.raw_alert.alert_id, state.triage.duplicate_of)
        return "end"
    if state.triage and not state.triage.requires_investigation:
        return "investigate"  # still runs, but the node itself short-circuits and produces a stub
    return "investigate"


def _route_after_review(state: PipelineState) -> str:
    return "end"


def build_pipeline():
    """Construct and compile the LangGraph state machine.

    Triage --> [duplicate? end : Investigate] --> Remediate --> Review --> End
    """
    graph = StateGraph(PipelineState)

    graph.add_node("triage", triage_node)
    graph.add_node("investigate", investigation_node)
    graph.add_node("remediate", remediation_node)
    graph.add_node("review", review_node)

    graph.set_entry_point("triage")

    graph.add_conditional_edges(
        "triage",
        _route_after_triage,
        {"investigate": "investigate", "end": END},
    )
    graph.add_edge("investigate", "remediate")
    graph.add_edge("remediate", "review")
    graph.add_conditional_edges("review", _route_after_review, {"end": END})

    return graph.compile()


# Compiled once at import time; reused across requests.
soc_pipeline = build_pipeline()


async def run_pipeline(raw_alert) -> PipelineState:
    initial_state = PipelineState(raw_alert=raw_alert)
    final_state_dict = await soc_pipeline.ainvoke(initial_state)
    # LangGraph returns a dict-like state; rehydrate into our Pydantic model.
    if isinstance(final_state_dict, PipelineState):
        return final_state_dict
    return PipelineState(**final_state_dict)
