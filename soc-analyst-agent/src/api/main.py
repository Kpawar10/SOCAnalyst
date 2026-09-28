from __future__ import annotations

import logging
import os
from typing import Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel

load_dotenv()

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("soc_api")

from src.graph.pipeline import run_pipeline  # noqa: E402
from src.memory.vector_store import write_closed_incident  # noqa: E402
from src.models.schemas import AlertCategory, PipelineState, RawAlert  # noqa: E402

app = FastAPI(
    title="Autonomous SOC Analyst",
    description="4-agent pipeline: Triage -> Investigate -> Remediate -> Review -> Human approval",
    version="0.1.0",
)

# In-memory store of pipeline runs, keyed by alert_id. Swap for a real table
# (see infra/terraform/rds.tf) in production -- this is fine for local dev/demo.
_pipeline_runs: dict[str, PipelineState] = {}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/alerts/ingest", status_code=202)
async def ingest_alert(alert: RawAlert, background_tasks: BackgroundTasks):
    """Accept a SIEM alert and kick off the pipeline asynchronously."""
    logger.info("Ingested alert_id=%s rule=%s", alert.alert_id, alert.rule_name)
    background_tasks.add_task(_run_and_store, alert)
    return {"accepted": True, "alert_id": alert.alert_id}


async def _run_and_store(alert: RawAlert) -> None:
    try:
        final_state = await run_pipeline(alert)
    except Exception:  # noqa: BLE001
        logger.exception("Pipeline failed for alert_id=%s", alert.alert_id)
        return
    _pipeline_runs[alert.alert_id] = final_state


@app.get("/alerts/{alert_id}")
async def get_alert_status(alert_id: str):
    state = _pipeline_runs.get(alert_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Not found (or still processing)")
    return state.model_dump(mode="json")


@app.get("/approvals/pending")
async def list_pending_approvals():
    pending = [
        s.model_dump(mode="json")
        for s in _pipeline_runs.values()
        if s.status == "approved_for_human_review"
    ]
    return {"count": len(pending), "items": pending}


class ApprovalDecision(BaseModel):
    approved: bool
    approver: str
    notes: Optional[str] = None
    resolution_summary: Optional[str] = None


@app.post("/approvals/{alert_id}/decide")
async def decide_approval(alert_id: str, decision: ApprovalDecision):
    """
    One-click human approval endpoint. Note that even on approval, this repo
    does NOT execute the remediation against real infrastructure -- see
    EXECUTE_REMEDIATIONS in .env.example. It logs the decision and (on close)
    writes the outcome back into long-term memory so future investigations
    benefit from it.
    """
    state = _pipeline_runs.get(alert_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Not found")
    if state.status != "approved_for_human_review":
        raise HTTPException(status_code=409, detail=f"Alert is in status '{state.status}', not awaiting approval")

    execute = os.environ.get("EXECUTE_REMEDIATIONS", "false").lower() == "true"
    if decision.approved and execute:
        logger.warning(
            "EXECUTE_REMEDIATIONS=true: would now call real firewall/IAM APIs for alert_id=%s "
            "(execution backend not implemented in this repo -- see src/tools/ for stubs).",
            alert_id,
        )
    elif decision.approved:
        logger.info("Approval recorded for alert_id=%s by %s (dry-run, not executed)", alert_id, decision.approver)
    else:
        logger.info("Remediation REJECTED for alert_id=%s by %s: %s", alert_id, decision.approver, decision.notes)

    state.status = "closed_approved" if decision.approved else "closed_rejected"

    if state.investigation and state.triage:
        await write_closed_incident(
            incident_id=alert_id,
            summary=decision.resolution_summary or state.investigation.analyst_summary,
            category=state.triage.category,
            resolution=state.status,
        )

    return {"alert_id": alert_id, "final_status": state.status}
