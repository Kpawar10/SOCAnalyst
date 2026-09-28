"""Seed long-term memory with synthetic historical incidents.

Usage: python scripts/seed_memory.py
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv

from src.memory.vector_store import write_closed_incident
from src.models.schemas import AlertCategory

load_dotenv()

SEED_INCIDENTS = [
    dict(
        incident_id="INC-2025-0142",
        summary=(
            "Repeated failed SSH logins from a single external IP against a jump-box, "
            "followed by one successful login using a service account password. "
            "Confirmed credential-stuffing attack; IP was already flagged by threat intel."
        ),
        category=AlertCategory.BRUTE_FORCE,
        resolution="closed_approved - blocked source IP, rotated service account credentials",
    ),
    dict(
        incident_id="INC-2025-0198",
        summary=(
            "Endpoint alert for PowerShell spawned from Outlook.exe with base64-encoded "
            "command line, contacting a newly-registered domain. Confirmed phishing "
            "payload delivering a loader."
        ),
        category=AlertCategory.MALWARE,
        resolution="closed_approved - isolated host, reset user credentials, blocked C2 domain",
    ),
    dict(
        incident_id="INC-2025-0211",
        summary=(
            "User account began downloading large volumes of files from SharePoint "
            "outside normal working hours shortly after an HR-flagged resignation. "
            "Investigation confirmed authorized off-boarding data export, not exfiltration."
        ),
        category=AlertCategory.FALSE_POSITIVE_LIKELY,
        resolution="closed_rejected - confirmed benign, added to allowlist for HR off-boarding pattern",
    ),
    dict(
        incident_id="INC-2025-0233",
        summary=(
            "Service account normally used only for nightly batch jobs authenticated "
            "interactively from an unfamiliar geographic location and attempted to add "
            "itself to the Domain Admins group."
        ),
        category=AlertCategory.PRIVILEGE_ESCALATION,
        resolution="closed_approved - suspended account pending manual investigation, required two-person approval",
    ),
    dict(
        incident_id="INC-2025-0267",
        summary=(
            "Beaconing pattern detected: workstation making periodic HTTPS calls to a "
            "domain with a low reputation score every 60 seconds, consistent with C2 "
            "check-in behavior. JA3 fingerprint matched a known malware family."
        ),
        category=AlertCategory.C2_BEACON,
        resolution="closed_approved - isolated host, blocked domain and associated IP range",
    ),
]


async def main() -> None:
    for incident in SEED_INCIDENTS:
        await write_closed_incident(**incident)
    print(f"Seeded {len(SEED_INCIDENTS)} historical incidents into long-term memory.")


if __name__ == "__main__":
    asyncio.run(main())
