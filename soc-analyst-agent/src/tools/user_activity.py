from __future__ import annotations

import hashlib
import logging
import os

import httpx

from src.models.schemas import UserActivitySnapshot

logger = logging.getLogger(__name__)


def _use_mock() -> bool:
    return os.environ.get("USE_MOCK_SIEM", "true").lower() == "true"


async def fetch_user_activity(user: str) -> UserActivitySnapshot:
    if _use_mock():
        return _mock_user_activity(user)

    idp_url = os.environ["IDENTITY_PROVIDER_API_URL"]
    api_key = os.environ["IDENTITY_PROVIDER_API_KEY"]
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{idp_url}/users/{user}/activity", headers={"Authorization": f"Bearer {api_key}"}
        )
        resp.raise_for_status()
        data = resp.json()
    return UserActivitySnapshot(
        user=user,
        recent_logins=data.get("recent_logins", []),
        is_privileged=data.get("is_privileged", False),
        anomalous_activity=data.get("anomalous_activity", False),
        notes=data.get("notes", ""),
    )


def _mock_user_activity(user: str) -> UserActivitySnapshot:
    digest = int(hashlib.sha256(user.encode()).hexdigest(), 16)
    is_privileged = "admin" in user.lower() or digest % 7 == 0
    anomalous = digest % 3 == 0
    return UserActivitySnapshot(
        user=user,
        recent_logins=[
            {"ip": "10.0.4.22", "location": "Gurugram, IN", "success": True},
            {"ip": "203.0.113.55", "location": "Unknown/VPN", "success": anomalous},
        ],
        is_privileged=is_privileged,
        anomalous_activity=anomalous,
        notes="Synthetic mock data for local dev/testing." + (" Flagged: login from atypical geo." if anomalous else ""),
    )
