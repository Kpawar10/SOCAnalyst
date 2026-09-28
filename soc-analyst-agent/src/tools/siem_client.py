from __future__ import annotations

import logging
import os

import httpx

from src.models.schemas import RawAlert

logger = logging.getLogger(__name__)


def _use_mock() -> bool:
    return os.environ.get("USE_MOCK_SIEM", "true").lower() == "true"


async def fetch_related_logs(alert: RawAlert) -> str:
    """Pull raw log lines related to this alert's host/user/timeframe from the SIEM."""
    if _use_mock():
        return _mock_related_logs(alert)

    api_url = os.environ["SIEM_API_URL"]
    api_key = os.environ["SIEM_API_KEY"]
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{api_url}/search",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "host": alert.host,
                "user": alert.user,
                "window_minutes": 30,
                "around": alert.received_at.isoformat(),
            },
        )
        resp.raise_for_status()
        data = resp.json()
    return "\n".join(data.get("lines", []))


def _mock_related_logs(alert: RawAlert) -> str:
    """Synthetic related log lines for local dev/demo/tests. Not real log data."""
    lines = [
        f"[mock-siem] host={alert.host or 'n/a'} auth event near {alert.received_at.isoformat()}",
        f"[mock-siem] process spawned on host={alert.host or 'n/a'} parent=explorer.exe child=powershell.exe -enc <base64>",
        f"[mock-siem] outbound connection from host={alert.host or 'n/a'} to {alert.dst_ip or 'n/a'}:443",
    ]
    return "\n".join(lines)
