from __future__ import annotations

import hashlib
import logging
import os

import httpx

from src.cache.redis_cache import cache_get_json, cache_set_json
from src.models.schemas import ThreatIntelHit

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 60 * 60  # threat intel is cached for an hour


def _use_mock() -> bool:
    return os.environ.get("USE_MOCK_THREAT_INTEL", "true").lower() == "true"


async def lookup_indicators(indicators: list[str]) -> list[ThreatIntelHit]:
    """Look up a batch of IPs/hostnames/hashes against threat intel, Redis-cached."""
    hits: list[ThreatIntelHit] = []
    for indicator in indicators:
        cache_key = f"threat_intel:{indicator}"
        cached = await cache_get_json(cache_key)
        if cached is not None:
            hits.append(ThreatIntelHit(**cached))
            continue

        hit = await _lookup_mock(indicator) if _use_mock() else await _lookup_real(indicator)
        await cache_set_json(cache_key, hit.model_dump(mode="json"), ttl_seconds=CACHE_TTL_SECONDS)
        hits.append(hit)
    return hits


async def _lookup_mock(indicator: str) -> ThreatIntelHit:
    """
    Deterministic mock so demos/tests are reproducible: indicators whose hash
    is even are "malicious", odd are "clean". Real deployments swap this for
    a call to VirusTotal / AbuseIPDB / a commercial feed.
    """
    digest = int(hashlib.sha256(indicator.encode()).hexdigest(), 16)
    malicious = digest % 5 == 0  # ~20% of synthetic indicators come back "malicious"
    return ThreatIntelHit(
        indicator=indicator,
        indicator_type=_guess_indicator_type(indicator),
        malicious=malicious,
        confidence=0.9 if malicious else 0.1,
        source="mock_threat_intel",
        tags=["known_c2", "botnet"] if malicious else [],
    )


async def _lookup_real(indicator: str) -> ThreatIntelHit:
    api_key = os.environ["THREAT_INTEL_API_KEY"]
    base_url = os.environ.get("THREAT_INTEL_API_URL", "https://api.threat-intel.example/v1/lookup")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            base_url, params={"indicator": indicator}, headers={"Authorization": f"Bearer {api_key}"}
        )
        resp.raise_for_status()
        data = resp.json()
    return ThreatIntelHit(
        indicator=indicator,
        indicator_type=_guess_indicator_type(indicator),
        malicious=data.get("malicious", False),
        confidence=data.get("confidence", 0.5),
        source=data.get("source", "real_threat_intel"),
        tags=data.get("tags", []),
    )


def _guess_indicator_type(indicator: str) -> str:
    if indicator.count(".") == 3 and all(part.isdigit() for part in indicator.split(".")):
        return "ip"
    if len(indicator) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in indicator):
        return "hash"
    return "domain_or_host"
