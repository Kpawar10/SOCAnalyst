from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_redis: aioredis.Redis | None = None

DUPLICATE_WINDOW_SECONDS = 15 * 60  # alerts with the same fingerprint within 15 min are dupes


def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        _redis = aioredis.from_url(url, decode_responses=True)
    return _redis


async def cache_get_json(key: str) -> Optional[dict]:
    try:
        r = get_redis()
        raw = await r.get(key)
        return json.loads(raw) if raw else None
    except Exception as e:  # noqa: BLE001 - cache is best-effort, never block the pipeline
        logger.warning("Redis GET failed for key=%s: %s", key, e)
        return None


async def cache_set_json(key: str, value: dict, ttl_seconds: int) -> None:
    try:
        r = get_redis()
        await r.set(key, json.dumps(value), ex=ttl_seconds)
    except Exception as e:  # noqa: BLE001
        logger.warning("Redis SET failed for key=%s: %s", key, e)


async def is_recent_duplicate(fingerprint: str) -> Optional[str]:
    """Returns the alert_id this fingerprint was first seen with, if any, within the dedupe window."""
    key = f"alert_fp:{fingerprint}"
    try:
        r = get_redis()
        return await r.get(key)
    except Exception as e:  # noqa: BLE001
        logger.warning("Redis dedupe check failed for fingerprint=%s: %s", fingerprint, e)
        return None


async def remember_alert_fingerprint(fingerprint: str, alert_id: str) -> None:
    key = f"alert_fp:{fingerprint}"
    try:
        r = get_redis()
        await r.set(key, alert_id, ex=DUPLICATE_WINDOW_SECONDS, nx=True)
    except Exception as e:  # noqa: BLE001
        logger.warning("Redis dedupe write failed for fingerprint=%s: %s", fingerprint, e)
