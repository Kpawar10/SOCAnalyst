"""
Long-term memory of past incidents, backed by Postgres + pgvector.

Two things live here:
1. `search_similar_incidents` -- used by the Investigation Agent to pull
   "have we seen something like this before, and how did it resolve" context.
2. `write_closed_incident` -- called once a human closes out an approved (or
   rejected) remediation, so the system accumulates institutional memory over
   time instead of re-litigating the same incident type from scratch.

Embeddings: for simplicity/cost this uses a lightweight local hashing
embedding by default (see `embed_text`) so the project runs without an
embeddings API key. Swap `embed_text` for a real embeddings call
(e.g. `voyage-2` or an Anthropic-compatible embedding model) in production --
the interface (returns list[float] of length EMBEDDING_DIM) stays the same.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional

import numpy as np
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from src.models.schemas import AlertCategory, SimilarIncident

logger = logging.getLogger(__name__)

EMBEDDING_DIM = 256

_engine: Engine | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        db_url = os.environ.get("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL is not set.")
        _engine = create_engine(db_url, pool_pre_ping=True)
    return _engine


def embed_text(text_input: str) -> list[float]:
    """
    Deterministic, dependency-free embedding stand-in.

    Hashes overlapping character n-grams into a fixed-size bag-of-features
    vector and L2-normalizes it. This gives cosine similarity that correlates
    with textual overlap -- good enough for a demo/dev environment without an
    embeddings API key. Replace with a real embedding model call for production.
    """
    vec = np.zeros(EMBEDDING_DIM, dtype=np.float32)
    normalized = text_input.lower()
    n = 4
    grams = [normalized[i : i + n] for i in range(max(len(normalized) - n + 1, 1))]
    for gram in grams:
        h = int(hashlib.md5(gram.encode("utf-8")).hexdigest(), 16)
        vec[h % EMBEDDING_DIM] += 1.0
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec.tolist()


async def search_similar_incidents(
    query_text: str, category: AlertCategory, top_k: int = 3
) -> list[SimilarIncident]:
    embedding = embed_text(query_text)
    engine = get_engine()
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT incident_id, summary, category, resolution,
                           1 - (embedding <=> CAST(:embedding AS vector)) AS similarity
                    FROM incidents
                    ORDER BY embedding <=> CAST(:embedding AS vector)
                    LIMIT :top_k
                    """
                ),
                {"embedding": embedding, "top_k": top_k},
            ).fetchall()
    except Exception as e:  # noqa: BLE001 - degrade gracefully if DB/table isn't ready
        logger.warning("Vector memory search failed (%s); continuing without historical context.", e)
        return []

    return [
        SimilarIncident(
            incident_id=r.incident_id,
            summary=r.summary,
            category=AlertCategory(r.category),
            resolution=r.resolution,
            similarity_score=float(r.similarity),
        )
        for r in rows
    ]


async def write_closed_incident(
    incident_id: str, summary: str, category: AlertCategory, resolution: str
) -> None:
    embedding = embed_text(summary)
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO incidents (incident_id, summary, category, resolution, embedding)
                VALUES (:incident_id, :summary, :category, :resolution, CAST(:embedding AS vector))
                ON CONFLICT (incident_id) DO UPDATE
                SET summary = EXCLUDED.summary,
                    category = EXCLUDED.category,
                    resolution = EXCLUDED.resolution,
                    embedding = EXCLUDED.embedding
                """
            ),
            {
                "incident_id": incident_id,
                "summary": summary,
                "category": category.value,
                "resolution": resolution,
                "embedding": embedding,
            },
        )
    logger.info("Wrote closed incident %s to long-term memory", incident_id)
