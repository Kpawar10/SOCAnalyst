"""Run once to set up the pgvector extension and the incidents table.

Usage: python scripts/init_db.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

from src.memory.vector_store import EMBEDDING_DIM

load_dotenv()


def main() -> None:
    db_url = os.environ["DATABASE_URL"]
    engine = create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    summary TEXT NOT NULL,
                    category TEXT NOT NULL,
                    resolution TEXT NOT NULL,
                    embedding VECTOR({EMBEDDING_DIM}) NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS incidents_embedding_idx
                ON incidents USING ivfflat (embedding vector_cosine_ops)
                WITH (lists = 100)
                """
            )
        )
    print("Database initialized: pgvector extension + incidents table ready.")


if __name__ == "__main__":
    main()
