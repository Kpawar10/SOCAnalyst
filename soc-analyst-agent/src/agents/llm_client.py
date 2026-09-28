from __future__ import annotations

import json
import logging
import os
import re

from anthropic import Anthropic
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

_client: Anthropic | None = None


def get_client() -> Anthropic:
    global _client
    if _client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Copy .env.example to .env and fill it in."
            )
        _client = Anthropic(api_key=api_key)
    return _client


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    return text


class LLMJSONError(Exception):
    pass


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=8))
def call_json(system_prompt: str, user_prompt: str, max_tokens: int = 1200) -> dict:
    """Call Claude and parse a strict JSON object out of the response.

    Retries on transient API errors and on malformed JSON (the retry re-sends
    the same prompt; Claude is generally reliable at JSON-only output when the
    system prompt is explicit about it, but this adds resilience).
    """
    client = get_client()
    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )

    text_parts = [block.text for block in response.content if getattr(block, "type", None) == "text"]
    raw_text = "".join(text_parts)
    cleaned = _strip_code_fences(raw_text)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        logger.warning("LLM returned non-JSON output, retrying. Raw: %r", raw_text[:500])
        raise LLMJSONError(f"Could not parse JSON from model output: {e}") from e
