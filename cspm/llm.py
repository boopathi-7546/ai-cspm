"""Thin, optional wrapper around the Anthropic API. Everything works without it."""
from __future__ import annotations

import os

from .config import LLM_MODEL


def get_client():
    """Return an Anthropic client, or None if no API key / SDK is available."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic
    except ImportError:
        return None
    return anthropic.Anthropic()


def complete(client, system: str, user: str, max_tokens: int = 1500) -> str:
    msg = client.messages.create(
        model=LLM_MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
