"""Thin, optional wrapper around Anthropic and Google Gemini APIs. Everything works without it."""
from __future__ import annotations

import os
import time

from .config import LLM_MODEL, LLM_PROVIDER


def get_provider() -> str:
    """Return the active LLM provider ('anthropic' or 'gemini')."""
    return os.getenv("LLM_PROVIDER", "anthropic").strip().lower()


def get_client():
    """Return an Anthropic or Gemini client, or None if no API key / SDK is available."""
    provider = get_provider()
    if provider == "gemini":
        if not os.getenv("GEMINI_API_KEY"):
            return None
        try:
            from google import genai
        except ImportError:
            return None
        try:
            return genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        except Exception:
            return None

    if provider == "anthropic":
        if not os.getenv("ANTHROPIC_API_KEY"):
            return None
        try:
            import anthropic
        except ImportError:
            return None
        try:
            return anthropic.Anthropic()
        except Exception:
            return None

    return None


def _is_rate_limit(exc: Exception) -> bool:
    """Check if exception is a 429 / rate-limit / resource exhausted error."""
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    if code == 429:
        return True
    msg = str(exc).lower()
    return "429" in msg or "resource_exhausted" in msg or "rate limit" in msg


def complete(client, system: str, user: str, max_tokens: int = 1500) -> str:
    """Complete a prompt using client (Anthropic or Gemini).

    Works with both real SDK clients and test fakes.
    """
    provider = get_provider()
    # Detect provider by client attributes or active provider
    if hasattr(client, "models"):
        is_gemini = True
    elif hasattr(client, "messages"):
        is_gemini = False
    else:
        is_gemini = (provider == "gemini")

    if is_gemini:
        model = os.getenv("CTI_LLM_MODEL", "").strip()
        if not model:
            raise ValueError("CTI_LLM_MODEL must be set for Gemini (e.g. gemini-2.0-flash)")

        # Thinking tokens count toward max_output_tokens, so use at least 256 for checks and 4096 for extraction
        if max_tokens <= 256:
            gemini_tokens = max(max_tokens, 256)
        else:
            gemini_tokens = max(max_tokens, 4096)

        thinking_config = None
        if "flash" in model.lower():
            try:
                from google.genai import types as genai_types
                if hasattr(genai_types, "ThinkingConfig"):
                    if "3." in model or model.startswith("gemini-3") or "-3-" in model:
                        thinking_config = genai_types.ThinkingConfig(thinking_level="low")
                    else:
                        thinking_config = genai_types.ThinkingConfig(thinking_budget=0)
            except Exception:
                if "3." in model or model.startswith("gemini-3") or "-3-" in model:
                    thinking_config = {"thinking_level": "low"}
                else:
                    thinking_config = {"thinking_budget": 0}

        def _make_config(tc):
            try:
                from google.genai import types as genai_types
                config_kwargs = {
                    "system_instruction": system,
                    "max_output_tokens": gemini_tokens,
                }
                if tc is not None:
                    config_kwargs["thinking_config"] = tc
                return genai_types.GenerateContentConfig(**config_kwargs)
            except Exception:
                cfg = {
                    "system_instruction": system,
                    "max_output_tokens": gemini_tokens,
                }
                if tc is not None:
                    cfg["thinking_config"] = tc
                return cfg

        config = _make_config(thinking_config)

        retries = 2
        try:
            base_backoff = float(os.getenv("CSPM_RETRY_BACKOFF", "0.5"))
        except ValueError:
            base_backoff = 0.5

        for attempt in range(retries + 1):
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=user,
                    config=config,
                )
                if hasattr(response, "text"):
                    return response.text or ""
                if isinstance(response, str):
                    return response
                return str(response)
            except Exception as exc:
                # If thinking_config is unsupported by this specific model, retry without it
                if thinking_config is not None and ("thinking" in str(exc).lower() or "invalid_argument" in str(exc).lower()):
                    thinking_config = None
                    config = _make_config(None)
                    continue
                if attempt < retries and _is_rate_limit(exc):
                    time.sleep(base_backoff * (2 ** attempt))
                    continue
                raise

    # Anthropic path
    model = os.getenv("CTI_LLM_MODEL", "").strip() or LLM_MODEL or "claude-sonnet-5-5"
    msg = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
