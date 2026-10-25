"""Thin, optional wrapper around Anthropic and Google Gemini APIs. Everything works without it."""
from __future__ import annotations

import os
import re
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


def extract_status_code(exc: Exception) -> int | None:
    """Extract HTTP status code from an exception if available."""
    for attr in ("status_code", "code", "http_status"):
        val = getattr(exc, attr, None)
        if isinstance(val, int) and 100 <= val <= 599:
            return val
        if isinstance(val, str) and val.isdigit() and 100 <= int(val) <= 599:
            return int(val)
    resp = getattr(exc, "response", None)
    if resp is not None:
        for attr in ("status_code", "status"):
            val = getattr(resp, attr, None)
            if isinstance(val, int) and 100 <= val <= 599:
                return val
            if isinstance(val, str) and val.isdigit() and 100 <= int(val) <= 599:
                return int(val)
    m = re.search(r"\b([1-5]\d{2})\b", str(exc))
    if m:
        return int(m.group(1))
    return None


def sanitize_llm_message(msg: str, max_len: int = 120) -> str:
    """Sanitize error message: redact potential API keys and truncate to max_len."""
    for env_var in ("GEMINI_API_KEY", "ANTHROPIC_API_KEY"):
        val = os.getenv(env_var, "").strip()
        if val and len(val) >= 6:
            msg = msg.replace(val, "[REDACTED]")
    msg = re.sub(r"\bAIza[0-9A-Za-z-_]{20,}\b", "[REDACTED]", msg)
    msg = re.sub(r"\bsk-ant-[0-9A-Za-z-_]{20,}\b", "[REDACTED]", msg)
    msg = re.sub(r"\bAQ\.[0-9A-Za-z-_]{20,}\b", "[REDACTED]", msg)
    msg = " ".join(msg.split()).strip()
    return msg[:max_len]


def format_llm_error(exc: Exception) -> str:
    """Format LLM failure details: exception type, HTTP status code (if available), truncated message."""
    exc_type = type(exc).__name__
    status_code = extract_status_code(exc)
    msg = sanitize_llm_message(str(exc), 120)

    header = f"{exc_type} ({status_code})" if status_code is not None else exc_type
    if msg:
        return f"llm failed: {header}: {msg}"
    return f"llm failed: {header}"


def _get_llm_delay() -> float:
    """Return configured delay in seconds between LLM requests (default 0)."""
    try:
        return float(os.getenv("CTI_LLM_DELAY_SECONDS", "0") or 0)
    except (ValueError, TypeError):
        return 0.0


def _apply_llm_delay() -> None:
    delay = _get_llm_delay()
    if delay > 0:
        time.sleep(delay)


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
    try:
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
                        sleep_time = max(base_backoff * (2 ** attempt), _get_llm_delay())
                        time.sleep(sleep_time)
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
    finally:
        _apply_llm_delay()

