"""Tiny .env loader (no extra dependency). Values are never printed or logged."""
from __future__ import annotations

import os
import re
from pathlib import Path

_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_env_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not _KEY.match(key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        if value:  # an empty `KEY=` placeholder must not count as configured
            out[key] = value
    return out


def load_dotenv(path: Path | str | None = None, override: bool = False) -> list[str]:
    """Load KEY=VALUE pairs into os.environ. Real environment variables win unless override=True.
    Returns the names that were set (never the values)."""
    env_path = Path(path) if path else Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return []
    set_names = []
    for key, value in parse_env_text(env_path.read_text(encoding="utf-8-sig")).items():
        if override or key not in os.environ:
            os.environ[key] = value
            set_names.append(key)
    return set_names
