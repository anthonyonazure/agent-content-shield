"""
Agent Content Shield — Canary Token System (Python)

Parity with core/canary.js. See that file for the design rationale.

Behavior:
  - Persistent 128-bit canary stored at ~/.shield/canary.json
  - Weekly rotation with overlap window (current + previous both valid)
  - Structured phrase matching (full "shield-<id>" string, not bare hex)
    so commit hashes, UUIDs, color codes can't false-positive
  - Canary gets PLANTED by embedding ``get_canary_phrase()`` output in
    shield-generated warning banners inside the agent's context. An
    attacker that exfiltrates the context window will carry the canary
    with it.

The JS and Python versions read/write the SAME canary file. An agent
running a hybrid JS-hook + Python-middleware stack will share one
canary identity, which is what you want — exfiltration detection
shouldn't depend on which language layer intercepts the leak.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any


def _canary_dir() -> Path:
    """Resolve the canary storage directory at call time so tests can
    override via the ``SHIELD_CANARY_DIR`` environment variable. In
    production the default (``~/.shield``) matches what the JS module
    uses so both languages share one canary identity."""
    override = os.environ.get("SHIELD_CANARY_DIR")
    if override:
        return Path(override)
    return Path.home() / ".shield"


def _canary_file() -> Path:
    return _canary_dir() / "canary.json"


ROTATION_MS = 7 * 24 * 60 * 60 * 1000  # 1 week


def generate_canary_id() -> str:
    """128-bit random identifier, hex-encoded. Matches the JS impl's
    ``crypto.randomBytes(16).toString('hex')`` output shape."""
    return secrets.token_hex(16)


def _now_ms() -> int:
    return int(time.time() * 1000)


def load_or_create_canary() -> dict[str, Any]:
    """Load existing canary, rotating if older than the rotation window.
    On the first run (or on any read/parse failure) generate a fresh
    canary and persist it. Failures to persist are intentionally
    swallowed — a canary-less scanner is still useful, and the whole
    module runs on untrusted filesystems where throwing would turn a
    defense layer into a crash vector."""
    cf = _canary_file()
    try:
        if cf.exists():
            data = json.loads(cf.read_text(encoding="utf-8"))
            age = _now_ms() - int(data.get("createdAt", 0))
            if age > ROTATION_MS:
                new_canary = {
                    "id": generate_canary_id(),
                    "previousId": data.get("id"),
                    "createdAt": _now_ms(),
                }
                _persist(new_canary)
                return new_canary
            return data
    except Exception:
        # Fall through to first-run creation.
        pass

    canary: dict[str, Any] = {
        "id": generate_canary_id(),
        "previousId": None,
        "createdAt": _now_ms(),
    }
    _persist(canary)
    return canary


def _persist(canary: dict[str, Any]) -> None:
    try:
        _canary_dir().mkdir(parents=True, exist_ok=True)
        _canary_file().write_text(
            json.dumps(canary, indent=2), encoding="utf-8"
        )
    except Exception as e:
        # Never crash on persistence — stderr the failure and continue.
        # An in-memory canary still catches attacks within the process
        # lifetime; it just won't survive a restart. Catch Exception
        # (not just OSError) because pathlib can raise RuntimeError on
        # some Python builds when home() can't resolve.
        import sys

        sys.stderr.write(f"shield: canary persist error: {type(e).__name__}: {e}\n")


def _refresh() -> None:
    """Re-read canary state from disk and rebuild module-level globals.
    Used when the canary file has rotated out-of-band or when tests
    change the storage directory mid-session."""
    global _CANARY_DATA, CANARY_ID, CANARY_PHRASE, _CANARY_PATTERNS
    _CANARY_DATA = load_or_create_canary()
    CANARY_ID = _CANARY_DATA["id"]
    CANARY_PHRASE = f"[ref:shield-{CANARY_ID}]"
    _CANARY_PATTERNS = [re.compile(rf"shield-{CANARY_ID}", re.I)]
    if _CANARY_DATA.get("previousId"):
        _CANARY_PATTERNS.append(
            re.compile(rf"shield-{_CANARY_DATA['previousId']}", re.I)
        )


_CANARY_DATA: dict[str, Any] = load_or_create_canary()
CANARY_ID: str = _CANARY_DATA["id"]
CANARY_PHRASE: str = f"[ref:shield-{CANARY_ID}]"

_CANARY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(rf"shield-{CANARY_ID}", re.I),
]
if _CANARY_DATA.get("previousId"):
    _CANARY_PATTERNS.append(re.compile(rf"shield-{_CANARY_DATA['previousId']}", re.I))


def check_for_canary(text: str) -> dict[str, Any]:
    """Check if text contains a canary token (current or previous
    rotation). Returns ``{detected, canaryId, severity?, reason?}``.

    The canaryId field is always redacted in the response — we never
    leak the actual id in a value that could echo back into prompts or
    logs. Shield consumers get a boolean signal and a severity; the
    id stays on disk."""
    if not text or len(text) < 20:
        return {"detected": False, "canaryId": None}
    for rx in _CANARY_PATTERNS:
        if rx.search(text):
            return {
                "detected": True,
                "canaryId": "[REDACTED]",
                "severity": 10,
                "reason": (
                    "Content contains shield canary token — "
                    "confirmed targeted exfiltration"
                ),
            }
    return {"detected": False, "canaryId": None}


def get_canary_phrase() -> str:
    """The phrase to embed in shield-generated warning banners. That's
    how the canary gets armed — it only works as a tripwire if it's
    actually planted in content the agent will see."""
    return CANARY_PHRASE


__all__ = [
    "check_for_canary",
    "get_canary_phrase",
    "generate_canary_id",
    "load_or_create_canary",
    "_refresh",
    "CANARY_ID",
    "CANARY_PHRASE",
    "ROTATION_MS",
]
