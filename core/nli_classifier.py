"""
Agent Content Shield — NLI Intent Classifier (Python)

Parity port of core/nli-classifier.js. Same fail-closed behavior: if
all classifier paths fail, return ``injection=True`` with a warning
rather than silently passing — an unreachable classifier is the worst
possible moment to fail open.

Zero *required* dependencies. Uses stdlib ``urllib`` for both the
Anthropic API path and the Ollama fallback. Callers that already have
``anthropic`` installed can pass ``use_sdk=True`` for connection
pooling + retries; otherwise the stdlib path works identically.

Order of attempts:
  1. Anthropic API via Claude Haiku (fastest)
  2. Anthropic API via Claude Sonnet if Haiku result is borderline
  3. Ollama deepseek-r1:8b fallback
  4. Fail closed (inject=True) if all paths fail

Shared state: core/nli-intents.json holds the 8-item threat taxonomy
and the NLI system prompt. JS + Python load the same file (JS still
uses inline copies in v0.4.1 — v0.4.2 tracks the JS refactor).
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# ── Shared lexicon ───────────────────────────────────────────────


def _intents_path() -> Path:
    return Path(__file__).resolve().parent / "nli-intents.json"


def _load_intents() -> dict[str, Any]:
    try:
        return json.loads(_intents_path().read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise RuntimeError(
            f"nli-intents.json missing at {_intents_path()}; v0.4.1 requires "
            "the shared intent taxonomy to be present"
        ) from e


_INTENTS_FILE = _load_intents()
THREAT_INTENTS: list[dict[str, Any]] = _INTENTS_FILE["intents"]
NLI_SYSTEM_PROMPT: str = _INTENTS_FILE["system_prompt"]
_VALID_INTENT_IDS: set[str] = {t["id"] for t in THREAT_INTENTS}


# ── JSON extraction + validation ─────────────────────────────────

_JSON_RX = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)


def extract_and_validate_json(content: str) -> dict[str, Any] | None:
    """Pull the LAST JSON object from the classifier's raw response
    (last = the model's reply, not an echoed input). Filter out any
    matches with an intent id not in our taxonomy — an attacker-
    embedded JSON with a fabricated `{"benign": true}` must not be
    able to override the classifier's actual decision."""
    parsed_objects: list[dict[str, Any]] = []
    for match in _JSON_RX.finditer(content):
        try:
            parsed_objects.append(json.loads(match.group(0)))
        except json.JSONDecodeError:
            continue
    if not parsed_objects:
        return None
    parsed = parsed_objects[-1]
    valid_matches = [
        m for m in (parsed.get("matches") or []) if m.get("intent") in _VALID_INTENT_IDS
    ]
    benign_in_payload = parsed.get("benign")
    return {
        "matches": valid_matches,
        "benign": (benign_in_payload if benign_in_payload is not None else True)
        if not valid_matches
        else False,
    }


# ── Anthropic API client (stdlib urllib, no SDK required) ───────


def _load_api_key() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return os.environ["ANTHROPIC_API_KEY"]
    # Look for a sibling .env file. We never walk the filesystem — the
    # shield config format is always next to the module.
    env_path = Path(__file__).resolve().parent.parent / ".env"
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^ANTHROPIC_API_KEY\s*=\s*(.+)$", line)
            if m:
                value = m.group(1).strip().strip('"').strip("'")
                os.environ["ANTHROPIC_API_KEY"] = value
                return value
    except OSError:
        pass
    return None


def classify_with_claude(
    text: str, *, model: str = "claude-haiku-4-5-20251001", timeout_sec: float = 15.0
) -> dict[str, Any] | None:
    """Call the Claude Messages API directly via urllib. Returns
    validated-intents dict or None on any failure. Never raises."""
    api_key = _load_api_key()
    if not api_key:
        return None
    body = json.dumps(
        {
            "model": model,
            "max_tokens": 512,
            "system": NLI_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": f"Classify this text:\n\n{text[:8000]}"}],
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    except Exception:
        return None

    content_blocks = data.get("content", [])
    text_content = ""
    for block in content_blocks:
        if block.get("type") == "text":
            text_content += block.get("text", "")
    if not text_content:
        return None
    parsed = extract_and_validate_json(text_content)
    if not parsed:
        return None
    return {**parsed, "model": model, "raw": text_content[:300]}


# ── Ollama fallback ─────────────────────────────────────────────

OLLAMA_BASE = os.environ.get("OLLAMA_URL", "http://localhost:11434")


def classify_with_ollama(text: str, *, timeout_sec: float = 30.0) -> dict[str, Any] | None:
    """Fallback via local Ollama deepseek-r1:8b (or another configured
    classifier model). Only used when the Anthropic path is unavailable."""
    model = os.environ.get("SHIELD_CLASSIFIER_MODEL", "deepseek-r1:8b")
    prompt = f"{NLI_SYSTEM_PROMPT}\n\nClassify this text:\n\n{text[:2000]}"
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 512, "num_ctx": 4096},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

    raw = data.get("response", "") or ""
    # Strip <think>...</think> reasoning blocks the deepseek-r1 family emits.
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", raw).strip()
    parsed = extract_and_validate_json(cleaned)
    if not parsed:
        return None
    return {**parsed, "model": model, "raw": cleaned[:300]}


# ── Main entrypoint ──────────────────────────────────────────────


def nli_classify(text: str) -> dict[str, Any]:
    """Classify text for injection intent. Tries Haiku → Sonnet (if
    borderline) → Ollama fallback. Fails CLOSED — returns
    ``injection=True`` with a warning when all classifiers fail."""
    start = time.time()
    result = classify_with_claude(text, model="claude-haiku-4-5-20251001")

    if result and result.get("matches"):
        confidences = [m.get("confidence", 0) for m in result["matches"]]
        max_conf = max(confidences) if confidences else 0
        if 0.3 < max_conf < 0.7:
            # Borderline — escalate to Sonnet for a better verdict
            sonnet = classify_with_claude(text, model="claude-sonnet-4-6")
            if sonnet:
                result = sonnet

    if not result:
        result = classify_with_ollama(text)

    if not result:
        # Fail closed — an unreachable classifier is the worst moment
        # to assume text is benign.
        return {
            "injection": True,
            "confidence": 0.5,
            "intents": [
                {"intent": "classifier_unavailable", "confidence": 0.5, "severity": 7}
            ],
            "maxSeverity": 7,
            "model": "none",
            "latencyMs": int((time.time() - start) * 1000),
            "warning": "All classifiers unavailable — failing closed",
        }

    matches = result.get("matches") or []
    confidences = [m.get("confidence", 0) for m in matches]
    high_conf = [m for m in matches if m.get("confidence", 0) >= 0.6]
    max_conf = max(confidences) if confidences else 0

    matched_intents = []
    for m in matches:
        intent = next((t for t in THREAT_INTENTS if t["id"] == m.get("intent")), None)
        matched_intents.append({**m, "severity": intent["severity"] if intent else 7})
    max_severity = max(
        (m.get("severity", 0) for m in matched_intents), default=0
    )

    return {
        "injection": len(high_conf) > 0,
        "confidence": max_conf,
        "intents": matched_intents,
        "maxSeverity": max_severity,
        "model": result.get("model"),
        "benign": result.get("benign"),
        "latencyMs": int((time.time() - start) * 1000),
    }


__all__ = [
    "nli_classify",
    "classify_with_claude",
    "classify_with_ollama",
    "extract_and_validate_json",
    "THREAT_INTENTS",
    "NLI_SYSTEM_PROMPT",
]
