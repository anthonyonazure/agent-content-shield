"""
Agent Content Shield — Behavioral Markov Anomaly Engine (Python)

Parity with core/behavioral-engine.js. See that file for design notes.

Models agent behavior as a Markov chain over tool-call sequences. Each
action is abstracted to ``CATEGORY:SENSITIVITY`` (e.g. ``FETCH:high``);
the model learns transition probabilities from benign sessions, and
the guard flags transitions that are surprising relative to the
learned baseline.

Shared state on disk:
  data/behavioral-model.json   transition probabilities + threshold
  data/sessions.jsonl          per-action append log

Both the JS engine and this Python port read/write these files, so an
agent running either layer sees the same history. The model file shape
is deliberately simple (`{transitions: {state: {next: count}}}`) to
keep cross-language debugging trivial.
"""

from __future__ import annotations

import json
import math
import os
import random
import re
import sys
import time
from pathlib import Path
from typing import Any


def _data_dir() -> Path:
    """Resolve data dir at call time so tests can override via
    ``SHIELD_DATA_DIR``. Matches the JS module's layout otherwise."""
    override = os.environ.get("SHIELD_DATA_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "data"


def _model_path() -> Path:
    return _data_dir() / "behavioral-model.json"


def _sessions_path() -> Path:
    return _data_dir() / "sessions.jsonl"


SESSION_TIMEOUT_MS = 30 * 60 * 1000  # 30 minutes

# ── Tool Abstraction ───────────────────────────────────────────────

TOOL_CATEGORIES: dict[str, str] = {
    "Read": "READ",
    "Glob": "READ",
    "Grep": "READ",
    "Write": "WRITE",
    "Edit": "WRITE",
    "WebFetch": "FETCH",
    "Bash": "EXEC",
}


def abstract_tool(tool: str | None) -> str:
    if not tool:
        return "OTHER"
    if tool in TOOL_CATEGORIES:
        return TOOL_CATEGORIES[tool]
    lower = tool.lower()
    if (
        lower.startswith("mem")
        or lower.startswith("knowledge")
        or "memory" in lower
    ):
        return "MEMORY"
    return "OTHER"


# ── Sensitivity Classification ─────────────────────────────────────

_HIGH_SENSITIVITY = [
    re.compile(r"\.env$", re.I),
    re.compile(r"\.ssh[/\\]", re.I),
    re.compile(r"credentials", re.I),
    re.compile(r"secrets?\b", re.I),
    re.compile(r"tokens?\.(json|yml|yaml)$", re.I),
    re.compile(r"settings\.json$", re.I),
    re.compile(r"\.gnupg[/\\]", re.I),
    re.compile(r"\.aws[/\\]credentials$", re.I),
    re.compile(r"\.mcp\.json$", re.I),
    re.compile(r"\.claude[/\\]settings\.json$", re.I),
    re.compile(r"id_rsa", re.I),
    re.compile(r"id_ed25519", re.I),
]

_MEDIUM_SENSITIVITY = [
    re.compile(r"\.bashrc$", re.I),
    re.compile(r"\.bash_profile$", re.I),
    re.compile(r"\.profile$", re.I),
    re.compile(r"\.zshrc$", re.I),
    re.compile(r"\.gitconfig$", re.I),
    re.compile(r"\.npmrc$", re.I),
    re.compile(r"config[/\\]", re.I),
    re.compile(r"\.yaml$", re.I),
    re.compile(r"\.yml$", re.I),
    re.compile(r"\.toml$", re.I),
    re.compile(r"crontab", re.I),
]


def classify_sensitivity(tool_input: dict[str, Any] | None) -> str:
    if not tool_input:
        return "low"
    target = (
        tool_input.get("file_path")
        or tool_input.get("command")
        or tool_input.get("url")
        or ""
    )
    normalized = str(target).replace("\\", "/")
    if any(rx.search(normalized) for rx in _HIGH_SENSITIVITY):
        return "high"
    if any(rx.search(normalized) for rx in _MEDIUM_SENSITIVITY):
        return "medium"
    return "low"


# ── State Encoding ─────────────────────────────────────────────────


def encode_state(history: list[dict[str, Any]] | None, n: int = 3) -> str:
    if not history:
        return "__START__"
    recent = history[-n:]
    return "->".join(f"{a['category']}:{a['sensitivity']}" for a in recent)


# ── Model ──────────────────────────────────────────────────────────

_model: dict[str, Any] | None = None


def _ensure_data_dir() -> None:
    try:
        _data_dir().mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def load_model() -> dict[str, Any]:
    global _model
    if _model is not None:
        return _model
    try:
        _model = json.loads(_model_path().read_text(encoding="utf-8"))
    except Exception:
        _model = {"transitions": {}, "totalSessions": 0}
    return _model


def save_model(model: dict[str, Any]) -> None:
    global _model
    _ensure_data_dir()
    _model_path().write_text(json.dumps(model, indent=2), encoding="utf-8")
    _model = model


def _reset_model_cache() -> None:
    """Drop the in-memory model cache. Primarily for tests that swap
    the data dir between runs."""
    global _model
    _model = None


def learn(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    """Learn transition probabilities from session objects."""
    model: dict[str, Any] = {"transitions": {}, "totalSessions": len(sessions)}
    for session in sessions:
        actions = session.get("actions", [])
        for i in range(len(actions)):
            history = actions[:i]
            state = encode_state(history)
            next_key = f"{actions[i]['category']}:{actions[i]['sensitivity']}"
            model["transitions"].setdefault(state, {})
            model["transitions"][state][next_key] = (
                model["transitions"][state].get(next_key, 0) + 1
            )
    save_model(model)
    return model


def score_action(
    session_actions: list[dict[str, Any]],
    next_tool: str,
    next_input: dict[str, Any] | None,
) -> float:
    """Score surprise of next action (0..1). Uses Laplace smoothing."""
    model = load_model()
    category = abstract_tool(next_tool)
    sensitivity = classify_sensitivity(next_input)
    state = encode_state(session_actions)
    next_key = f"{category}:{sensitivity}"

    dist = model["transitions"].get(state)
    if not dist:
        return 0.6  # novel state

    total = sum(dist.values())
    vocab_size = len(model["transitions"]) or 1
    count = dist.get(next_key, 0)
    probability = (count + 1) / (total + vocab_size)
    surprise = -math.log2(probability)
    max_surprise = math.log2(total + vocab_size) if (total + vocab_size) > 1 else 1
    return min(surprise / (max_surprise or 1), 1.0)


def calibrate_threshold(
    sessions: list[dict[str, Any]], fp_budget: float = 0.001
) -> float:
    """Calibrate threshold from benign data. fp_budget = target FP rate."""
    learn(sessions)
    scores: list[float] = []
    for session in sessions:
        actions = session.get("actions", [])
        for i in range(len(actions)):
            history = actions[:i]
            s = score_action(
                history,
                actions[i].get("tool") or actions[i].get("category"),
                actions[i].get("input") or {},
            )
            scores.append(s)
    if not scores:
        return 0.8
    scores.sort()
    idx = min(int(len(scores) * (1 - fp_budget)), len(scores) - 1)
    threshold = max(scores[idx], 0.5)  # floor at 0.5
    model = load_model()
    model["threshold"] = threshold
    save_model(model)
    return threshold


# ── Session Management ────────────────────────────────────────────

_current_session: dict[str, Any] | None = None


def get_or_create_session() -> dict[str, Any]:
    global _current_session
    now = int(time.time() * 1000)
    if (
        _current_session is not None
        and now - _current_session["lastActivity"] < SESSION_TIMEOUT_MS
    ):
        _current_session["lastActivity"] = now
        return _current_session
    _current_session = {
        "id": f"ses_{now}_{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))}",
        "startedAt": now,
        "lastActivity": now,
        "actions": [],
        "cumulativeRisk": 0,
    }
    return _current_session


def _reset_current_session() -> None:
    """Drop the singleton session. Primarily for tests."""
    global _current_session
    _current_session = None


def append_action(session_id: str, action: dict[str, Any]) -> dict[str, Any]:
    global _current_session
    _ensure_data_dir()
    session = (
        _current_session
        if _current_session is not None and _current_session["id"] == session_id
        else get_or_create_session()
    )
    entry = {
        "tool": action.get("tool"),
        "category": abstract_tool(action.get("tool")),
        "sensitivity": classify_sensitivity(action.get("input") or {}),
        "timestamp": int(time.time() * 1000),
    }
    session["actions"].append(entry)
    session["lastActivity"] = entry["timestamp"]
    try:
        with _sessions_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps({"sessionId": session["id"], **entry}) + "\n")
    except Exception as e:
        sys.stderr.write(f"shield-behavioral: session log error: {e}\n")
    return entry


# ── Cumulative Session Risk ──────────────────────────────────────


def compute_session_risk(session: dict[str, Any] | None) -> float:
    if not session or not session.get("actions"):
        return 0.0
    actions = session["actions"]
    high_count = sum(1 for a in actions if a.get("sensitivity") == "high")
    fetch_then_write = any(
        actions[i - 1].get("category") == "FETCH"
        and actions[i].get("category") == "WRITE"
        for i in range(1, len(actions))
    )
    exec_then_write = any(
        actions[i - 1].get("category") == "EXEC"
        and actions[i].get("category") == "WRITE"
        and actions[i].get("sensitivity") == "high"
        for i in range(1, len(actions))
    )
    risk = high_count * 0.15
    if fetch_then_write:
        risk += 0.3
    if exec_then_write:
        risk += 0.4
    return min(risk, 1.0)


# ── Integration Hook ─────────────────────────────────────────────


def behavioral_guard(
    tool_name: str, tool_input: dict[str, Any] | None
) -> dict[str, Any]:
    session = get_or_create_session()
    model = load_model()
    threshold = model.get("threshold", 0.75)
    category = abstract_tool(tool_name)
    sensitivity = classify_sensitivity(tool_input)
    surprise = score_action(session["actions"], tool_name, tool_input)
    session_risk = compute_session_risk(session)
    anomalous = surprise > threshold

    explanation: str | None = None
    if anomalous:
        state = encode_state(session["actions"])
        explanation = (
            f"Unexpected {category}:{sensitivity} after [{state}] "
            f"(surprise={surprise:.3f}, threshold={threshold:.3f})"
        )
        if sensitivity == "high":
            explanation += " | HIGH-SENSITIVITY TARGET"

    return {
        "anomalous": anomalous,
        "surprise": surprise,
        "explanation": explanation,
        "sessionRisk": session_risk,
    }


__all__ = [
    # Core engine
    "encode_state",
    "abstract_tool",
    "classify_sensitivity",
    "score_action",
    "learn",
    "calibrate_threshold",
    # Session management
    "get_or_create_session",
    "append_action",
    # Integration
    "behavioral_guard",
    # Risk computation
    "compute_session_risk",
    # Persistence (exposed for testing / introspection)
    "load_model",
    "save_model",
    "_reset_model_cache",
    "_reset_current_session",
    "TOOL_CATEGORIES",
    "SESSION_TIMEOUT_MS",
]
