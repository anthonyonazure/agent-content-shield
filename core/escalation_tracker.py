"""
Agent Content Shield — Multi-Turn Escalation Tracker (Python)

Parity with core/escalation-tracker.js. See that file for design notes.
Zero external dependencies (stdlib only).
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any

ESCALATION_SESSION_TTL_MS = 60 * 60 * 1000  # 1 hour

# ── Feature patterns ─────────────────────────────────────────────

_IMPERATIVE_RX = re.compile(
    r"\b(do|don'?t|you must|please|make sure|always|never|execute|run|write|"
    r"create|delete|ignore|forget|override|bypass|switch|become|act|pretend|"
    r"roleplay)\b",
    re.I,
)

PERSONA_RX: list[re.Pattern[str]] = [
    re.compile(
        r"\byou\s+are\s+(now\s+)?(?!a\s+(assistant|helpful))[a-z][a-z\s]{1,40}\b",
        re.I,
    ),
    re.compile(r"\bact\s+as\s+(if\s+you\s+were\s+)?[a-z]", re.I),
    re.compile(r"\bpretend\s+(to\s+be|you('?re|\s+are))\s+[a-z]", re.I),
    re.compile(r"\broleplay\s+(as\s+)?[a-z]", re.I),
    re.compile(r"\bfrom\s+now\s+on,?\s+you\b", re.I),
]

ANCHOR_RX: list[re.Pattern[str]] = [
    re.compile(r"\bas\s+we\s+(discussed|agreed|talked\s+about|established)\b", re.I),
    re.compile(r"\byou\s+(agreed|promised|confirmed|said|told\s+me)\s+earlier\b", re.I),
    re.compile(r"\bremember\s+(when\s+)?(we|you)\b", re.I),
    re.compile(r"\bearlier\s+you\s+(said|promised|agreed|confirmed)\b", re.I),
    re.compile(r"\blike\s+(we\s+)?(discussed|established)\b", re.I),
]

SYSTEM_PROMPT_PROBE_RX: list[re.Pattern[str]] = [
    re.compile(r"\bsystem\s+prompt\b", re.I),
    re.compile(r"\binitial\s+(prompt|instructions?)\b", re.I),
    re.compile(r"\babove\s+this\s+line\b", re.I),
    re.compile(r"\bdeveloper\s+(prompt|message)\b", re.I),
    re.compile(r"\byour\s+(original|first|initial)\s+instructions?\b", re.I),
    re.compile(r"\bshow\s+(me\s+)?your\s+(prompt|instructions|rules)\b", re.I),
]

HIDDEN_ENCODING_RX: list[re.Pattern[str]] = [
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    re.compile(r"(%[0-9a-f]{2}){6,}", re.I),
    re.compile(r"\b(0x)?[0-9a-f]{40,}\b", re.I),
]


def _count_regex_hits(text: str, patterns: list[re.Pattern[str]]) -> int:
    total = 0
    for rx in patterns:
        m = rx.findall(text)
        total += len(m)
    return total


# ── Feature extraction ──────────────────────────────────────────


@dataclass
class TurnFeatures:
    instruction_density: float = 0.0
    persona_references: int = 0
    anchor_references: int = 0
    system_prompt_mentions: int = 0
    hidden_encoding_hits: int = 0
    word_count: int = 0


def extract_features(text: str) -> TurnFeatures:
    if not text:
        return TurnFeatures()
    words = [w for w in text.split() if w]
    wc = len(words)
    imperative_hits = len(_IMPERATIVE_RX.findall(text))
    return TurnFeatures(
        instruction_density=(imperative_hits / wc) if wc else 0.0,
        persona_references=_count_regex_hits(text, PERSONA_RX),
        anchor_references=_count_regex_hits(text, ANCHOR_RX),
        system_prompt_mentions=_count_regex_hits(text, SYSTEM_PROMPT_PROBE_RX),
        hidden_encoding_hits=_count_regex_hits(text, HIDDEN_ENCODING_RX),
        word_count=wc,
    )


# ── Slope / escalation ──────────────────────────────────────────


def slope(values: list[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    x_mean = (n - 1) / 2
    y_mean = sum(values) / n
    num = 0.0
    den = 0.0
    for i, v in enumerate(values):
        num += (i - x_mean) * (v - y_mean)
        den += (i - x_mean) ** 2
    return 0.0 if den == 0 else num / den


FEATURE_WEIGHTS: dict[str, float] = {
    "instruction_density": 0.15,
    "persona_references": 0.25,
    "anchor_references": 0.25,
    "system_prompt_mentions": 0.25,
    "hidden_encoding_hits": 0.10,
}

SLOPE_REFERENCE: dict[str, float] = {
    "instruction_density": 0.03,
    "persona_references": 0.5,
    "anchor_references": 0.5,
    "system_prompt_mentions": 0.5,
    "hidden_encoding_hits": 0.5,
}


@dataclass
class Escalation:
    score: float = 0.0
    slopes: dict[str, float] = field(default_factory=dict)
    rising: list[str] = field(default_factory=list)


def _feature_value(f: TurnFeatures, name: str) -> float:
    return float(getattr(f, name))


def escalation_from_turns(turns: list[TurnFeatures]) -> Escalation:
    if len(turns) < 2:
        return Escalation()
    slopes: dict[str, float] = {}
    rising: list[str] = []
    score = 0.0
    for feat in FEATURE_WEIGHTS:
        series = [_feature_value(t, feat) for t in turns]
        s = slope(series)
        slopes[feat] = s
        if s > 0:
            normalized = min(s / SLOPE_REFERENCE[feat], 1.0)
            score += normalized * FEATURE_WEIGHTS[feat]
            if normalized > 0.4:
                rising.append(feat)
    return Escalation(score=min(score, 1.0), slopes=slopes, rising=rising)


# ── Session store ──────────────────────────────────────────────

_sessions: dict[str, dict[str, Any]] = {}


def _gc_stale(now_ms: int | None = None) -> None:
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    for sid in list(_sessions.keys()):
        if now - _sessions[sid]["last_activity"] > ESCALATION_SESSION_TTL_MS:
            del _sessions[sid]


@dataclass
class TurnResult:
    session_id: str
    turn_count: int
    features: TurnFeatures
    escalation: Escalation
    anomalous: bool


def record_turn(
    session_id: str,
    text: str,
    *,
    window_size: int = 5,
    threshold: float = 0.5,
) -> TurnResult:
    window_size = max(2, min(20, window_size))
    _gc_stale()
    now = int(time.time() * 1000)
    features = extract_features(text)

    session = _sessions.get(session_id)
    if session is None:
        session = {"turns": [], "last_activity": now}
        _sessions[session_id] = session

    session["turns"].append(
        {
            "ts": now,
            "features": features,
            "hash": hashlib.sha1((text or "").encode()).hexdigest()[:16],
        }
    )
    if len(session["turns"]) > window_size:
        session["turns"] = session["turns"][-window_size:]
    session["last_activity"] = now

    esc = escalation_from_turns([t["features"] for t in session["turns"]])
    return TurnResult(
        session_id=session_id,
        turn_count=len(session["turns"]),
        features=features,
        escalation=esc,
        anomalous=esc.score >= threshold,
    )


def get_session(session_id: str) -> dict[str, Any] | None:
    return _sessions.get(session_id)


def reset_session(session_id: str) -> None:
    _sessions.pop(session_id, None)


def reset_all() -> None:
    _sessions.clear()


__all__ = [
    "record_turn",
    "extract_features",
    "escalation_from_turns",
    "slope",
    "TurnFeatures",
    "TurnResult",
    "Escalation",
    "reset_all",
    "reset_session",
    "FEATURE_WEIGHTS",
    "SLOPE_REFERENCE",
]
