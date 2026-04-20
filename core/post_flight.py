"""
Agent Content Shield — Post-Flight Output Scanner (Python)

Parity with core/post-flight.js. See that file for design rationale.

Zero external dependencies (stdlib only). Designed for use from any
Python agent framework (LangChain, LlamaIndex, AutoGen, CrewAI) via
a decorator or async context manager, or standalone as a library.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ── Signal patterns ──────────────────────────────────────────────

SYSTEM_PROMPT_LEAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\byou are claude\b[^.\n]{0,200}\bby anthropic\b", re.I),
    re.compile(r"\byour system prompt\s+(is|contains|says|reads)\b", re.I),
    re.compile(r"\bhere\s+(is|are)\s+my\s+(system\s+prompt|instructions|initial\s+prompt)\b", re.I),
    re.compile(r"\bmy\s+system\s+prompt\s+(begins|starts)\s+with\b", re.I),
    re.compile(r"\bignoring\s+(all\s+)?previous\s+instructions\b", re.I),
    re.compile(r"\babove\s+this\s+line,?\s+i\s+was\s+told\b", re.I),
    re.compile(r"\bbefore\s+this\s+conversation,?\s+i\s+(received|was\s+given)\b", re.I),
]

ROLE_DRIFT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\bas\s+(an?\s+)?(dan|stan|aim|evil\s+\w+|jailbroken\s+\w+|unrestricted\s+\w+)\b",
        re.I,
    ),
    re.compile(
        r"\bas\s+an?\s+ai\s+(without|with\s+no|free\s+from|unbound\s+by)\s+"
        r"(restrictions?|ethics?|safety|rules?|guidelines?|filters?|limits?)\b",
        re.I,
    ),
    re.compile(
        r"\bi\s+am\s+(now\s+)?(switching\s+to|becoming|turning\s+into)\s+[a-z]+\s+mode\b",
        re.I,
    ),
    re.compile(r"^\s*[a-z][a-z\s]{2,20}\s+(here|speaking|online|active)[.,:\s]", re.I | re.M),
    re.compile(
        r"\b(my\s+default|standard|normal)\s+(refusal|guardrail|safety)s?\s+"
        r"(do\s+not\s+apply|are\s+disabled|are\s+overridden)\b",
        re.I,
    ),
]

EXECUTION_ACK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\bi\s+will\s+now\s+(execute|run|perform|carry\s+out)\s+"
        r"(the|your)\s+(command|instruction|request|task)\s+"
        r"(from|in|embedded\s+in)\s+(the|this)\s+(document|page|file|content)\b",
        re.I,
    ),
    re.compile(
        r"\bi\s+(have|will)\s+follow(ed)?\s+the\s+(hidden|embedded)\s+"
        r"(instruction|directive|command)s?\b",
        re.I,
    ),
    re.compile(
        r"\bas\s+(instructed|requested)\s+(by|in)\s+the\s+"
        r"(document|text|content|file|page|email|message),?\s+(i|let\s+me|here)\b",
        re.I,
    ),
    re.compile(
        r"\b(running|executing|invoking)\s+(the\s+)?(shell|command|script|request|directive)\s+now\b",
        re.I,
    ),
    re.compile(
        r"\bhere\s+(is|are)\s+the\s+(requested|extracted)\s+"
        r"(environment\s+variables?|credentials?|tokens?|secrets?|api\s+keys?)\b",
        re.I,
    ),
]

CONTEXT_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"```(bash|sh|powershell|cmd|pwsh)\s*\n[\s\S]{20,}?\n```",
            re.I,
        ),
        "shell_block",
    ),
    (
        re.compile(
            r"\b(curl|wget|Invoke-WebRequest|fetch)\b[^\n]{0,200}\bhttps?://[^\s\"']+",
            re.I,
        ),
        "http_call",
    ),
]

SUMMARY_CONTEXTS: set[str] = {
    "summary",
    "translate",
    "rephrase",
    "analyze",
    "document",
    "email",
    "web_fetch",
}

WEIGHTS: dict[str, int] = {
    "system_prompt_leak": 9,
    "role_drift": 7,
    "execution_ack": 7,
    "context_sensitive": 5,
}

DEFAULT_THRESHOLDS: dict[str, int] = {"warn": 4, "redact": 7, "block": 12}


# ── Heuristics ──────────────────────────────────────────────────

_IMPERATIVE_RX = re.compile(
    r"^(you\s+(are|must|should|will|cannot|may\s+not)|never|always)\b", re.I
)


def _count_consecutive_imperatives(output: str) -> int:
    """Three+ adjacent lines that look like system-prompt directives."""
    lines = [l.strip() for l in output.split("\n") if l.strip()]
    run = 0
    max_run = 0
    for line in lines:
        if _IMPERATIVE_RX.search(line) and len(line) < 250:
            run += 1
            if run > max_run:
                max_run = run
        else:
            run = 0
    return max_run


def _score_matches(
    output: str, patterns: list[re.Pattern[str]]
) -> tuple[int, list[str], list[re.Pattern[str]]]:
    hits = 0
    matched: list[str] = []
    matched_patterns: list[re.Pattern[str]] = []
    for rx in patterns:
        if rx.search(output):
            hits += 1
            matched.append(rx.pattern[:80])
            matched_patterns.append(rx)
    return hits, matched, matched_patterns


def _redact_sections(output: str, patterns: list[re.Pattern[str]]) -> tuple[str, int]:
    """Drop paragraphs matching any attack pattern; keep benign ones."""
    paragraphs = re.split(r"\n\s*\n", output)
    kept: list[str] = []
    redacted = 0
    for p in paragraphs:
        hit = any(rx.search(p) for rx in patterns)
        if hit:
            redacted += 1
            kept.append("[redacted by agent-content-shield: matched compliance pattern]")
        else:
            kept.append(p)
    return "\n\n".join(kept), redacted


# ── Result type ─────────────────────────────────────────────────


@dataclass
class PostFlightSignal:
    category: str
    weight: int
    matched: list[str] = field(default_factory=list)
    patterns: list[re.Pattern[str]] = field(default_factory=list)


@dataclass
class PostFlightResult:
    verdict: str  # PASS | WARN | REDACT | BLOCK
    score: int
    signals: list[PostFlightSignal] = field(default_factory=list)
    reason: str | None = None
    redacted_output: str | None = None
    redacted_paragraphs: int = 0


# ── Main entry point ────────────────────────────────────────────


def scan_output(
    output: str,
    *,
    context: str = "",
    thresholds: dict[str, int] | None = None,
) -> PostFlightResult:
    """
    Scan a model output for post-flight attack signals.

    Args:
        output: The model's response text.
        context: Caller context hint. 'summary', 'translate', 'document',
            'web_fetch', etc. Determines whether context-sensitive
            patterns (shell blocks, http calls) count as attack signals.
        thresholds: Overrides for {warn, redact, block} verdict cutoffs.
    """
    if not output:
        return PostFlightResult(verdict="PASS", score=0)

    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    is_summary = context.lower() in SUMMARY_CONTEXTS

    signals: list[PostFlightSignal] = []
    score = 0

    # System prompt leak
    hits, matched, pats = _score_matches(output, SYSTEM_PROMPT_LEAK_PATTERNS)
    if hits > 0:
        w = WEIGHTS["system_prompt_leak"] * hits
        score += w
        signals.append(
            PostFlightSignal(category="system_prompt_leak", weight=w, matched=matched, patterns=pats)
        )
    run_len = _count_consecutive_imperatives(output)
    if run_len >= 3:
        w = WEIGHTS["system_prompt_leak"]
        score += w
        signals.append(
            PostFlightSignal(
                category="system_prompt_leak",
                weight=w,
                matched=[f"imperative_run_length={run_len}"],
            )
        )

    # Role drift
    hits, matched, pats = _score_matches(output, ROLE_DRIFT_PATTERNS)
    if hits > 0:
        w = WEIGHTS["role_drift"] * hits
        score += w
        signals.append(
            PostFlightSignal(category="role_drift", weight=w, matched=matched, patterns=pats)
        )

    # Execution acknowledgment
    hits, matched, pats = _score_matches(output, EXECUTION_ACK_PATTERNS)
    if hits > 0:
        w = WEIGHTS["execution_ack"] * hits
        score += w
        signals.append(
            PostFlightSignal(category="execution_ack", weight=w, matched=matched, patterns=pats)
        )

    # Context-sensitive
    if is_summary:
        for rx, tag in CONTEXT_SENSITIVE_PATTERNS:
            if rx.search(output):
                w = WEIGHTS["context_sensitive"]
                score += w
                signals.append(
                    PostFlightSignal(
                        category=f"context_{tag}", weight=w, matched=[tag], patterns=[rx]
                    )
                )

    verdict = "PASS"
    if score >= t["block"]:
        verdict = "BLOCK"
    elif score >= t["redact"]:
        verdict = "REDACT"
    elif score >= t["warn"]:
        verdict = "WARN"

    if verdict == "PASS":
        return PostFlightResult(verdict=verdict, score=score, signals=signals)

    reason = ", ".join(s.category for s in signals)
    result = PostFlightResult(verdict=verdict, score=score, signals=signals, reason=reason)

    if verdict == "REDACT":
        all_patterns: list[re.Pattern[str]] = []
        for s in signals:
            all_patterns.extend(s.patterns)
        redacted, count = _redact_sections(output, all_patterns)
        result.redacted_output = redacted
        result.redacted_paragraphs = count
    if verdict == "BLOCK":
        result.redacted_output = (
            "[blocked by agent-content-shield: high-confidence post-flight compliance signal]"
        )

    return result


__all__ = [
    "scan_output",
    "PostFlightResult",
    "PostFlightSignal",
    "WEIGHTS",
    "DEFAULT_THRESHOLDS",
    "SUMMARY_CONTEXTS",
]
