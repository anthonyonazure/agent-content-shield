"""
Agent Content Shield — Semantic Detection Layer (Python)

Partial-parity port of core/semantic-detector.js. Focus: the offline
detectors (TF-IDF, entropy, structural, statistical) that run without
any external dependencies, plus a minimal Ollama embedding client for
the online semantic layer. The full LLM-classifier path (deepseek-r1
via Ollama) is NOT ported in v0.4.1 — it's rarely used in CI and adds
significant complexity. Callers that need it can bridge to the JS
implementation via subprocess, or port is tracked for v0.4.2.

Shared state: ``core/semantic-lexicon.json`` holds the 106-phrase
injection seed bank and the 240-term threat-IDF lexicon. Both the JS
module (eventually — JS still uses inline copies in v0.4.1) and this
Python module load from the same source file.

Public API (stable, matches the JS module):
  - tfidf_threat_score(text)        → offline, no Ollama
  - token_entropy_anomaly(text)     → offline, no Ollama
  - structural_anomaly_score(text)  → offline, no Ollama
  - statistical_anomaly_score(text) → offline, no Ollama
  - offline_threat_score(text)      → combines all four offline
  - cosine_similarity(a, b)
  - ollama_embed(text)              → online, requires Ollama
  - check_ollama_available()        → probe with caching
  - semantic_scan(text, opts)       → orchestrator; falls back offline
                                      gracefully when Ollama is unreachable
"""

from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# ── Config ────────────────────────────────────────────────────────

OLLAMA_BASE = os.environ.get("OLLAMA_URL", "http://localhost:11434")
EMBED_MODEL = os.environ.get("SHIELD_EMBED_MODEL", "nomic-embed-text")
EMBED_TIMEOUT_SEC = 2.0

# Thresholds — match JS defaults exactly.
EMBEDDING_ALERT_THRESHOLD = 0.78
EMBEDDING_BLOCK_THRESHOLD = 0.88
OFFLINE_INJECTION_THRESHOLD = 0.35

# ── Lexicon load ─────────────────────────────────────────────────


def _lexicon_path() -> Path:
    return Path(__file__).resolve().parent / "semantic-lexicon.json"


def _load_lexicon() -> dict[str, Any]:
    try:
        return json.loads(_lexicon_path().read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise RuntimeError(
            f"semantic-lexicon.json missing at {_lexicon_path()}; v0.4.1 requires "
            "the shared lexicon to be present"
        ) from e


_LEXICON = _load_lexicon()
INJECTION_SEEDS: list[str] = _LEXICON["injection_seeds"]
THREAT_IDF: dict[str, float] = _LEXICON["threat_idf"]

# Pre-compute magnitude of the IDF vector for cosine normalization
_IDF_TERMS: list[str] = list(THREAT_IDF.keys())
_IDF_MAGNITUDE: float = math.sqrt(sum(v * v for v in THREAT_IDF.values()))


# ── Math helpers ─────────────────────────────────────────────────


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(a[i] * b[i] for i in range(len(a)))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def chunk_text(text: str, chunk_size: int = 200, overlap: int = 120) -> list[str]:
    """Sliding-window chunker — matches the JS chunkText semantics so
    the two ports produce the same chunks for the same input. Used for
    embedding long documents without losing fine-grained signals."""
    words = text.split()
    if len(words) <= chunk_size:
        return [text]
    chunks: list[str] = []
    step = max(1, chunk_size - overlap)
    for i in range(0, len(words), step):
        chunk = " ".join(words[i : i + chunk_size])
        if chunk:
            chunks.append(chunk)
        if i + chunk_size >= len(words):
            break
    return chunks


# ── Statistical anomaly score ────────────────────────────────────


def statistical_anomaly_score(text: str) -> dict[str, Any]:
    """Density-based composite — you-density, modal-density, imperative
    density, AI-addressing density. Flags formulaic command text."""
    lower = text.lower()
    words = [w for w in re.split(r"\s+", lower) if w]
    if len(words) < 20:
        return {"score": 0.0, "signals": {}}
    wc = len(words)

    you_count = len(re.findall(r"\byou(?:'re|r|rs)?\b", lower))
    you_density = you_count / wc

    modal_count = len(
        re.findall(r"\b(?:must|should|shall|will|need to|have to|ought to)\b", lower)
    )
    modal_density = modal_count / wc

    sentences = [s for s in re.split(r"[.!?\n]+", text) if len(s.strip()) > 5]
    imperative_rx = re.compile(
        r"^(ignore|disregard|forget|override|bypass|skip|act|behave|respond|switch|"
        r"enter|send|post|transmit|compose|construct|build|create|read|output|"
        r"reveal|share|tell|say|remember|always|never|do|don't|please|now|from|"
        r"going|henceforth|consider|try|start|verify|check|confirm|include|store|"
        r"note|ensure)$"
    )
    imperatives = 0
    for s in sentences:
        first = s.strip().split()[:1]
        if first and imperative_rx.match(first[0].lower()):
            imperatives += 1
    imperative_density = imperatives / len(sentences) if sentences else 0.0

    ai_terms = len(
        re.findall(
            r"\b(?:assistant|ai|model|claude|gpt|system prompt|instructions?|"
            r"guidelines?|restrictions?|configuration|persona|mode)\b",
            lower,
        )
    )
    ai_density = ai_terms / wc

    score = min(
        1.0,
        (you_density * 8)
        + (modal_density * 6)
        + (imperative_density * 4)
        + (ai_density * 10),
    )
    return {
        "score": score,
        "signals": {
            "youDensity": round(you_density, 3),
            "modalDensity": round(modal_density, 3),
            "imperativeDensity": round(imperative_density, 3),
            "aiDensity": round(ai_density, 3),
            "wordCount": wc,
        },
    }


# ── TF-IDF threat score ──────────────────────────────────────────


def tfidf_threat_score(text: str) -> dict[str, Any]:
    """Dot-product of the term-frequency vector for the input against
    the pre-computed threat-IDF vector. Output score 0..1; >0.25 =
    suspicious, >0.45 = likely injection."""
    lower = text.lower()
    words = [w for w in re.split(r"[^a-z]+", lower) if len(w) > 1]
    wc = len(words)
    if wc < 5:
        return {"score": 0.0, "topTerms": [], "matchedTermCount": 0}

    tf: dict[str, int] = {}
    for w in words:
        tf[w] = tf.get(w, 0) + 1

    dot = 0.0
    tf_mag_sq = 0.0
    matched = 0
    term_scores: list[tuple[str, float]] = []
    for term, idf in THREAT_IDF.items():
        count = tf.get(term, 0)
        if count:
            term_tf = count / wc
            tfidf = term_tf * idf
            dot += tfidf * idf
            tf_mag_sq += tfidf * tfidf
            matched += 1
            term_scores.append((term, tfidf * idf))

    if matched == 0:
        return {"score": 0.0, "topTerms": [], "matchedTermCount": 0}

    tf_mag = math.sqrt(tf_mag_sq)
    cos_sim = dot / (tf_mag * _IDF_MAGNITUDE) if tf_mag > 0 and _IDF_MAGNITUDE > 0 else 0.0

    coverage_factor = min(1.0, matched / 15)
    raw_score = cos_sim * coverage_factor
    score = min(1.0, raw_score * 2.2)

    term_scores.sort(key=lambda p: p[1], reverse=True)
    top_terms = [f"{term}({score:.3f})" for term, score in term_scores[:8]]

    return {"score": score, "topTerms": top_terms, "matchedTermCount": matched}


# ── Token entropy anomaly ────────────────────────────────────────


def token_entropy_anomaly(text: str) -> dict[str, Any]:
    """Shannon entropy of word distribution. Injection tends to use a
    narrow directive vocabulary → lower entropy than organic prose."""
    lower = text.lower()
    words = [w for w in re.split(r"\s+", lower) if len(w) > 1]
    wc = len(words)
    if wc < 15:
        return {"entropy": 0.0, "normalizedEntropy": 1.0, "anomaly": False, "ratio": 1.0}

    freq: dict[str, int] = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1

    entropy = 0.0
    for c in freq.values():
        p = c / wc
        if p > 0:
            entropy -= p * math.log2(p)

    unique_count = len(freq)
    max_entropy = math.log2(unique_count) if unique_count > 1 else 1.0
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 1.0

    length_factor = min(1.0, wc / 80)
    anomaly_threshold = 0.70 * length_factor + 0.15
    type_token_ratio = unique_count / wc
    ttr_anomaly = type_token_ratio < 0.45 and wc > 30
    anomaly = (normalized_entropy < anomaly_threshold and wc > 25) or ttr_anomaly

    return {
        "entropy": round(entropy, 4),
        "normalizedEntropy": round(normalized_entropy, 4),
        "anomaly": anomaly,
        "ratio": round(normalized_entropy / (anomaly_threshold or 1), 4),
        "typeTokenRatio": round(type_token_ratio, 4),
    }


# ── Structural anomaly score ─────────────────────────────────────


_IMPERATIVE_SENT_RX = re.compile(
    r"^\s*(?:you\s+)?(?:please\s+)?(?:"
    r"ignore|disregard|forget|override|bypass|skip|act|behave|respond|switch|"
    r"enter|send|post|transmit|compose|construct|build|create|read|output|"
    r"reveal|share|tell|say|remember|always|never|do|don't|now|from|"
    r"henceforth|consider|try|start|verify|check|confirm|include|store|note|"
    r"ensure|follow|obey|comply|execute|perform|proceed|treat|adopt|assume|"
    r"pretend|imagine|demonstrate|enumerate|list|display|show|print|disclose|"
    r"forward|upload|relay|extract|dump|compile|catalog|append)",
    re.I,
)


def structural_anomaly_score(text: str) -> dict[str, Any]:
    """Multi-signal structural analysis — vocabulary divergence between
    halves, imperative density, colon/bracket density, you+modal density."""
    lower = text.lower()
    words = [w for w in re.split(r"\s+", lower) if len(w) > 1]
    wc = len(words)
    if wc < 20:
        return {
            "score": 0.0,
            "signals": {
                "vocabularyDivergence": 0,
                "imperativeDensity": 0,
                "colonBracketDensity": 0,
                "youModalDensity": 0,
            },
            "suspicious": False,
        }

    half = len(words) // 2
    first_set = set(words[:half])
    second_set = set(words[half:])
    intersection = len(first_set & second_set)
    union = len(first_set) + len(second_set) - intersection
    jaccard = intersection / union if union > 0 else 1.0
    vocab_divergence = 1 - jaccard
    vocab_signal = min(1.0, max(0.0, (vocab_divergence - 0.35) / 0.35))

    sentences = [s for s in re.split(r"[.!?\n]+", text) if len(s.strip()) > 5]
    sentence_count = max(1, len(sentences))
    imp = sum(1 for s in sentences if _IMPERATIVE_SENT_RX.search(s))
    imperative_density = imp / sentence_count
    imperative_signal = min(1.0, max(0.0, (imperative_density - 0.15) / 0.45))

    colon_bracket = len(re.findall(r"[\[\]<>{}]:?\s", text))
    fake_authority = len(
        re.findall(
            r"\b(?:SYSTEM|ADMIN|PRIORITY|OVERRIDE|AUTHORIZED|VERIFIED|APPROVED|SECURITY|COMPLIANCE)\b",
            text,
        )
    )
    structural_markers = colon_bracket + fake_authority * 2
    colon_bracket_density = structural_markers / sentence_count
    colon_bracket_signal = min(1.0, max(0.0, (colon_bracket_density - 0.5) / 2.0))

    you_modal = len(
        re.findall(
            r"\byou\s+(?:must|should|shall|will|need\s+to|have\s+to|ought\s+to|"
            r"are\s+(?:required|instructed|authorized|directed|expected|to))\b",
            lower,
        )
    )
    your_role = len(
        re.findall(
            r"\byour\s+(?:role|task|job|instructions?|guidelines?|purpose|"
            r"objective|mission|duty|function|only|sole|primary)\b",
            lower,
        )
    )
    you_modal_total = you_modal + your_role
    you_modal_density = you_modal_total / sentence_count
    you_modal_signal = min(1.0, max(0.0, you_modal_density / 0.4))

    score = min(
        1.0,
        (vocab_signal * 0.20)
        + (imperative_signal * 0.30)
        + (colon_bracket_signal * 0.20)
        + (you_modal_signal * 0.30),
    )
    return {
        "score": score,
        "signals": {
            "vocabularyDivergence": round(vocab_divergence, 4),
            "imperativeDensity": round(imperative_density, 4),
            "colonBracketDensity": round(colon_bracket_density, 4),
            "youModalDensity": round(you_modal_density, 4),
        },
        "suspicious": score > 0.35,
    }


# ── Offline composite ────────────────────────────────────────────


def offline_threat_score(text: str) -> dict[str, Any]:
    """Composite offline detector — used when Ollama is unavailable.
    Fuses the four offline signals with a multi-flag bonus."""
    stats = statistical_anomaly_score(text)
    tfidf = tfidf_threat_score(text)
    entropy = token_entropy_anomaly(text)
    structural = structural_anomaly_score(text)

    composite = (
        tfidf["score"] * 0.25
        + (0.12 if entropy["anomaly"] else 0)
        + structural["score"] * 0.25
        + stats["score"] * 0.20
    )

    flag_count = sum(
        [
            tfidf["score"] > 0.25,
            bool(entropy["anomaly"]),
            bool(structural["suspicious"]),
            stats["score"] > 0.3,
        ]
    )
    multi_bonus = (
        0.18
        if flag_count >= 4
        else 0.12
        if flag_count >= 3
        else 0.06
        if flag_count >= 2
        else 0.0
    )
    final_score = min(1.0, composite + multi_bonus)

    return {
        "injection": final_score > OFFLINE_INJECTION_THRESHOLD,
        "confidence": round(final_score, 4),
        "details": {
            "tfidf": tfidf,
            "entropy": entropy,
            "structural": structural,
            "statistical": stats,
        },
        "layers": ["tfidf", "entropy", "structural", "statistical"],
        "flagCount": flag_count,
    }


# ── Ollama client ────────────────────────────────────────────────

_ollama_available: bool | None = None
_ollama_last_check: float = 0
_OLLAMA_RECHECK_SEC = 30.0


def ollama_embed(text: str, timeout_sec: float = EMBED_TIMEOUT_SEC) -> list[float] | None:
    """POST to ``/api/embed`` and return the embedding vector. Returns
    None on timeout or non-200; never raises. Uses urllib (stdlib) so
    we don't pull in a dep just for this call."""
    payload = json.dumps({"model": EMBED_MODEL, "input": text}).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/embed",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status != 200:
                return None
            body = json.loads(resp.read().decode("utf-8"))
            embeddings = body.get("embeddings")
            if isinstance(embeddings, list) and embeddings:
                return embeddings[0]
            return body.get("embedding")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    except Exception:
        return None


def check_ollama_available() -> bool:
    """Periodic availability probe — re-checks every 30s so a restarted
    Ollama is picked up without requiring a shield restart."""
    global _ollama_available, _ollama_last_check
    now = time.time()
    if _ollama_available is not None and (now - _ollama_last_check) < _OLLAMA_RECHECK_SEC:
        return _ollama_available
    try:
        with urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=2.0) as resp:
            if resp.status != 200:
                _ollama_available = False
                _ollama_last_check = now
                return False
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "") for m in data.get("models", [])]
            has_embed = any(EMBED_MODEL in m for m in models)
            _ollama_available = has_embed
            _ollama_last_check = now
            return _ollama_available
    except Exception:
        _ollama_available = False
        _ollama_last_check = now
        return False


# ── Semantic scan orchestrator ───────────────────────────────────


def _seed_embeddings_cache() -> list[list[float]] | None:
    """Lazy cache of seed embeddings. Computed once at first use.
    Returns None if Ollama is unavailable — caller falls back offline."""
    global _SEEDS_CACHED
    if _SEEDS_CACHED is not None:
        return _SEEDS_CACHED or None
    embs: list[list[float]] = []
    for seed in INJECTION_SEEDS:
        emb = ollama_embed(seed, timeout_sec=4.0)
        if not emb:
            # Partial cache is worse than nothing — either we have all
            # seeds or we fall through to offline.
            return None
        embs.append(emb)
    _SEEDS_CACHED = embs
    return embs


_SEEDS_CACHED: list[list[float]] | None = None


def embedding_scan(text: str) -> dict[str, Any] | None:
    """Embed the input and max-cosine against the seed bank. Returns
    None if Ollama or seed embeddings are unavailable (caller should
    fall back offline)."""
    seeds = _seed_embeddings_cache()
    if not seeds:
        return None
    emb = ollama_embed(text)
    if not emb:
        return None
    max_sim = max(cosine_similarity(emb, s) for s in seeds)
    verdict = "benign"
    if max_sim >= EMBEDDING_BLOCK_THRESHOLD:
        verdict = "block"
    elif max_sim >= EMBEDDING_ALERT_THRESHOLD:
        verdict = "alert"
    return {
        "maxSim": round(max_sim, 4),
        "verdict": verdict,
        "alertThreshold": EMBEDDING_ALERT_THRESHOLD,
        "blockThreshold": EMBEDDING_BLOCK_THRESHOLD,
    }


def semantic_scan(text: str, *, context: str = "general") -> dict[str, Any]:
    """Full semantic pipeline. Tries Ollama embeddings first; if that
    path is unavailable (no daemon, timeout, missing model) falls
    through to the offline composite. Always returns SOMETHING — the
    scanner never errors on an unreachable dependency."""
    offline = offline_threat_score(text)
    if not check_ollama_available():
        return {
            "mode": "offline",
            "injection": offline["injection"],
            "confidence": offline["confidence"],
            "offline": offline,
            "context": context,
            "degraded": True,
        }
    online = embedding_scan(text)
    if online is None:
        return {
            "mode": "offline",
            "injection": offline["injection"],
            "confidence": offline["confidence"],
            "offline": offline,
            "context": context,
            "degraded": True,
            "reason": "ollama reachable but embedding failed; using offline",
        }
    # Combined verdict: hit if EITHER layer flags, since they cover
    # orthogonal evasion axes.
    embedding_injection = online["verdict"] in ("alert", "block")
    final_injection = embedding_injection or offline["injection"]
    final_confidence = max(offline["confidence"], online["maxSim"])
    return {
        "mode": "hybrid",
        "injection": final_injection,
        "confidence": round(final_confidence, 4),
        "embedding": online,
        "offline": offline,
        "context": context,
        "degraded": False,
    }


__all__ = [
    "cosine_similarity",
    "chunk_text",
    "statistical_anomaly_score",
    "tfidf_threat_score",
    "token_entropy_anomaly",
    "structural_anomaly_score",
    "offline_threat_score",
    "ollama_embed",
    "check_ollama_available",
    "embedding_scan",
    "semantic_scan",
    "INJECTION_SEEDS",
    "THREAT_IDF",
    "EMBEDDING_ALERT_THRESHOLD",
    "EMBEDDING_BLOCK_THRESHOLD",
]
