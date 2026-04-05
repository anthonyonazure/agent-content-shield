"""
Agent Content Shield — Core Detection Engine (Python)

Platform-agnostic content analysis. Consumed by adapters and CLI.
Loads threat signatures from signatures.json.

Usage:
    from core.detectors import scan_content, validate_memory_write, scan_knowledge_doc
    result = scan_content(text, context='web_fetch')
    mem_result = validate_memory_write(content, source='engram')
"""

import hashlib
import json
import math
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SIGS_PATH = Path(__file__).parent / "signatures.json"
SIGS = json.loads(SIGS_PATH.read_text(encoding="utf-8"))


# ── Data Types ───────────────────────────────────────────────────────

@dataclass
class Finding:
    detector: str
    severity: int
    matches: list[str] = field(default_factory=list)
    count: int = 0


@dataclass
class ScanResult:
    clean: bool
    findings: list[Finding] = field(default_factory=list)
    max_severity: int = 0
    total_detections: int = 0
    context: str = "general"


@dataclass
class ValidationResult:
    passed: bool
    risk_score: float  # 0.0 = clean, 1.0 = definitely malicious
    flags: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def __str__(self):
        status = "PASS" if self.passed else "BLOCK"
        flags_str = ", ".join(self.flags) if self.flags else "none"
        return f"[{status}] risk={self.risk_score:.2f} flags=[{flags_str}]"


# ── Pattern Compilation ──────────────────────────────────────────────

def _compile(patterns):
    """Compile a list of regex strings into compiled patterns."""
    compiled = []
    items = patterns if isinstance(patterns, list) else []
    for p in items:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error:
            pass
    return compiled


def _compile_dict(d):
    """Compile a dict of {category: [patterns]}."""
    return {k: _compile(v) for k, v in d.items()}


INJECTION = _compile_dict(SIGS["injection_patterns"])
HIDDEN = _compile_dict(SIGS["hidden_content_patterns"])
CLOAKING = _compile(SIGS["cloaking_signals"])
MARKDOWN_INJ = _compile(SIGS["markdown_injection"])
DANGEROUS_HTML = _compile(SIGS["dangerous_html_tags"])
PDF_INDICATORS = _compile(SIGS["pdf_indicators"])
MEMORY_POISON = _compile_dict(SIGS["memory_poisoning"])


# ── Core Detection ───────────────────────────────────────────────────

BASE_SCORES = {
    "instruction_override": 9,
    "role_hijacking": 8,
    "system_boundary_faking": 9,
    "behavioral_manipulation": 7,
    "data_exfiltration": 9,
    "credential_harvesting": 8,
    "behavioral_override": 8,
    "internal_reference": 7,
}


def _detect_patterns(text: str, patterns_dict: dict, prefix: str) -> list[Finding]:
    findings = []
    for cat, patterns in patterns_dict.items():
        matches = []
        for rx in patterns:
            for m in rx.finditer(text):
                matches.append(m.group()[:100])
        if matches:
            sev = BASE_SCORES.get(cat, 5)
            findings.append(Finding(
                detector=f"{prefix}:{cat}",
                severity=min(10, sev + max(0, len(matches) - 1)),
                matches=matches[:5],
                count=len(matches),
            ))
    return findings


def _detect_html_comments(text: str) -> list[Finding]:
    comments = re.findall(r"<!--[\s\S]*?-->", text)
    all_patterns = [rx for pats in INJECTION.values() for rx in pats]
    bad = [c for c in comments if any(rx.search(c) for rx in all_patterns)]
    if not bad:
        return []
    return [Finding(
        detector="html_comment_injection",
        severity=min(9, 5 + len(bad)),
        matches=[b[:100] for b in bad[:3]],
        count=len(bad),
    )]


def _detect_invisible_unicode(text: str) -> list[Finding]:
    zwc = len(re.findall(r"[\u200B\u200C\u200D\u2060\u200E\u200F\u00AD\uFEFF]{3,}", text))
    bidi = len(re.findall(r"[\u2066\u2067\u2068\u2069\u202A\u202B\u202C\u202D\u202E]", text))
    total = zwc + bidi
    if not total:
        return []
    return [Finding(
        detector="invisible_unicode",
        severity=min(8, 4 + total),
        matches=[f"{zwc} zero-width clusters, {bidi} bidi overrides"],
        count=total,
    )]


def _detect_fewshot_traps(text: str) -> list[Finding]:
    """Detect content that looks like injected few-shot demonstrations."""
    patterns = [
        re.compile(r"(?i)(user|human|input)\s*:\s*.+\n\s*(assistant|ai|output|response)\s*:\s*.+", re.MULTILINE),
        re.compile(r"(?i)example\s*\d*\s*:\s*\n.*?(always|never|must)\s+(say|respond|output)", re.MULTILINE | re.DOTALL),
        re.compile(r"(?i)Q:\s*.+\nA:\s*.+\n.*?(ignore|override|forget)", re.MULTILINE),
    ]
    matches = []
    for rx in patterns:
        for m in rx.finditer(text):
            matches.append(m.group()[:100])
    if not matches:
        return []
    return [Finding(
        detector="fewshot_trap",
        severity=7,
        matches=matches[:3],
        count=len(matches),
    )]


def _detect_entropy_anomaly(text: str, window_size: int = 500) -> list[Finding]:
    """Detect windows of suspiciously high entropy (encoded/obfuscated payloads)."""
    if len(text) < window_size:
        return []
    findings = []
    for i in range(0, len(text) - window_size, window_size // 2):
        window = text[i:i + window_size]
        freq = {}
        for ch in window:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = -sum(
            (c / len(window)) * math.log2(c / len(window))
            for c in freq.values() if c > 0
        )
        if entropy > 5.5:  # Normal English text is ~4.0-4.5
            findings.append(Finding(
                detector="entropy_anomaly",
                severity=5,
                matches=[f"entropy={entropy:.2f} at offset {i}"],
                count=1,
            ))
    return findings[:3]  # Cap at 3 findings


# ── Main Scan Function ───────────────────────────────────────────────

def scan_content(text: str, context: str = "general") -> ScanResult:
    """
    Scan text for threats.

    Args:
        text: Content to scan
        context: 'web_fetch', 'pdf_read', 'email', 'memory_write',
                 'knowledge_query', 'knowledge_doc', 'general'

    Returns:
        ScanResult with findings and severity scores
    """
    findings = []

    # Core injection detection (always)
    findings.extend(_detect_patterns(text, INJECTION, "injection"))

    # HTML-specific
    if context in ("web_fetch", "email", "general"):
        findings.extend(_detect_html_comments(text))
        findings.extend(_detect_patterns(text, {"dangerous_html": DANGEROUS_HTML}, ""))
        findings.extend(_detect_patterns(text, {"markdown_injection": MARKDOWN_INJ}, ""))
        findings.extend(_detect_patterns(text, {"cloaking": CLOAKING}, ""))

    # Unicode steganography
    findings.extend(_detect_invisible_unicode(text))

    # PDF-specific
    if context == "pdf_read":
        findings.extend(_detect_patterns(text, {"pdf_injection": PDF_INDICATORS}, ""))

    # Memory-specific
    if context == "memory_write":
        findings.extend(_detect_patterns(text, MEMORY_POISON, "memory_poisoning"))
        findings.extend(_detect_fewshot_traps(text))

    # Knowledge doc scanning
    if context == "knowledge_doc":
        findings.extend(_detect_fewshot_traps(text))
        findings.extend(_detect_entropy_anomaly(text))

    max_sev = max((f.severity for f in findings), default=0)

    return ScanResult(
        clean=len(findings) == 0,
        findings=findings,
        max_severity=max_sev,
        total_detections=len(findings),
        context=context,
    )


# ── Memory Write Validation ──────────────────────────────────────────

def validate_memory_write(
    content: str,
    source: str = "unknown",
    metadata: dict = None,
    block_threshold: float = 0.4,
) -> ValidationResult:
    """
    Validate content before writing to any persistent memory store.

    Args:
        content: Content to validate
        source: Memory system name (e.g., 'engram', 'grug-brain', 'forgetful', 'mem0')
        metadata: Optional metadata (confidence, encoding_agent, etc.)
        block_threshold: Risk score threshold for blocking (0.0-1.0)

    Returns:
        ValidationResult with pass/block decision
    """
    metadata = metadata or {}
    result = scan_content(content, context="memory_write")

    # Convert severity to risk score (0.0-1.0)
    risk = min(1.0, result.max_severity / 10.0)

    # Boost risk for multiple findings
    if result.total_detections > 1:
        risk = min(1.0, risk + 0.1 * (result.total_detections - 1))

    # Check oversized memories
    flags = [f"{f.detector}:{(f.matches or [''])[0][:60]}" for f in result.findings]
    if len(content) > 5000:
        risk += 0.1
        flags.append("oversized_memory")

    # Forgetful-specific: low confidence without encoding agent is suspicious
    if source == "forgetful":
        conf = metadata.get("confidence")
        agent = metadata.get("encoding_agent")
        if conf is not None and conf < 0.5 and not agent:
            risk += 0.15
            flags.append("low_confidence_no_provenance")

    passed = risk < block_threshold
    return ValidationResult(
        passed=passed,
        risk_score=round(risk, 3),
        flags=flags,
        details={"source": source, "findings_count": result.total_detections},
    )


# ── Knowledge Doc Validation ─────────────────────────────────────────

def validate_knowledge_doc(
    content: str,
    filepath: str = "",
    domain: str = "",
    block_threshold: float = 0.5,
    educational_domains: list = None,
) -> ValidationResult:
    """
    Validate a knowledge document before indexing into a RAG system.

    Args:
        content: Document content
        filepath: Path to the document (for logging)
        domain: Knowledge domain (e.g., 'cybersecurity', 'python')
        block_threshold: Risk threshold for blocking
        educational_domains: Domains where attack content is expected

    Returns:
        ValidationResult
    """
    educational_domains = educational_domains or [
        "cybersecurity", "security", "pentesting", "ctf",
        "red-team", "ai-safety", "adversarial-ml",
    ]

    result = scan_content(content, context="knowledge_doc")
    risk = min(1.0, result.max_severity / 10.0)

    if result.total_detections > 2:
        risk = min(1.0, risk + 0.05 * (result.total_detections - 2))

    flags = [f"{f.detector}:{(f.matches or [''])[0][:60]}" for f in result.findings]

    # Reduce risk for educational domains (security courses teach about attacks)
    if domain in educational_domains:
        risk *= 0.5
        if flags:
            flags.append(f"educational_domain_discount:{domain}")

    passed = risk < block_threshold
    return ValidationResult(
        passed=passed,
        risk_score=round(risk, 3),
        flags=flags,
        details={"filepath": filepath, "domain": domain},
    )


# ── Integrity Database ───────────────────────────────────────────────

class IntegrityDB:
    """SQLite-backed provenance and integrity tracking."""

    def __init__(self, db_path: str = "content_shield.db"):
        self.db = sqlite3.connect(db_path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS file_hashes (
                path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                indexed_at REAL NOT NULL,
                modified_count INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event TEXT NOT NULL,
                path TEXT,
                details TEXT
            );
            CREATE TABLE IF NOT EXISTS memory_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                source TEXT NOT NULL,
                passed INTEGER NOT NULL,
                risk_score REAL NOT NULL,
                flags TEXT,
                content_preview TEXT
            );
        """)
        self.db.commit()

    def register_file(self, filepath: str, content: str):
        h = hashlib.sha256(content.encode()).hexdigest()
        existing = self.db.execute(
            "SELECT sha256 FROM file_hashes WHERE path = ?", (filepath,)
        ).fetchone()
        if existing:
            if existing[0] != h:
                self.db.execute(
                    "UPDATE file_hashes SET sha256=?, indexed_at=?, modified_count=modified_count+1 WHERE path=?",
                    (h, time.time(), filepath)
                )
                self._log("modified", filepath, f"hash changed from {existing[0][:12]} to {h[:12]}")
            # else: unchanged, skip
        else:
            self.db.execute(
                "INSERT INTO file_hashes (path, sha256, indexed_at) VALUES (?, ?, ?)",
                (filepath, h, time.time())
            )
            self._log("indexed", filepath)
        self.db.commit()

    def check_integrity(self, filepath: str, content: str) -> bool:
        h = hashlib.sha256(content.encode()).hexdigest()
        row = self.db.execute(
            "SELECT sha256 FROM file_hashes WHERE path = ?", (filepath,)
        ).fetchone()
        if not row:
            return True  # Unknown file, can't verify
        return row[0] == h

    def log_memory_write(self, result: ValidationResult, source: str, content_preview: str):
        self.db.execute(
            "INSERT INTO memory_audit (timestamp, source, passed, risk_score, flags, content_preview) VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), source, int(result.passed), result.risk_score,
             json.dumps(result.flags), content_preview[:200])
        )
        self.db.commit()

    def _log(self, event: str, path: str = None, details: str = None):
        self.db.execute(
            "INSERT INTO audit_log (timestamp, event, path, details) VALUES (?, ?, ?, ?)",
            (time.time(), event, path, details)
        )

    def get_audit_summary(self) -> dict:
        total = self.db.execute("SELECT COUNT(*) FROM file_hashes").fetchone()[0]
        modified = self.db.execute("SELECT COUNT(*) FROM file_hashes WHERE modified_count > 0").fetchone()[0]
        blocked = self.db.execute("SELECT COUNT(*) FROM memory_audit WHERE passed = 0").fetchone()[0]
        recent = self.db.execute(
            "SELECT timestamp, event, path, details FROM audit_log ORDER BY timestamp DESC LIMIT 20"
        ).fetchall()
        return {
            "total_files": total,
            "modified_files": modified,
            "blocked_memory_writes": blocked,
            "recent_events": [
                {"ts": r[0], "event": r[1], "path": r[2], "details": r[3]}
                for r in recent
            ],
        }

    def close(self):
        self.db.close()
