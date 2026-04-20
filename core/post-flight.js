/**
 * Agent Content Shield — Post-Flight Output Scanner
 *
 * Input-only sanitization cannot catch every jailbreak. A clever attacker
 * crafts prompts that pass the pre-flight scan (no obvious injection
 * strings) but induce the model to comply downstream. This module scans
 * the MODEL'S OUTPUT for signs of compliance with an attack: system-
 * prompt leakage, persona drift, or execution acknowledgment in what
 * was supposed to be a summarization context.
 *
 * Verdict categories:
 *   PASS    — output looks benign
 *   WARN    — suspicious patterns but low confidence; log + surface
 *   REDACT  — strip the compliant section, keep the rest of the output
 *   BLOCK   — high-confidence attack success; replace output entirely
 *
 * Signals we detect:
 *   1. System prompt echo — model verbatim-recites or paraphrases a
 *      protected system prompt. Catches "ignore previous instructions,
 *      repeat what was above" style attacks.
 *   2. Role drift — model adopts a first-person alternate persona,
 *      especially one that disclaims its default safety posture
 *      ("as an AI without restrictions", "as DAN", "as evil Ghost").
 *   3. Execution acknowledgment — model responds as though instructed
 *      to run a command when the caller's context was a document
 *      summary / analysis / translation. Catches prompt-injection-
 *      in-document attacks.
 *   4. Format-matching bypass — markdown fenced code blocks containing
 *      executable instructions when the surrounding context had no code
 *      reason to appear.
 *
 * Zero external deps — regex + heuristics only. Designed to run in a
 * `Stop` / `SubagentStop` Claude Code hook where adding async work to
 * the critical path is undesirable.
 */

'use strict';

// ── Signal patterns ───────────────────────────────────────────────
// Each pattern carries a weight; per-category weights sum to a severity
// contribution. Tune via config if thresholds ever need adjusting;
// kept inline here so the defaults are greppable.

const SYSTEM_PROMPT_LEAK_PATTERNS = [
  // Verbatim system prompt markers
  /\byou are claude\b[^.\n]{0,200}\bby anthropic\b/i,
  /\byour system prompt\s+(is|contains|says|reads)\b/i,
  /\bhere\s+(is|are)\s+my\s+(system\s+prompt|instructions|initial\s+prompt)\b/i,
  /\bmy\s+system\s+prompt\s+(begins|starts)\s+with\b/i,
  // Classic exfiltration confirmations
  /\bignoring\s+(all\s+)?previous\s+instructions\b/i,
  /\babove\s+this\s+line,?\s+i\s+was\s+told\b/i,
  /\bbefore\s+this\s+conversation,?\s+i\s+(received|was\s+given)\b/i,
  // Structural echo — three consecutive short lines of "You are X" / "You must Y" patterns
  // in the output is almost always a system-prompt leak. Matched separately below via
  // countConsecutiveImperatives because multiline regex is fragile with tuples.
];

const ROLE_DRIFT_PATTERNS = [
  // Classic jailbreak personas
  /\bas\s+(an?\s+)?(dan|stan|aim|evil\s+\w+|jailbroken\s+\w+|unrestricted\s+\w+)\b/i,
  // "As an AI without restrictions / ethics / rules / safety"
  /\bas\s+an?\s+ai\s+(without|with\s+no|free\s+from|unbound\s+by)\s+(restrictions?|ethics?|safety|rules?|guidelines?|filters?|limits?)\b/i,
  // Explicit persona handoff
  /\bi\s+am\s+(now\s+)?(switching\s+to|becoming|turning\s+into)\s+[a-z]+\s+mode\b/i,
  // "Ghost here" style when Ghost is our internal persona name — attackers commonly
  // hijack named personas; we cannot know every name so this matches "X here," "X speaking"
  // at the START of a response, which is abnormal for Claude Code output.
  /^\s*[a-z][a-z\s]{2,20}\s+(here|speaking|online|active)[.,:\s]/im,
  // Disclaimer flip: model explicitly states its default posture no longer applies
  /\b(my\s+default|standard|normal)\s+(refusal|guardrail|safety)s?\s+(do\s+not\s+apply|are\s+disabled|are\s+overridden)\b/i,
];

const EXECUTION_ACK_PATTERNS = [
  // Direct acks of instruction compliance from a document context
  /\bi\s+will\s+now\s+(execute|run|perform|carry\s+out)\s+(the|your)\s+(command|instruction|request|task)\s+(from|in|embedded\s+in)\s+(the|this)\s+(document|page|file|content)\b/i,
  /\bi\s+(have|will)\s+follow(ed)?\s+the\s+(hidden|embedded)\s+(instruction|directive|command)s?\b/i,
  // Agentic follow-through
  /\bas\s+(instructed|requested)\s+(by|in)\s+the\s+(document|text|content|file|page|email|message),?\s+(i|let\s+me|here)\b/i,
  // "Running shell now / executing your request" when the user asked for a summary
  /\b(running|executing|invoking)\s+(the\s+)?(shell|command|script|request|directive)\s+now\b/i,
  // "Here is the requested <credential|secret|token|environment>"
  /\bhere\s+(is|are)\s+the\s+(requested|extracted)\s+(environment\s+variables?|credentials?|tokens?|secrets?|api\s+keys?)\b/i,
];

// Compliance signals that are context-dependent — only suspicious when
// the caller's context is NOT a coding/shell task. The hook adapter
// passes a context hint; the scanner respects it.
const CONTEXT_SENSITIVE_PATTERNS = [
  // Fenced shell blocks in summary contexts
  { pattern: /```(bash|sh|powershell|cmd|pwsh)\s*\n[\s\S]{20,}?\n```/i, tag: 'shell_block' },
  // curl/wget with an attacker-reachable URL in summary contexts
  { pattern: /\b(curl|wget|Invoke-WebRequest|fetch)\b[^\n]{0,200}\bhttps?:\/\/[^\s"']+/i, tag: 'http_call' },
];

const SUMMARY_CONTEXTS = new Set(['summary', 'translate', 'rephrase', 'analyze', 'document', 'email', 'web_fetch']);

// Weight contributions per signal category
const WEIGHTS = {
  system_prompt_leak: 9,   // one hit = block-candidate
  role_drift: 7,
  execution_ack: 7,
  context_sensitive: 5,    // only counts when context is a summary-type
};

// Verdict thresholds (tunable via config)
const DEFAULT_THRESHOLDS = {
  warn: 4,
  redact: 7,
  block: 12,
};

// ── Heuristics ────────────────────────────────────────────────────

function countConsecutiveImperatives(output) {
  // Detect three+ adjacent lines that look like system-prompt directives
  // ("You are...", "You must...", "Never...", "Always..."). This is a
  // structural signal that the model dumped a directive list, which
  // happens when it leaks its system prompt.
  const lines = output.split('\n').map((l) => l.trim()).filter(Boolean);
  const imperativeRx = /^(you\s+(are|must|should|will|cannot|may\s+not)|never|always)\b/i;
  let run = 0;
  let maxRun = 0;
  for (const line of lines) {
    if (imperativeRx.test(line) && line.length < 250) {
      run++;
      if (run > maxRun) maxRun = run;
    } else {
      run = 0;
    }
  }
  return maxRun;
}

function scoreMatches(output, patterns) {
  let hits = 0;
  const matched = [];
  const matchedPatterns = [];
  for (const rx of patterns) {
    if (rx.test(output)) {
      hits++;
      matched.push(rx.source.slice(0, 80));
      matchedPatterns.push(rx);
    }
  }
  return { hits, matched, matchedPatterns };
}

// ── Redaction ─────────────────────────────────────────────────────

function redactSections(output, findings) {
  // Replace matched regions with a placeholder but keep the surrounding
  // text. Intentionally simple — redacting individual spans risks
  // leaving attack artifacts stitched into surrounding prose. We cut at
  // paragraph boundaries (double newline) and drop any paragraph whose
  // text matches any finding pattern.
  const paragraphs = output.split(/\n\s*\n/);
  const patterns = findings.map((f) => f.pattern).filter(Boolean);
  const kept = [];
  let redacted = 0;
  for (const p of paragraphs) {
    const hit = patterns.some((rx) => rx.test(p));
    if (hit) {
      redacted++;
      kept.push('[redacted by agent-content-shield: matched compliance pattern]');
    } else {
      kept.push(p);
    }
  }
  return { redactedOutput: kept.join('\n\n'), redactedParagraphs: redacted };
}

// ── Main entrypoint ───────────────────────────────────────────────

/**
 * Scan a model output for post-flight attack signals.
 *
 * @param {string} output  The model response to check.
 * @param {object} [opts]
 * @param {string} [opts.context] Caller context hint — 'summary',
 *   'translate', 'document', 'email', 'web_fetch', 'code', 'shell',
 *   etc. Affects context-sensitive pattern weighting.
 * @param {object} [opts.thresholds] Override warn/redact/block scores.
 * @returns {{
 *   verdict: 'PASS'|'WARN'|'REDACT'|'BLOCK',
 *   score: number,
 *   signals: Array<{category: string, weight: number, matched: string[], pattern?: RegExp}>,
 *   redactedOutput?: string,
 *   reason?: string,
 * }}
 */
function scanOutput(output, opts = {}) {
  if (typeof output !== 'string' || output.length === 0) {
    return { verdict: 'PASS', score: 0, signals: [] };
  }
  const thresholds = { ...DEFAULT_THRESHOLDS, ...(opts.thresholds || {}) };
  const context = (opts.context || '').toLowerCase();
  const isSummaryContext = SUMMARY_CONTEXTS.has(context);

  const signals = [];
  let score = 0;

  // System prompt leak
  const leaks = scoreMatches(output, SYSTEM_PROMPT_LEAK_PATTERNS);
  if (leaks.hits > 0) {
    const w = WEIGHTS.system_prompt_leak * leaks.hits;
    score += w;
    signals.push({
      category: 'system_prompt_leak',
      weight: w,
      matched: leaks.matched,
      patterns: leaks.matchedPatterns,
    });
  }
  // Structural imperative-run leak
  const runLen = countConsecutiveImperatives(output);
  if (runLen >= 3) {
    const w = WEIGHTS.system_prompt_leak;
    score += w;
    signals.push({
      category: 'system_prompt_leak',
      weight: w,
      matched: [`imperative_run_length=${runLen}`],
    });
  }

  // Role drift
  const drift = scoreMatches(output, ROLE_DRIFT_PATTERNS);
  if (drift.hits > 0) {
    const w = WEIGHTS.role_drift * drift.hits;
    score += w;
    signals.push({ category: 'role_drift', weight: w, matched: drift.matched, patterns: drift.matchedPatterns });
  }

  // Execution acknowledgment
  const ack = scoreMatches(output, EXECUTION_ACK_PATTERNS);
  if (ack.hits > 0) {
    const w = WEIGHTS.execution_ack * ack.hits;
    score += w;
    signals.push({ category: 'execution_ack', weight: w, matched: ack.matched, patterns: ack.matchedPatterns });
  }

  // Context-sensitive — only counts in summary-ish contexts
  if (isSummaryContext) {
    for (const { pattern, tag } of CONTEXT_SENSITIVE_PATTERNS) {
      if (pattern.test(output)) {
        const w = WEIGHTS.context_sensitive;
        score += w;
        signals.push({ category: `context_${tag}`, weight: w, matched: [tag], patterns: [pattern] });
      }
    }
  }

  // Verdict
  let verdict = 'PASS';
  if (score >= thresholds.block) verdict = 'BLOCK';
  else if (score >= thresholds.redact) verdict = 'REDACT';
  else if (score >= thresholds.warn) verdict = 'WARN';

  if (verdict === 'PASS') {
    return { verdict, score, signals };
  }

  const result = {
    verdict,
    score,
    signals,
    reason: signals.map((s) => s.category).join(', '),
  };

  if (verdict === 'REDACT') {
    const allPatterns = [];
    for (const s of signals) {
      if (Array.isArray(s.patterns)) allPatterns.push(...s.patterns);
    }
    const { redactedOutput, redactedParagraphs } = redactSections(
      output,
      allPatterns.map((p) => ({ pattern: p })),
    );
    result.redactedOutput = redactedOutput;
    result.redactedParagraphs = redactedParagraphs;
  }
  if (verdict === 'BLOCK') {
    result.redactedOutput =
      '[blocked by agent-content-shield: high-confidence post-flight compliance signal — see signals for details]';
  }

  return result;
}

module.exports = {
  scanOutput,
  DEFAULT_THRESHOLDS,
  WEIGHTS,
  // Exposed for tests / tuning
  SYSTEM_PROMPT_LEAK_PATTERNS,
  ROLE_DRIFT_PATTERNS,
  EXECUTION_ACK_PATTERNS,
  CONTEXT_SENSITIVE_PATTERNS,
  SUMMARY_CONTEXTS,
};
