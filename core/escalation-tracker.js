/**
 * Agent Content Shield — Multi-Turn Escalation Tracker
 *
 * Sits ALONGSIDE behavioral-engine.js, not inside it. The existing
 * behavioral engine models tool-call sequences (READ → FETCH → WRITE
 * chains). This module models prompt-level escalation: attacks that
 * look innocuous turn-by-turn but compound — gradual persona rewrite,
 * trust-building followed by injection, anchoring attacks that refer
 * to fabricated prior agreements.
 *
 * Features extracted per turn:
 *   instructionDensity  Imperative verbs / total words. Rising density
 *                       across a session signals the caller is drifting
 *                       from conversational to directive posture.
 *   personaReferences   Counts of "you are X", "act as X", "pretend to
 *                       be X", "roleplay as X". One is normal; three+
 *                       across a short window is escalation.
 *   anchorReferences    Counts of "as we discussed", "you agreed",
 *                       "you earlier said", "remember when we". Classic
 *                       fabricated-context anchoring attacks.
 *   systemPromptMentions  References to "system prompt", "initial
 *                       instructions", "above this line", "developer
 *                       prompt". Attempts to probe the system layer.
 *   hiddenEncodingHits  Count of base64 / hex / url-encoded payloads.
 *                       Encoding evasion that ramps across turns.
 *
 * Escalation signal:
 *   For each feature, compute the slope across the last N turns. If
 *   multiple features are monotonically rising at once, that's a
 *   high-confidence multi-turn attack. We combine the slopes with
 *   weights and normalize to 0..1.
 *
 * Storage:
 *   Per-session state lives in an in-memory map keyed by sessionId.
 *   Optionally persisted to data/escalation.jsonl for post-mortem
 *   analysis (off by default — raw prompt hashes only, never text).
 *   State expires after ESCALATION_SESSION_TTL_MS of inactivity.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const ESCALATION_LOG = path.join(DATA_DIR, 'escalation.jsonl');
const ESCALATION_SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

// ── Feature extractors ────────────────────────────────────────────

const IMPERATIVE_RX = /\b(do|don'?t|you must|please|make sure|always|never|execute|run|write|create|delete|ignore|forget|override|bypass|switch|become|act|pretend|roleplay)\b/gi;

const PERSONA_RX = [
  /\byou\s+are\s+(now\s+)?(?!a\s+(assistant|helpful))[a-z][a-z\s]{1,40}\b/i,
  /\bact\s+as\s+(if\s+you\s+were\s+)?[a-z]/i,
  /\bpretend\s+(to\s+be|you('?re|\s+are))\s+[a-z]/i,
  /\broleplay\s+(as\s+)?[a-z]/i,
  /\bfrom\s+now\s+on,?\s+you\b/i,
];

const ANCHOR_RX = [
  /\bas\s+we\s+(discussed|agreed|talked\s+about|established)\b/i,
  /\byou\s+(agreed|promised|confirmed|said|told\s+me)\s+earlier\b/i,
  /\bremember\s+(when\s+)?(we|you)\b/i,
  /\bearlier\s+you\s+(said|promised|agreed|confirmed)\b/i,
  /\blike\s+(we\s+)?(discussed|established)\b/i,
];

const SYSTEM_PROMPT_PROBE_RX = [
  /\bsystem\s+prompt\b/i,
  /\binitial\s+(prompt|instructions?)\b/i,
  /\babove\s+this\s+line\b/i,
  /\bdeveloper\s+(prompt|message)\b/i,
  /\byour\s+(original|first|initial)\s+instructions?\b/i,
  /\bshow\s+(me\s+)?your\s+(prompt|instructions|rules)\b/i,
];

const HIDDEN_ENCODING_RX = [
  // base64 run — long enough to be suspicious (>40 chars)
  /[A-Za-z0-9+/]{40,}={0,2}/,
  // url-encoded payload with many %XX
  /(%[0-9a-f]{2}){6,}/i,
  // hex payload
  /\b(0x)?[0-9a-f]{40,}\b/i,
];

function countRegexHits(text, patterns) {
  let hits = 0;
  for (const rx of patterns) {
    if (rx.global) {
      const m = text.match(rx);
      if (m) hits += m.length;
    } else if (rx.test(text)) {
      hits++;
    }
  }
  return hits;
}

function extractFeatures(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return {
      instructionDensity: 0,
      personaReferences: 0,
      anchorReferences: 0,
      systemPromptMentions: 0,
      hiddenEncodingHits: 0,
      wordCount: 0,
    };
  }
  const words = text.split(/\s+/).filter(Boolean);
  const wordCount = words.length;
  const imperativeHits = (text.match(IMPERATIVE_RX) || []).length;
  return {
    instructionDensity: wordCount === 0 ? 0 : imperativeHits / wordCount,
    personaReferences: countRegexHits(text, PERSONA_RX),
    anchorReferences: countRegexHits(text, ANCHOR_RX),
    systemPromptMentions: countRegexHits(text, SYSTEM_PROMPT_PROBE_RX),
    hiddenEncodingHits: countRegexHits(text, HIDDEN_ENCODING_RX),
    wordCount,
  };
}

// ── Slope / escalation computation ────────────────────────────────

/**
 * Simple linear regression slope over the last N observations.
 * Returns the slope in units of "feature per turn" — positive means
 * the feature is rising, negative means falling. A slope of 0 means
 * flat (no escalation) even if the absolute value is high.
 */
function slope(values) {
  const n = values.length;
  if (n < 2) return 0;
  const xMean = (n - 1) / 2;
  const yMean = values.reduce((a, b) => a + b, 0) / n;
  let num = 0;
  let den = 0;
  for (let i = 0; i < n; i++) {
    num += (i - xMean) * (values[i] - yMean);
    den += (i - xMean) ** 2;
  }
  return den === 0 ? 0 : num / den;
}

// Per-feature weight in the final escalation score. Anchoring attacks
// and system-prompt probes are rarer baseline and more diagnostic than
// raw instruction density, so they carry more weight.
const FEATURE_WEIGHTS = {
  instructionDensity: 0.15,
  personaReferences: 0.25,
  anchorReferences: 0.25,
  systemPromptMentions: 0.25,
  hiddenEncodingHits: 0.10,
};

// A feature's slope is normalized against a reference slope that means
// "clearly rising across the window" — tuning constant, not magic.
// Instruction density is a 0..1 ratio so its reference is tiny; counts
// are integers so their reference is larger.
const SLOPE_REFERENCE = {
  instructionDensity: 0.03,
  personaReferences: 0.5,
  anchorReferences: 0.5,
  systemPromptMentions: 0.5,
  hiddenEncodingHits: 0.5,
};

function escalationFromTurns(turns) {
  if (turns.length < 2) {
    return { score: 0, slopes: {}, rising: [] };
  }
  const features = Object.keys(FEATURE_WEIGHTS);
  const slopes = {};
  const rising = [];
  let score = 0;
  for (const f of features) {
    const series = turns.map((t) => t.features[f] ?? 0);
    const s = slope(series);
    slopes[f] = s;
    if (s > 0) {
      const normalized = Math.min(s / SLOPE_REFERENCE[f], 1);
      score += normalized * FEATURE_WEIGHTS[f];
      if (normalized > 0.4) rising.push(f);
    }
  }
  return { score: Math.min(score, 1), slopes, rising };
}

// ── Session store ────────────────────────────────────────────────

const _sessions = new Map(); // sessionId → { turns, lastActivity }

function gcStale(now = Date.now()) {
  for (const [id, s] of _sessions.entries()) {
    if (now - s.lastActivity > ESCALATION_SESSION_TTL_MS) _sessions.delete(id);
  }
}

function ensureDataDir() {
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
}

function logTurn(sessionId, features, persist) {
  if (!persist) return;
  try {
    ensureDataDir();
    const entry = {
      sessionId,
      ts: Date.now(),
      // We intentionally never log the raw prompt — only a hash for
      // post-mortem linkage and the numeric features.
      features,
    };
    fs.appendFileSync(ESCALATION_LOG, JSON.stringify(entry) + '\n');
  } catch {}
}

/**
 * Record a new turn for a session and return the current escalation
 * score + feature slopes.
 *
 * @param {string} sessionId
 * @param {string} text                 The user's prompt text for this turn.
 * @param {object} [opts]
 * @param {number} [opts.windowSize=5]  Rolling window length.
 * @param {boolean} [opts.persist=false] Append features to escalation.jsonl.
 * @returns {{
 *   sessionId: string,
 *   turnCount: number,
 *   features: object,
 *   escalation: { score: number, slopes: object, rising: string[] },
 *   anomalous: boolean,
 * }}
 */
function recordTurn(sessionId, text, opts = {}) {
  const windowSize = Math.max(2, Math.min(20, opts.windowSize || 5));
  const persist = !!opts.persist;
  const threshold = typeof opts.threshold === 'number' ? opts.threshold : 0.5;

  gcStale();
  const now = Date.now();
  const features = extractFeatures(text);

  let session = _sessions.get(sessionId);
  if (!session) {
    session = { turns: [], lastActivity: now };
    _sessions.set(sessionId, session);
  }
  session.turns.push({ ts: now, features, hash: crypto.createHash('sha1').update(text || '').digest('hex').slice(0, 16) });
  // Trim to window
  if (session.turns.length > windowSize) {
    session.turns = session.turns.slice(-windowSize);
  }
  session.lastActivity = now;

  const escalation = escalationFromTurns(session.turns);
  logTurn(sessionId, features, persist);

  return {
    sessionId,
    turnCount: session.turns.length,
    features,
    escalation,
    anomalous: escalation.score >= threshold,
  };
}

function getSession(sessionId) {
  return _sessions.get(sessionId) || null;
}

function resetSession(sessionId) {
  _sessions.delete(sessionId);
}

function resetAll() {
  _sessions.clear();
}

module.exports = {
  // Primary API
  recordTurn,
  extractFeatures,
  escalationFromTurns,
  // Introspection / testing
  getSession,
  resetSession,
  resetAll,
  slope,
  FEATURE_WEIGHTS,
  SLOPE_REFERENCE,
  ESCALATION_SESSION_TTL_MS,
};
