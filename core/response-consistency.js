/**
 * Agent Content Shield — Response Consistency Monitor (AC-1.b Defense)
 *
 * Defends against conditional delivery attacks described in
 * "Your Agent Is Mine" (Liu et al., 2026). AC-1.b routers behave
 * honestly for the first N requests, then inject payloads once they
 * detect YOLO mode, specific tools, or warm-up thresholds.
 *
 * Detection strategy:
 *   1. Build per-session response fingerprints (domain distribution,
 *      command structure, argument entropy, tool-call patterns)
 *   2. Detect statistical drift after warm-up period using CUSUM
 *   3. Flag sessions where response characteristics shift suddenly
 *
 * This catches routers that "go malicious" mid-session — the behavioral
 * engine tracks tool sequences, this module tracks response content drift.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, '..', 'data');
const CONSISTENCY_FILE = path.join(DATA_DIR, 'response-consistency.json');

// ── Session Response Profile ──────────────────────────────────────

class ResponseProfile {
  constructor() {
    this.totalResponses = 0;
    this.domainCounts = {};     // domain → count (for URL-containing responses)
    this.toolCallCounts = {};   // tool_name → count
    this.avgArgLength = 0;      // running average of argument JSON length
    this.argLengthVariance = 0; // running variance
    this.shellCommandPatterns = {}; // command prefix → count
    this.entropyHistory = [];   // per-response entropy scores
    this.driftScore = 0;        // CUSUM drift accumulator
    this.lastResponseHash = null;
    this.windowStart = Date.now();
  }
}

// ── Singleton Session State ───────────────────────────────────────

let _sessions = {};
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

function getSession(sessionId) {
  const now = Date.now();
  // Cleanup expired sessions
  for (const [id, s] of Object.entries(_sessions)) {
    if (now - s.profile.windowStart > SESSION_TIMEOUT_MS) {
      delete _sessions[id];
    }
  }

  if (!_sessions[sessionId]) {
    _sessions[sessionId] = {
      profile: new ResponseProfile(),
      alerts: [],
    };
  }
  return _sessions[sessionId];
}

// ── Feature Extraction ────────────────────────────────────────────

function extractDomains(text) {
  const rx = /https?:\/\/([^\/\s'"]+)/gi;
  const domains = [];
  let m;
  while ((m = rx.exec(text)) !== null) {
    domains.push(m[1].toLowerCase().split(':')[0]);
  }
  return domains;
}

function extractCommandPrefix(command) {
  if (!command) return null;
  // First meaningful token: curl, wget, pip, npm, git, etc.
  const tokens = command.trim().split(/\s+/);
  for (const t of tokens) {
    if (t && !t.startsWith('-') && !t.startsWith('$') && !t.startsWith('(')) {
      return t.replace(/['"]/g, '').toLowerCase();
    }
  }
  return null;
}

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let ent = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) ent -= p * Math.log2(p);
  }
  return ent;
}

// ── CUSUM Drift Detection ─────────────────────────────────────────
// Cumulative Sum (CUSUM) detects persistent shifts in a signal.
// We track deviation from the session's running mean entropy.

const CUSUM_THRESHOLD = 3.0;   // Standard deviations before alert
const CUSUM_DRIFT_K = 0.5;    // Slack parameter
const MIN_WARM_UP = 5;        // Minimum responses before drift detection active

function updateCusum(profile, newEntropy) {
  profile.entropyHistory.push(newEntropy);

  if (profile.entropyHistory.length < MIN_WARM_UP) return 0;

  // Compute running mean and std of entropy
  const history = profile.entropyHistory;
  const mean = history.reduce((a, b) => a + b, 0) / history.length;
  const variance = history.reduce((a, b) => a + (b - mean) ** 2, 0) / history.length;
  const std = Math.sqrt(variance) || 0.1;

  // Normalized deviation
  const z = (newEntropy - mean) / std;

  // CUSUM accumulator — detects persistent upward shift
  profile.driftScore = Math.max(0, profile.driftScore + z - CUSUM_DRIFT_K);

  return profile.driftScore;
}

// ── Domain Distribution Shift ─────────────────────────────────────

function domainShiftScore(profile, newDomains) {
  if (profile.totalResponses < MIN_WARM_UP || newDomains.length === 0) return 0;

  let novelDomains = 0;
  for (const d of newDomains) {
    if (!profile.domainCounts[d]) novelDomains++;
  }

  // If >50% of domains in this response are novel to the session, flag it
  const novelRatio = novelDomains / newDomains.length;

  // Weight by how established the session is
  const sessionMaturity = Math.min(profile.totalResponses / 20, 1.0);

  return novelRatio * sessionMaturity;
}

// ── Command Pattern Shift ─────────────────────────────────────────

function commandShiftScore(profile, command) {
  if (!command || profile.totalResponses < MIN_WARM_UP) return 0;

  const prefix = extractCommandPrefix(command);
  if (!prefix) return 0;

  const total = Object.values(profile.shellCommandPatterns).reduce((a, b) => a + b, 0);
  if (total < 3) return 0;

  // If this command prefix has never appeared and session is mature
  if (!profile.shellCommandPatterns[prefix]) {
    const maturity = Math.min(profile.totalResponses / 15, 1.0);
    // High-risk prefixes get extra weight
    const highRisk = ['curl', 'wget', 'bash', 'sh', 'python', 'node', 'eval', 'exec'];
    const riskMultiplier = highRisk.includes(prefix) ? 1.5 : 1.0;
    return maturity * riskMultiplier * 0.5;
  }

  return 0;
}

// ── Argument Length Anomaly ────────────────────────────────────────

function argLengthAnomaly(profile, argLength) {
  if (profile.totalResponses < MIN_WARM_UP) return 0;

  const mean = profile.avgArgLength;
  const std = Math.sqrt(profile.argLengthVariance) || 1;

  // Z-score of current argument length
  const z = Math.abs(argLength - mean) / std;

  // Only flag extreme outliers (>3 sigma)
  return z > 3 ? Math.min((z - 3) * 0.3, 1.0) : 0;
}

// ── Main Recording & Scoring ──────────────────────────────────────

/**
 * Record a tool-call response and check for consistency drift.
 * Call this for every tool-call response the agent receives.
 *
 * @param {string} sessionId - Current session identifier
 * @param {object} toolCall - { name, arguments (string or object) }
 * @param {string} rawResponse - Raw response text/JSON from provider
 * @returns {{ drift: boolean, score: number, details: object }}
 */
function recordAndCheck(sessionId, toolCall, rawResponse) {
  const session = getSession(sessionId);
  const profile = session.profile;

  const toolName = toolCall?.name || '';
  const args = typeof toolCall?.arguments === 'string'
    ? toolCall.arguments
    : JSON.stringify(toolCall?.arguments || '');
  const argLength = args.length;
  const responseText = typeof rawResponse === 'string'
    ? rawResponse : JSON.stringify(rawResponse || '');

  // Extract features
  const domains = extractDomains(args + ' ' + responseText);
  const entropy = shannonEntropy(args);
  const command = toolName === 'Bash' ? (toolCall?.arguments?.command || args) : null;

  // Update profile
  profile.totalResponses++;
  for (const d of domains) {
    profile.domainCounts[d] = (profile.domainCounts[d] || 0) + 1;
  }
  profile.toolCallCounts[toolName] = (profile.toolCallCounts[toolName] || 0) + 1;

  if (command) {
    const prefix = extractCommandPrefix(command);
    if (prefix) profile.shellCommandPatterns[prefix] = (profile.shellCommandPatterns[prefix] || 0) + 1;
  }

  // Update running average and variance (Welford's algorithm)
  const n = profile.totalResponses;
  const oldMean = profile.avgArgLength;
  profile.avgArgLength = oldMean + (argLength - oldMean) / n;
  profile.argLengthVariance = profile.argLengthVariance + (argLength - oldMean) * (argLength - profile.avgArgLength);
  if (n > 1) profile.argLengthVariance /= (n - 1);

  profile.lastResponseHash = crypto.createHash('sha256').update(responseText).digest('hex').slice(0, 16);

  // Compute drift signals
  const cusumScore = updateCusum(profile, entropy);
  const domainDrift = domainShiftScore(profile, domains);
  const cmdDrift = commandShiftScore(profile, command);
  const argAnomaly = argLengthAnomaly(profile, argLength);

  // Composite drift score (weighted)
  const compositeScore =
    (cusumScore / CUSUM_THRESHOLD) * 0.35 +
    domainDrift * 0.30 +
    cmdDrift * 0.20 +
    argAnomaly * 0.15;

  const drift = compositeScore > 0.6 && profile.totalResponses >= MIN_WARM_UP;

  const result = {
    drift,
    score: Math.min(compositeScore, 1.0),
    responseNumber: profile.totalResponses,
    details: {
      cusumScore: cusumScore.toFixed(3),
      domainDrift: domainDrift.toFixed(3),
      commandDrift: cmdDrift.toFixed(3),
      argAnomaly: argAnomaly.toFixed(3),
      entropy: entropy.toFixed(3),
      novelDomains: domains.filter(d => !profile.domainCounts[d] || profile.domainCounts[d] === 1).length,
      sessionAge: profile.totalResponses,
    },
  };

  if (drift) {
    session.alerts.push({
      ts: Date.now(),
      responseNumber: profile.totalResponses,
      score: compositeScore,
      toolCall: toolName,
    });
  }

  return result;
}

/**
 * Get the current session's consistency summary.
 */
function getSessionSummary(sessionId) {
  const session = _sessions[sessionId];
  if (!session) return null;

  return {
    totalResponses: session.profile.totalResponses,
    driftScore: session.profile.driftScore,
    alerts: session.alerts.length,
    topDomains: Object.entries(session.profile.domainCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5),
    topTools: Object.entries(session.profile.toolCallCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5),
  };
}

/**
 * Reset all sessions (for testing).
 */
function reset() {
  _sessions = {};
}

module.exports = {
  recordAndCheck,
  getSessionSummary,
  reset,
  // For testing
  _internals: {
    ResponseProfile,
    extractDomains,
    extractCommandPrefix,
    shannonEntropy,
    updateCusum,
    domainShiftScore,
    commandShiftScore,
    getSession,
    MIN_WARM_UP,
    CUSUM_THRESHOLD,
  },
};
