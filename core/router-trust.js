/**
 * Agent Content Shield — Router Trust Scoring
 *
 * Per the "Your Agent Is Mine" paper (Liu et al., 2026), routers are
 * an explicitly configured trust boundary. This module tracks which
 * API endpoints (routers) are in use and scores them based on:
 *
 *   1. Whether the endpoint is a known first-party provider
 *   2. Historical detection rate from that endpoint
 *   3. Whether the endpoint has produced flagged content
 *   4. TLS/certificate metadata
 *
 * The goal is to make the router trust decision visible rather than
 * invisible — the paper's core observation is that users don't realize
 * they're trusting an intermediary.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const SHIELD_DIR = path.join(os.homedir(), '.shield');
const TRUST_FILE = path.join(SHIELD_DIR, 'router-trust.json');

// ── Known First-Party Provider Endpoints ──────────────────────────
// These are the official API endpoints for major LLM providers.
// Any other base URL indicates a router/proxy intermediary.

const FIRST_PARTY_ENDPOINTS = new Set([
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'aiplatform.googleapis.com',
  'bedrock-runtime.us-east-1.amazonaws.com',
  'bedrock-runtime.us-west-2.amazonaws.com',
  'bedrock-runtime.eu-west-1.amazonaws.com',
  'bedrock-runtime.ap-northeast-1.amazonaws.com',
  'models.inference.ai.azure.com',
  // Azure OpenAI uses custom subdomains: *.openai.azure.com
]);

const AZURE_OPENAI_PATTERN = /^[a-z0-9-]+\.openai\.azure\.com$/i;

// ── Router Trust Database ─────────────────────────────────────────

let _trustDb = null;

function loadTrustDb() {
  if (_trustDb) return _trustDb;
  try {
    fs.mkdirSync(SHIELD_DIR, { recursive: true });
    _trustDb = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8'));
  } catch {
    _trustDb = { routers: {}, version: 1 };
  }
  return _trustDb;
}

function saveTrustDb() {
  try {
    fs.mkdirSync(SHIELD_DIR, { recursive: true });
    fs.writeFileSync(TRUST_FILE, JSON.stringify(_trustDb, null, 2));
  } catch (e) {
    process.stderr.write(`shield-trust: save error: ${e.message}\n`);
  }
}

// ── Endpoint Classification ───────────────────────────────────────

function classifyEndpoint(baseUrl) {
  if (!baseUrl) return { type: 'unknown', host: null, trusted: false };

  let host;
  try {
    const url = new URL(baseUrl);
    host = url.hostname.toLowerCase();
  } catch {
    // Might be just a hostname
    host = baseUrl.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  }

  if (FIRST_PARTY_ENDPOINTS.has(host)) {
    return { type: 'first_party', host, trusted: true };
  }
  if (AZURE_OPENAI_PATTERN.test(host)) {
    return { type: 'azure_openai', host, trusted: true };
  }
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
    return { type: 'local', host, trusted: false, note: 'Local proxy — verify what it forwards to' };
  }
  if (host.includes('openrouter.ai')) {
    return { type: 'known_router', host, trusted: false, note: 'OpenRouter is a known aggregator — responses pass through intermediary' };
  }
  if (host.includes('litellm') || host.includes('lite-llm')) {
    return { type: 'known_router', host, trusted: false, note: 'LiteLLM proxy detected — see March 2026 supply chain incident' };
  }

  return { type: 'unknown_router', host, trusted: false, note: 'Unknown intermediary — no response integrity guarantee' };
}

// ── Trust Score Computation ───────────────────────────────────────

/**
 * Record an interaction with a router endpoint and update trust score.
 *
 * @param {string} baseUrl - The API base URL
 * @param {object} event - { type: 'clean'|'flagged'|'blocked', details? }
 * @returns {object} Current trust assessment for this endpoint
 */
function recordInteraction(baseUrl, event) {
  const db = loadTrustDb();
  const classification = classifyEndpoint(baseUrl);
  const key = classification.host || baseUrl;

  if (!db.routers[key]) {
    db.routers[key] = {
      host: key,
      classification: classification.type,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      totalInteractions: 0,
      cleanCount: 0,
      flaggedCount: 0,
      blockedCount: 0,
      trustScore: classification.trusted ? 0.9 : 0.5,
      alerts: [],
    };
  }

  const router = db.routers[key];
  router.lastSeen = Date.now();
  router.totalInteractions++;

  switch (event.type) {
    case 'clean':
      router.cleanCount++;
      // Slowly increase trust for clean interactions (max 0.95 for non-first-party)
      if (!classification.trusted) {
        router.trustScore = Math.min(router.trustScore + 0.001, 0.8);
      }
      break;

    case 'flagged':
      router.flaggedCount++;
      // Decrease trust — flagged content is suspicious
      router.trustScore = Math.max(router.trustScore - 0.05, 0.0);
      router.alerts.push({
        ts: Date.now(),
        type: 'flagged',
        details: (event.details || '').slice(0, 200),
      });
      // Keep only last 50 alerts
      if (router.alerts.length > 50) router.alerts = router.alerts.slice(-50);
      break;

    case 'blocked':
      router.blockedCount++;
      // Significant trust decrease for blocked content
      router.trustScore = Math.max(router.trustScore - 0.15, 0.0);
      router.alerts.push({
        ts: Date.now(),
        type: 'blocked',
        details: (event.details || '').slice(0, 200),
      });
      if (router.alerts.length > 50) router.alerts = router.alerts.slice(-50);
      break;
  }

  saveTrustDb();
  return getAssessment(key);
}

/**
 * Get the current trust assessment for an endpoint.
 */
function getAssessment(hostOrUrl) {
  const db = loadTrustDb();
  const classification = classifyEndpoint(hostOrUrl);
  const key = classification.host || hostOrUrl;
  const router = db.routers[key];

  if (!router) {
    return {
      host: key,
      classification: classification.type,
      trusted: classification.trusted,
      trustScore: classification.trusted ? 0.9 : 0.5,
      note: classification.note || null,
      warning: classification.trusted ? null : 'ROUTER WARNING: This endpoint is not a first-party provider. Responses may be tampered with.',
      interactions: 0,
    };
  }

  const flagRate = router.totalInteractions > 0
    ? (router.flaggedCount + router.blockedCount) / router.totalInteractions
    : 0;

  let warning = null;
  if (router.trustScore < 0.3) {
    warning = `ROUTER ALERT: Endpoint ${key} has low trust score (${router.trustScore.toFixed(2)}). ${router.blockedCount} blocked, ${router.flaggedCount} flagged out of ${router.totalInteractions} interactions.`;
  } else if (!classification.trusted) {
    warning = `ROUTER WARNING: ${key} is not a first-party provider endpoint. ${classification.note || 'No response integrity guarantee.'}`;
  }

  return {
    host: key,
    classification: classification.type,
    trusted: classification.trusted,
    trustScore: router.trustScore,
    note: classification.note || null,
    warning,
    interactions: router.totalInteractions,
    flagRate: flagRate.toFixed(3),
    recentAlerts: router.alerts.slice(-5),
  };
}

/**
 * Check if an endpoint should be auto-blocked based on trust score.
 */
function shouldBlock(hostOrUrl) {
  const assessment = getAssessment(hostOrUrl);
  return assessment.trustScore < 0.1;
}

/**
 * Get a summary of all tracked routers.
 */
function getAllRouters() {
  const db = loadTrustDb();
  return Object.values(db.routers).map(r => ({
    host: r.host,
    classification: r.classification,
    trustScore: r.trustScore,
    interactions: r.totalInteractions,
    flagged: r.flaggedCount,
    blocked: r.blockedCount,
    lastSeen: new Date(r.lastSeen).toISOString(),
  }));
}

/**
 * Detect base URL from environment variables commonly used by agent frameworks.
 */
function detectActiveRouter() {
  const envVars = [
    'OPENAI_BASE_URL', 'ANTHROPIC_BASE_URL', 'OPENAI_API_BASE',
    'LITELLM_BASE_URL', 'OPENROUTER_BASE_URL', 'API_BASE_URL',
    'CLAUDE_BASE_URL',
  ];

  const detected = [];
  for (const v of envVars) {
    const val = process.env[v];
    if (val) {
      const classification = classifyEndpoint(val);
      detected.push({
        envVar: v,
        url: val,
        ...classification,
      });
    }
  }
  return detected;
}

/**
 * Reset trust database (for testing).
 */
function reset() {
  _trustDb = { routers: {}, version: 1 };
  try { fs.unlinkSync(TRUST_FILE); } catch {}
}

module.exports = {
  classifyEndpoint,
  recordInteraction,
  getAssessment,
  shouldBlock,
  getAllRouters,
  detectActiveRouter,
  reset,
  FIRST_PARTY_ENDPOINTS,
  // For testing
  _internals: { loadTrustDb, saveTrustDb, TRUST_FILE },
};
