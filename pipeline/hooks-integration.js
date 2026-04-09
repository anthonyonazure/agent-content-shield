/**
 * Agent Content Shield — Learning Pipeline: Hooks Integration Layer
 *
 * This module provides drop-in functions that hooks.js calls to wire the
 * learning pipeline into every scan. Gracefully degrades if SQLite is
 * not available (the shield continues to work, just without learning).
 *
 * Integration points in hooks.js:
 *   1. After logDetection()    -> learn.recordDetection(data)
 *   2. After respond({allow})  -> learn.recordCleanScan(source)
 *   3. Pre-fetch URL check     -> learn.checkReputation(url)
 *   4. Post-scan               -> learn.evaluateShadow(text, fired)
 *   5. Every scan              -> learn.recordMetrics({...})
 *   6. On block override       -> learn.recordOverride(token)
 */

let _initialized = false;
let _available = false;

// Lazy init — don't crash hooks.js if pipeline dependencies missing
function init() {
  if (_initialized) return _available;
  _initialized = true;
  try {
    // Test that better-sqlite3 is available
    require('./db').getDb();
    _available = true;

    // Start health metrics collector
    const { collector } = require('./health-metrics');
    collector.start();
  } catch (e) {
    process.stderr.write(`shield-pipeline: not available (${e.message}). Learning disabled.\n`);
    _available = false;
  }
  return _available;
}

// ═══════════════════════════════════════════════════════════════════════
// PUBLIC API — Safe wrappers that no-op if pipeline unavailable
// ═══════════════════════════════════════════════════════════════════════

/**
 * Record a detection into the learning database and update reputation.
 * Called by hooks.js whenever logDetection() fires.
 */
function recordDetection(data) {
  if (!init()) return;
  try {
    const { ingestLine } = require('./ingest');
    ingestLine(JSON.stringify({ ts: new Date().toISOString(), ...data }));

    // Update domain reputation if there's a URL
    const source = data.url || data.source;
    if (source) {
      const rep = require('./reputation');
      rep.recordDetection(source, data.maxSev || data.severity || 5, data.findings || []);
      if (data.hook === 'pre-fetch' || data.maxSev >= 8) {
        rep.recordBlock(source);
      }
    }
  } catch {}
}

/**
 * Record a clean scan — used for domain reputation rehabilitation.
 */
function recordCleanScan(source) {
  if (!init()) return;
  try {
    if (source) {
      require('./reputation').recordCleanScan(source);
    }
  } catch {}
}

/**
 * Check domain reputation before fetching.
 * Returns { action: 'allow'|'flag'|'block', score, domain }
 */
function checkReputation(url) {
  if (!init()) return { action: 'allow', score: 0.5 };
  try {
    return require('./reputation').checkReputation(url);
  } catch {
    return { action: 'allow', score: 0.5 };
  }
}

/**
 * Evaluate A/B shadow rules against scanned content.
 * Called after every production scan.
 */
function evaluateShadow(content, productionFired, hook) {
  if (!init()) return [];
  try {
    return require('./ab-testing').evaluateShadow(content, productionFired, hook);
  } catch {
    return [];
  }
}

/**
 * Record health metrics for this scan.
 */
function recordMetrics(data) {
  if (!init()) return;
  try {
    const { collector } = require('./health-metrics');
    collector.recordScan(data);
  } catch {}
}

/**
 * Create a pending feedback token when blocking/warning.
 * Returns { token, contentHash } for override tracking.
 */
function createFeedbackToken(detectionData) {
  if (!init()) return null;
  try {
    return require('./feedback').createPendingFeedback(detectionData);
  } catch {
    return null;
  }
}

/**
 * Resolve a user override — records as false positive feedback.
 */
function resolveOverride(token) {
  if (!init()) return null;
  try {
    return require('./feedback').resolveOverride(token);
  } catch {
    return null;
  }
}

/**
 * Check if pipeline is available and get status.
 */
function status() {
  if (!init()) return { available: false };
  try {
    const { getStatus } = require('./index');
    return { available: true, ...getStatus() };
  } catch {
    return { available: _available };
  }
}

module.exports = {
  init,
  recordDetection,
  recordCleanScan,
  checkReputation,
  evaluateShadow,
  recordMetrics,
  createFeedbackToken,
  resolveOverride,
  status,
};
