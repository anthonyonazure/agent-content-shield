/**
 * Agent Content Shield — Learning Pipeline: Content Reputation Database
 *
 * Component 4: Tracks domains/URLs that have served malicious content.
 * Builds a local reputation score. First offense = flag, repeat offender
 * = auto-block. Persists across sessions via SQLite.
 *
 * Reputation scoring:
 *   - Starts at 0.5 (neutral)
 *   - Each detection increases by severity_weight * decay_factor
 *   - Each clean scan slightly decreases (rehabilitation)
 *   - At 0.8+ = auto-flag, at 0.95+ = auto-block
 *   - False positives rapidly rehabilitate the score
 *
 * Integration: Called from hooks.js at scan time (both pre-fetch and post-content).
 */

const { getDb } = require('./db');

// Reputation thresholds
const FLAG_THRESHOLD = 0.8;     // Reputation score at which to flag
const BLOCK_THRESHOLD = 0.95;   // Reputation score at which to auto-block
const REHAB_RATE = 0.005;       // Score decrease per clean scan
const FP_REHAB_RATE = 0.15;     // Score decrease per confirmed false positive
const SEVERITY_WEIGHT = {       // How much each severity level increases score
  1: 0.01, 2: 0.02, 3: 0.03, 4: 0.05, 5: 0.08,
  6: 0.12, 7: 0.18, 8: 0.25, 9: 0.35, 10: 0.50,
};
const DECAY_HALFLIFE_DAYS = 30; // Older offenses decay in weight

// ═══════════════════════════════════════════════════════════════════════
// DOMAIN EXTRACTION
// ═══════════════════════════════════════════════════════════════════════

function extractDomain(urlOrSource) {
  if (!urlOrSource) return null;
  try {
    const url = new URL(urlOrSource);
    return url.hostname.toLowerCase();
  } catch {
    // Try extracting from partial URLs
    const match = urlOrSource.match(/(?:https?:\/\/)?([^\/\s:]+)/);
    return match ? match[1].toLowerCase() : null;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// REPUTATION QUERIES
// ═══════════════════════════════════════════════════════════════════════

let _stmts = null;
function getStmts() {
  if (_stmts) return _stmts;
  const db = getDb();
  _stmts = {
    get: db.prepare('SELECT * FROM url_reputation WHERE domain = ?'),
    upsertScan: db.prepare(`
      INSERT INTO url_reputation (domain, first_seen, last_seen, total_scans, reputation_score)
      VALUES (@domain, @now, @now, 1, 0.5)
      ON CONFLICT(domain) DO UPDATE SET
        last_seen = @now,
        total_scans = total_scans + 1
    `),
    recordDetection: db.prepare(`
      UPDATE url_reputation SET
        total_detections = total_detections + 1,
        last_seen = @now,
        max_severity_seen = MAX(max_severity_seen, @severity),
        reputation_score = MIN(1.0, reputation_score + @delta),
        auto_block = CASE WHEN MIN(1.0, reputation_score + @delta) >= ${BLOCK_THRESHOLD} THEN 1 ELSE auto_block END,
        attack_categories = @categories
      WHERE domain = @domain
    `),
    recordBlock: db.prepare(`
      UPDATE url_reputation SET
        total_blocks = total_blocks + 1,
        last_seen = @now
      WHERE domain = @domain
    `),
    recordClean: db.prepare(`
      UPDATE url_reputation SET
        reputation_score = MAX(0.0, reputation_score - ${REHAB_RATE}),
        auto_block = CASE WHEN MAX(0.0, reputation_score - ${REHAB_RATE}) < ${BLOCK_THRESHOLD} THEN 0 ELSE auto_block END
      WHERE domain = @domain
    `),
    recordFP: db.prepare(`
      UPDATE url_reputation SET
        false_positive_count = false_positive_count + 1,
        reputation_score = MAX(0.0, reputation_score - ${FP_REHAB_RATE}),
        auto_block = CASE WHEN MAX(0.0, reputation_score - ${FP_REHAB_RATE}) < ${BLOCK_THRESHOLD} THEN 0 ELSE auto_block END
      WHERE domain = @domain
    `),
    topMalicious: db.prepare(`
      SELECT * FROM url_reputation
      WHERE reputation_score >= ${FLAG_THRESHOLD}
      ORDER BY reputation_score DESC
      LIMIT 50
    `),
    allDomains: db.prepare(`
      SELECT * FROM url_reputation
      ORDER BY reputation_score DESC
      LIMIT 200
    `),
  };
  return _stmts;
}

// ═══════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════

/**
 * Check the reputation of a domain before fetching.
 * Returns { domain, score, action: 'allow'|'flag'|'block', stats }
 */
function checkReputation(urlOrSource) {
  const domain = extractDomain(urlOrSource);
  if (!domain) return { domain: null, score: 0.5, action: 'allow' };

  const stmts = getStmts();

  const record = stmts.get.get(domain);
  if (!record) return { domain, score: 0.5, action: 'allow' };

  let action = 'allow';
  if (record.auto_block || record.reputation_score >= BLOCK_THRESHOLD) {
    action = 'block';
  } else if (record.reputation_score >= FLAG_THRESHOLD) {
    action = 'flag';
  }

  return {
    domain,
    score: record.reputation_score,
    action,
    stats: {
      total_scans: record.total_scans,
      total_detections: record.total_detections,
      total_blocks: record.total_blocks,
      false_positives: record.false_positive_count,
      max_severity: record.max_severity_seen,
      first_seen: record.first_seen,
      last_seen: record.last_seen,
    },
  };
}

/**
 * Record that a detection occurred for a domain.
 * Updates reputation score based on severity with time-decay.
 */
function recordDetection(urlOrSource, severity, categories = []) {
  const domain = extractDomain(urlOrSource);
  if (!domain) return;

  const stmts = getStmts();
  const now = new Date().toISOString();

  // Ensure domain exists
  stmts.upsertScan.run({ domain, now });

  // Compute reputation delta based on severity with time-decay
  let delta = SEVERITY_WEIGHT[severity] || 0.05;

  // Apply time-decay: older offenses carry less weight
  const record_pre = stmts.get.get(domain);
  if (record_pre?.first_seen) {
    const daysSinceFirst = (Date.now() - new Date(record_pre.first_seen).getTime()) / (1000 * 60 * 60 * 24);
    const decayFactor = Math.pow(0.5, daysSinceFirst / DECAY_HALFLIFE_DAYS);
    delta *= decayFactor;
  }

  // Get existing categories and merge
  const record = stmts.get.get(domain);
  let existingCategories = [];
  try { existingCategories = JSON.parse(record?.attack_categories || '[]'); } catch {}
  const allCategories = [...new Set([...existingCategories, ...categories])];

  stmts.recordDetection.run({
    domain,
    now,
    severity,
    delta,
    categories: JSON.stringify(allCategories),
  });
}

/**
 * Record that a domain was blocked.
 */
function recordBlock(urlOrSource) {
  const domain = extractDomain(urlOrSource);
  if (!domain) return;
  const stmts = getStmts();
  stmts.recordBlock.run({ domain, now: new Date().toISOString() });
}

/**
 * Record a clean scan — slightly rehabilitates the domain.
 */
function recordCleanScan(urlOrSource) {
  const domain = extractDomain(urlOrSource);
  if (!domain) return;
  const stmts = getStmts();
  const now = new Date().toISOString();
  // Ensure domain exists (upsert tracks scan count)
  stmts.upsertScan.run({ domain, now });
  stmts.recordClean.run({ domain });
}

/**
 * Record a false positive — rapidly rehabilitates the domain.
 */
function recordFalsePositive(urlOrSource) {
  const domain = extractDomain(urlOrSource);
  if (!domain) return;
  const stmts = getStmts();
  stmts.recordFP.run({ domain });
}

/**
 * Get all domains flagged or blocked.
 */
function getMaliciousDomains() {
  return getStmts().topMalicious.all();
}

/**
 * Get full reputation report.
 */
function getReputationReport() {
  const stmts = getStmts();
  const all = stmts.allDomains.all();
  const db = getDb();

  const summary = db.prepare(`
    SELECT
      COUNT(*) as total_domains,
      SUM(CASE WHEN reputation_score >= ${BLOCK_THRESHOLD} THEN 1 ELSE 0 END) as auto_blocked,
      SUM(CASE WHEN reputation_score >= ${FLAG_THRESHOLD} AND reputation_score < ${BLOCK_THRESHOLD} THEN 1 ELSE 0 END) as flagged,
      SUM(CASE WHEN reputation_score < ${FLAG_THRESHOLD} THEN 1 ELSE 0 END) as clean,
      SUM(total_detections) as total_detections,
      SUM(false_positive_count) as total_false_positives
    FROM url_reputation
  `).get();

  return { summary, domains: all };
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const cmd = process.argv[2];
  if (cmd === 'report') {
    console.log(JSON.stringify(getReputationReport(), null, 2));
  } else if (cmd === 'check') {
    const url = process.argv[3];
    if (!url) { console.error('Usage: reputation check <url>'); process.exit(1); }
    console.log(JSON.stringify(checkReputation(url), null, 2));
  } else if (cmd === 'malicious') {
    console.log(JSON.stringify(getMaliciousDomains(), null, 2));
  } else {
    console.log('Usage: node pipeline/reputation.js [report|check <url>|malicious]');
  }
}

module.exports = {
  checkReputation,
  recordDetection,
  recordBlock,
  recordCleanScan,
  recordFalsePositive,
  getMaliciousDomains,
  getReputationReport,
  extractDomain,
  FLAG_THRESHOLD,
  BLOCK_THRESHOLD,
};
