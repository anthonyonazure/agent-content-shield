/**
 * Agent Content Shield — Learning Pipeline: Database Layer
 *
 * SQLite-backed persistent store for detection analytics, feedback,
 * reputation, A/B tests, and health metrics. Zero external dependencies
 * (uses node:sqlite available in Node 22+, falls back to better-sqlite3).
 *
 * Schema is auto-migrated on first access.
 */

const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.SHIELD_DB_PATH ||
  path.join(__dirname, '..', 'data', 'shield-learning.db');

let _db = null;

function getDb() {
  if (_db) return _db;

  // Ensure data directory exists
  const dir = path.dirname(DB_PATH);
  fs.mkdirSync(dir, { recursive: true });

  // Try Node 22+ built-in sqlite, fall back to better-sqlite3
  let Database;
  try {
    // Node 22.5+ has node:sqlite (experimental)
    Database = require('better-sqlite3');
  } catch {
    throw new Error(
      'SQLite not available. Install better-sqlite3: npm install better-sqlite3'
    );
  }

  _db = new Database(DB_PATH);
  _db.pragma('journal_mode = WAL');
  _db.pragma('foreign_keys = ON');

  migrate(_db);
  return _db;
}

// ═══════════════════════════════════════════════════════════════════════
// SCHEMA MIGRATIONS
// ═══════════════════════════════════════════════════════════════════════

const MIGRATIONS = [
  // v1: Core detection log (parsed from JSONL into queryable form)
  `CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,                      -- ISO 8601
    hook TEXT NOT NULL,                    -- pre-fetch | post-content | pre-memory | pre-bash | pre-write
    tool TEXT,                             -- tool_name that triggered
    source TEXT,                           -- URL or file path
    layer TEXT,                            -- regex | semantic | canary | fatal_error
    max_severity INTEGER DEFAULT 0,       -- 0-10
    detection_count INTEGER DEFAULT 0,
    findings TEXT,                         -- JSON array of detector names
    confidence REAL,                       -- semantic layer confidence 0-1
    latency_ms INTEGER,                   -- scan duration
    command TEXT,                          -- for bash hooks
    url TEXT,                              -- for fetch hooks
    reason TEXT,                           -- block reason
    error TEXT,                            -- for fatal_error entries
    raw_json TEXT                          -- original JSONL line for replay
  )`,

  `CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(ts)`,
  `CREATE INDEX IF NOT EXISTS idx_detections_hook ON detections(hook)`,
  `CREATE INDEX IF NOT EXISTS idx_detections_layer ON detections(layer)`,
  `CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(max_severity)`,

  // v2: User feedback (false positive / false negative signals)
  `CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    detection_id INTEGER,                 -- FK to detections.id (null if FN)
    feedback_type TEXT NOT NULL,           -- false_positive | false_negative | confirmed_true
    hook TEXT,
    detector TEXT,                         -- which detector was wrong
    severity INTEGER,
    user_action TEXT,                      -- override | report | confirm
    content_hash TEXT,                     -- SHA-256 of scanned content (for dedup)
    notes TEXT,
    FOREIGN KEY (detection_id) REFERENCES detections(id)
  )`,

  `CREATE INDEX IF NOT EXISTS idx_feedback_detector ON feedback(detector)`,
  `CREATE INDEX IF NOT EXISTS idx_feedback_type ON feedback(feedback_type)`,

  // v3: Domain/URL reputation
  `CREATE TABLE IF NOT EXISTS url_reputation (
    domain TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    total_scans INTEGER DEFAULT 0,
    total_detections INTEGER DEFAULT 0,
    total_blocks INTEGER DEFAULT 0,
    false_positive_count INTEGER DEFAULT 0,
    reputation_score REAL DEFAULT 0.5,    -- 0=trusted, 1=malicious
    auto_block INTEGER DEFAULT 0,         -- 1 = auto-block enabled
    max_severity_seen INTEGER DEFAULT 0,
    attack_categories TEXT,               -- JSON array of categories seen
    notes TEXT
  )`,

  `CREATE INDEX IF NOT EXISTS idx_reputation_score ON url_reputation(reputation_score)`,

  // v4: A/B test shadow rules
  `CREATE TABLE IF NOT EXISTS ab_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    rule_type TEXT NOT NULL,               -- regex | threshold | signature
    rule_config TEXT NOT NULL,             -- JSON config for the rule
    status TEXT DEFAULT 'shadow',          -- shadow | promoted | retired
    created_at TEXT NOT NULL,
    promoted_at TEXT,
    total_evaluations INTEGER DEFAULT 0,
    true_positives INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    true_negatives INTEGER DEFAULT 0,
    false_negatives INTEGER DEFAULT 0
  )`,

  // v5: A/B test per-evaluation log
  `CREATE TABLE IF NOT EXISTS ab_evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    would_fire INTEGER NOT NULL,          -- 1 if shadow rule would have flagged
    production_fired INTEGER NOT NULL,    -- 1 if production rule fired
    content_hash TEXT,
    hook TEXT,
    FOREIGN KEY (test_id) REFERENCES ab_tests(id)
  )`,

  // v6: Threshold tuning history
  `CREATE TABLE IF NOT EXISTS threshold_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    detector TEXT NOT NULL,
    old_threshold REAL NOT NULL,
    new_threshold REAL NOT NULL,
    reason TEXT,                           -- bayesian_update | manual | ab_promotion
    fp_rate REAL,                          -- false positive rate at time of change
    tp_rate REAL,                          -- true positive rate
    sample_count INTEGER                   -- how many samples informed this
  )`,

  // v7: Health metrics (time-series, 1-minute buckets)
  `CREATE TABLE IF NOT EXISTS health_metrics (
    ts TEXT NOT NULL,                      -- ISO 8601, truncated to minute
    scan_count INTEGER DEFAULT 0,
    block_count INTEGER DEFAULT 0,
    warn_count INTEGER DEFAULT 0,
    pass_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    latency_p50_ms REAL,
    latency_p95_ms REAL,
    latency_p99_ms REAL,
    ollama_available INTEGER,             -- 1 or 0
    degraded_mode INTEGER,                -- 1 if in degraded mode
    queue_depth INTEGER DEFAULT 0,
    PRIMARY KEY (ts)
  )`,

  // v8: IDF calibration runs
  `CREATE TABLE IF NOT EXISTS idf_calibrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    benign_corpus_size INTEGER,
    injection_corpus_size INTEGER,
    term_count INTEGER,
    calibration_config TEXT,              -- JSON: smoothing, min_df, etc.
    result_hash TEXT,                     -- SHA-256 of produced weights
    notes TEXT
  )`,

  // v9: Threat feed tracking
  `CREATE TABLE IF NOT EXISTS threat_feeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_name TEXT NOT NULL UNIQUE,
    feed_url TEXT,
    last_fetched TEXT,
    last_hash TEXT,                       -- content hash for change detection
    patterns_added INTEGER DEFAULT 0,
    seeds_added INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active'          -- active | paused | error
  )`,
];

function migrate(db) {
  db.exec('BEGIN');
  try {
    for (const sql of MIGRATIONS) {
      db.exec(sql);
    }
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function close() {
  if (_db) {
    _db.close();
    _db = null;
  }
}

module.exports = { getDb, close, DB_PATH, MIGRATIONS };
