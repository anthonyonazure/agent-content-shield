/**
 * Agent Content Shield — Learning Pipeline: Detection Analytics Ingestion
 *
 * Component 1: Parses JSONL detection logs into the SQLite database.
 * Computes analytics: false positive rate by detector, mean detection latency
 * by layer, attack pattern frequency over time, most-targeted tools,
 * geographic origin of malicious URLs (via TLD heuristic).
 *
 * Can run as:
 *   - One-shot backfill:  node pipeline/ingest.js --backfill
 *   - Tail mode:          node pipeline/ingest.js --tail
 *   - Programmatic:       require('./ingest').ingestLine(jsonlLine)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getDb } = require('./db');

const LOG_DIR = path.join(__dirname, '..', 'logs');
const DETECTION_LOG = path.join(LOG_DIR, 'detections.jsonl');

// ═══════════════════════════════════════════════════════════════════════
// JSONL LINE PARSER — Normalizes the heterogeneous log format
// ═══════════════════════════════════════════════════════════════════════

function parseDetectionLine(line) {
  const raw = JSON.parse(line);

  return {
    ts: raw.ts || new Date().toISOString(),
    hook: raw.hook || 'unknown',
    tool: raw.tool || null,
    source: raw.source || null,
    layer: raw.layer || (raw.error ? 'fatal_error' : raw.confidence != null ? 'semantic' : 'regex'),
    max_severity: raw.maxSev || raw.severity || 0,
    detection_count: raw.detections || (raw.findings ? raw.findings.length : 0),
    findings: raw.findings ? JSON.stringify(raw.findings) : null,
    confidence: raw.confidence != null ? raw.confidence : null,
    latency_ms: raw.latencyMs || null,
    command: raw.command || null,
    url: raw.url || null,
    reason: raw.reason || null,
    error: raw.error || null,
    raw_json: line,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// DATABASE INSERTION
// ═══════════════════════════════════════════════════════════════════════

let _insertStmt = null;

function getInsertStmt() {
  if (_insertStmt) return _insertStmt;
  const db = getDb();
  _insertStmt = db.prepare(`
    INSERT INTO detections
      (ts, hook, tool, source, layer, max_severity, detection_count,
       findings, confidence, latency_ms, command, url, reason, error, raw_json)
    VALUES
      (@ts, @hook, @tool, @source, @layer, @max_severity, @detection_count,
       @findings, @confidence, @latency_ms, @command, @url, @reason, @error, @raw_json)
  `);
  return _insertStmt;
}

function ingestLine(line) {
  if (!line || !line.trim()) return null;
  try {
    const parsed = parseDetectionLine(line.trim());
    const stmt = getInsertStmt();
    const result = stmt.run(parsed);
    return result.lastInsertRowid;
  } catch (e) {
    process.stderr.write(`ingest error: ${e.message}\n`);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// BACKFILL — Import all existing JSONL logs
// ═══════════════════════════════════════════════════════════════════════

function backfill() {
  const db = getDb();
  const logFiles = [];

  // Find all detection log files (current + rotated)
  try {
    const files = fs.readdirSync(LOG_DIR);
    for (const f of files) {
      if (f.startsWith('detections') && f.endsWith('.jsonl')) {
        logFiles.push(path.join(LOG_DIR, f));
      }
    }
  } catch (e) {
    process.stderr.write(`backfill: cannot read log dir: ${e.message}\n`);
    return { imported: 0, errors: 0 };
  }

  logFiles.sort(); // Process oldest first

  let imported = 0;
  let errors = 0;

  // Check if we already have data (avoid double-import)
  const existingCount = db.prepare('SELECT COUNT(*) as cnt FROM detections').get().cnt;
  if (existingCount > 0) {
    process.stderr.write(`backfill: ${existingCount} records already exist. Use --force to re-import.\n`);
    if (!process.argv.includes('--force')) {
      return { imported: 0, errors: 0, skipped: true, existing: existingCount };
    }
    db.exec('DELETE FROM detections');
  }

  const insertMany = db.transaction((lines) => {
    for (const line of lines) {
      try {
        ingestLine(line);
        imported++;
      } catch {
        errors++;
      }
    }
  });

  for (const logFile of logFiles) {
    const content = fs.readFileSync(logFile, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    insertMany(lines);
    process.stderr.write(`backfill: ${logFile} — ${lines.length} lines\n`);
  }

  return { imported, errors };
}

// ═══════════════════════════════════════════════════════════════════════
// ANALYTICS QUERIES
// ═══════════════════════════════════════════════════════════════════════

function analytics() {
  const db = getDb();

  // False positive rate by detector (requires feedback data)
  const fpByDetector = db.prepare(`
    SELECT
      f.detector,
      COUNT(*) as total_feedback,
      SUM(CASE WHEN f.feedback_type = 'false_positive' THEN 1 ELSE 0 END) as fp_count,
      ROUND(
        CAST(SUM(CASE WHEN f.feedback_type = 'false_positive' THEN 1 ELSE 0 END) AS REAL)
        / NULLIF(COUNT(*), 0), 4
      ) as fp_rate
    FROM feedback f
    GROUP BY f.detector
    ORDER BY fp_rate DESC
  `).all();

  // Mean detection latency by layer
  const latencyByLayer = db.prepare(`
    SELECT
      layer,
      COUNT(*) as scan_count,
      ROUND(AVG(latency_ms), 1) as avg_latency_ms,
      MIN(latency_ms) as min_latency_ms,
      MAX(latency_ms) as max_latency_ms
    FROM detections
    WHERE latency_ms IS NOT NULL
    GROUP BY layer
  `).all();

  // Attack pattern frequency over time (daily buckets)
  const patternFrequency = db.prepare(`
    SELECT
      DATE(ts) as day,
      hook,
      COUNT(*) as count,
      MAX(max_severity) as max_sev
    FROM detections
    WHERE layer != 'fatal_error'
    GROUP BY DATE(ts), hook
    ORDER BY day DESC, count DESC
  `).all();

  // Most targeted tools
  const targetedTools = db.prepare(`
    SELECT
      tool,
      COUNT(*) as detection_count,
      ROUND(AVG(max_severity), 1) as avg_severity,
      MAX(max_severity) as max_severity
    FROM detections
    WHERE tool IS NOT NULL AND layer != 'fatal_error'
    GROUP BY tool
    ORDER BY detection_count DESC
    LIMIT 20
  `).all();

  // Domain frequency from URLs
  const domainFrequency = db.prepare(`
    SELECT
      url,
      COUNT(*) as block_count,
      MAX(max_severity) as max_sev,
      MIN(ts) as first_seen,
      MAX(ts) as last_seen
    FROM detections
    WHERE url IS NOT NULL
    GROUP BY url
    ORDER BY block_count DESC
    LIMIT 20
  `).all();

  // Detection volume over time
  const volumeByHour = db.prepare(`
    SELECT
      SUBSTR(ts, 1, 13) || ':00' as hour,
      COUNT(*) as total,
      SUM(CASE WHEN max_severity >= 7 THEN 1 ELSE 0 END) as high_sev,
      SUM(CASE WHEN layer = 'fatal_error' THEN 1 ELSE 0 END) as errors
    FROM detections
    GROUP BY SUBSTR(ts, 1, 13)
    ORDER BY hour DESC
    LIMIT 168
  `).all();

  // Detector effectiveness (which detectors fire most)
  const detectorHits = db.prepare(`
    SELECT
      json_each.value as detector,
      COUNT(*) as fire_count,
      ROUND(AVG(d.max_severity), 1) as avg_sev
    FROM detections d, json_each(d.findings)
    WHERE d.findings IS NOT NULL
    GROUP BY json_each.value
    ORDER BY fire_count DESC
  `).all();

  return {
    fpByDetector,
    latencyByLayer,
    patternFrequency,
    targetedTools,
    domainFrequency,
    volumeByHour,
    detectorHits,
    generated: new Date().toISOString(),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// TAIL MODE — Watch log file for new lines
// ═══════════════════════════════════════════════════════════════════════

function tailLog() {
  let lastSize = 0;
  try {
    lastSize = fs.statSync(DETECTION_LOG).size;
  } catch {}

  process.stderr.write(`tail: watching ${DETECTION_LOG} (starting at byte ${lastSize})\n`);

  const interval = setInterval(() => {
    try {
      const stats = fs.statSync(DETECTION_LOG);
      if (stats.size > lastSize) {
        const fd = fs.openSync(DETECTION_LOG, 'r');
        const buf = Buffer.alloc(stats.size - lastSize);
        fs.readSync(fd, buf, 0, buf.length, lastSize);
        fs.closeSync(fd);

        const newLines = buf.toString('utf-8').trim().split('\n').filter(Boolean);
        for (const line of newLines) {
          const id = ingestLine(line);
          if (id) process.stderr.write(`tail: ingested detection #${id}\n`);
        }
        lastSize = stats.size;
      }
    } catch (e) {
      process.stderr.write(`tail error: ${e.message}\n`);
    }
  }, 2000); // Poll every 2 seconds

  // Graceful shutdown
  process.on('SIGINT', () => { clearInterval(interval); process.exit(0); });
  process.on('SIGTERM', () => { clearInterval(interval); process.exit(0); });
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const cmd = process.argv[2];
  if (cmd === '--backfill' || cmd === 'backfill') {
    const result = backfill();
    console.log(JSON.stringify(result, null, 2));
  } else if (cmd === '--tail' || cmd === 'tail') {
    backfill(); // Catch up first
    tailLog();
  } else if (cmd === '--analytics' || cmd === 'analytics') {
    backfill();
    const report = analytics();
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log('Usage: node pipeline/ingest.js [backfill|tail|analytics]');
  }
}

module.exports = { ingestLine, backfill, analytics, parseDetectionLine };
