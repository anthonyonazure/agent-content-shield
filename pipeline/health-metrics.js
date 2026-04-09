/**
 * Agent Content Shield — Learning Pipeline: Shield Health Metrics
 *
 * Component 7: Compute and expose real-time health metrics:
 *   - Scan volume per second/minute
 *   - p50/p95/p99 latency
 *   - Detection rate (% of scans that fire)
 *   - Ollama availability %
 *   - Degraded-mode %
 *   - Queue depth
 *
 * Two modes:
 *   - Collector: In-process, called by hooks.js on every scan
 *   - Reporter:  CLI or API, reads from health_metrics table
 */

const { getDb } = require('./db');

// ═══════════════════════════════════════════════════════════════════════
// IN-MEMORY COLLECTOR
// Accumulates metrics in memory, flushes to SQLite every minute.
// ═══════════════════════════════════════════════════════════════════════

class MetricsCollector {
  constructor() {
    this.currentBucket = null;
    this.counts = { scan: 0, block: 0, warn: 0, pass: 0, error: 0 };
    this.latencies = [];
    this.ollamaChecks = [];   // Array of booleans
    this.degradedChecks = []; // Array of booleans
    this.queueDepth = 0;
    this._flushTimer = null;
  }

  /**
   * Get the current minute bucket key (ISO 8601 truncated to minute).
   */
  _bucketKey() {
    const now = new Date();
    now.setSeconds(0, 0);
    return now.toISOString();
  }

  /**
   * Start the auto-flush timer (call once at init).
   */
  start() {
    if (this._flushTimer) return;
    this.currentBucket = this._bucketKey();
    this._flushTimer = setInterval(() => this._maybeFlush(), 60000);
    // Don't prevent process exit
    if (this._flushTimer.unref) this._flushTimer.unref();
  }

  /**
   * Stop the collector and flush remaining data.
   */
  stop() {
    if (this._flushTimer) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
    this._flush();
  }

  /**
   * Record a scan result. Called by hooks.js after every decision.
   */
  recordScan({ decision, latencyMs, ollamaAvailable, degradedMode, queueDepth }) {
    const bucket = this._bucketKey();
    if (bucket !== this.currentBucket) {
      this._flush();
      this.currentBucket = bucket;
    }

    this.counts.scan++;
    if (decision === 'block') this.counts.block++;
    else if (decision === 'warn') this.counts.warn++;
    else if (decision === 'error') this.counts.error++;
    else this.counts.pass++;

    if (latencyMs != null) this.latencies.push(latencyMs);
    if (ollamaAvailable != null) this.ollamaChecks.push(ollamaAvailable);
    if (degradedMode != null) this.degradedChecks.push(degradedMode);
    if (queueDepth != null) this.queueDepth = queueDepth;
  }

  /**
   * Check if bucket rolled over, flush if needed.
   */
  _maybeFlush() {
    const bucket = this._bucketKey();
    if (bucket !== this.currentBucket && this.counts.scan > 0) {
      this._flush();
      this.currentBucket = bucket;
    }
  }

  /**
   * Compute percentiles and write to SQLite.
   */
  _flush() {
    if (this.counts.scan === 0) return;

    const sorted = [...this.latencies].sort((a, b) => a - b);
    const p = (pct) => {
      if (sorted.length === 0) return null;
      const idx = Math.ceil(sorted.length * pct / 100) - 1;
      return sorted[Math.max(0, idx)];
    };

    const ollamaAvail = this.ollamaChecks.length > 0
      ? this.ollamaChecks.filter(Boolean).length / this.ollamaChecks.length > 0.5 ? 1 : 0
      : null;
    const degraded = this.degradedChecks.length > 0
      ? this.degradedChecks.filter(Boolean).length / this.degradedChecks.length > 0.5 ? 1 : 0
      : null;

    try {
      const db = getDb();
      db.prepare(`
        INSERT OR REPLACE INTO health_metrics
          (ts, scan_count, block_count, warn_count, pass_count, error_count,
           latency_p50_ms, latency_p95_ms, latency_p99_ms,
           ollama_available, degraded_mode, queue_depth)
        VALUES
          (@ts, @scan, @block, @warn, @pass, @error,
           @p50, @p95, @p99,
           @ollama, @degraded, @queue)
      `).run({
        ts: this.currentBucket,
        scan: this.counts.scan,
        block: this.counts.block,
        warn: this.counts.warn,
        pass: this.counts.pass,
        error: this.counts.error,
        p50: p(50),
        p95: p(95),
        p99: p(99),
        ollama: ollamaAvail,
        degraded,
        queue: this.queueDepth,
      });
    } catch (e) {
      process.stderr.write(`metrics flush error: ${e.message}\n`);
    }

    // Reset accumulators
    this.counts = { scan: 0, block: 0, warn: 0, pass: 0, error: 0 };
    this.latencies = [];
    this.ollamaChecks = [];
    this.degradedChecks = [];
  }
}

// Singleton instance
const collector = new MetricsCollector();

// ═══════════════════════════════════════════════════════════════════════
// REPORTER — Query historical metrics
// ═══════════════════════════════════════════════════════════════════════

/**
 * Get health metrics for the last N minutes.
 */
function getRecentMetrics(minutes = 60) {
  const db = getDb();
  return db.prepare(`
    SELECT * FROM health_metrics
    ORDER BY ts DESC
    LIMIT ?
  `).all(minutes);
}

/**
 * Compute aggregate health report.
 */
function getHealthReport(hours = 24) {
  const db = getDb();

  const cutoff = new Date(Date.now() - hours * 3600000).toISOString();

  const summary = db.prepare(`
    SELECT
      SUM(scan_count) as total_scans,
      SUM(block_count) as total_blocks,
      SUM(warn_count) as total_warns,
      SUM(pass_count) as total_passes,
      SUM(error_count) as total_errors,
      ROUND(AVG(latency_p50_ms), 1) as avg_p50_ms,
      ROUND(AVG(latency_p95_ms), 1) as avg_p95_ms,
      ROUND(MAX(latency_p99_ms), 1) as max_p99_ms,
      ROUND(
        CAST(SUM(CASE WHEN ollama_available = 1 THEN 1 ELSE 0 END) AS REAL)
        / NULLIF(COUNT(*), 0) * 100, 1
      ) as ollama_uptime_pct,
      ROUND(
        CAST(SUM(CASE WHEN degraded_mode = 1 THEN 1 ELSE 0 END) AS REAL)
        / NULLIF(COUNT(*), 0) * 100, 1
      ) as degraded_pct,
      MAX(queue_depth) as max_queue_depth,
      COUNT(*) as total_minutes
    FROM health_metrics
    WHERE ts >= ?
  `).get(cutoff);

  // Detection rate
  const totalScans = summary?.total_scans || 0;
  const totalDetections = (summary?.total_blocks || 0) + (summary?.total_warns || 0);
  const detectionRate = totalScans > 0
    ? parseFloat((totalDetections / totalScans * 100).toFixed(2))
    : 0;

  // Scans per second (average)
  const totalMinutes = summary?.total_minutes || 1;
  const scansPerSecond = parseFloat((totalScans / (totalMinutes * 60)).toFixed(2));

  // Peak throughput
  const peak = db.prepare(`
    SELECT MAX(scan_count) as peak_per_minute FROM health_metrics WHERE ts >= ?
  `).get(cutoff);

  return {
    period: `${hours}h`,
    totalScans,
    totalDetections,
    detectionRate,
    scansPerSecond,
    peakPerMinute: peak?.peak_per_minute || 0,
    latency: {
      p50: summary?.avg_p50_ms,
      p95: summary?.avg_p95_ms,
      p99: summary?.max_p99_ms,
    },
    availability: {
      ollama_uptime_pct: summary?.ollama_uptime_pct || 0,
      degraded_pct: summary?.degraded_pct || 0,
      maxQueueDepth: summary?.max_queue_depth || 0,
    },
    errors: summary?.total_errors || 0,
    generated: new Date().toISOString(),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const cmd = process.argv[2];
  if (cmd === 'report') {
    const hours = parseInt(process.argv[3]) || 24;
    console.log(JSON.stringify(getHealthReport(hours), null, 2));
  } else if (cmd === 'recent') {
    const minutes = parseInt(process.argv[3]) || 60;
    console.log(JSON.stringify(getRecentMetrics(minutes), null, 2));
  } else {
    console.log('Usage: node pipeline/health-metrics.js [report [hours]|recent [minutes]]');
  }
}

module.exports = {
  collector,
  MetricsCollector,
  getRecentMetrics,
  getHealthReport,
};
