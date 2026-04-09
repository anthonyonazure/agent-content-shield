/**
 * Agent Content Shield — Learning Pipeline: Main Entry Point
 *
 * Exports all pipeline components for programmatic use.
 * Also serves as the CLI dispatcher for the full pipeline.
 *
 * Usage:
 *   node pipeline/index.js status          — Overall pipeline health
 *   node pipeline/index.js backfill        — Import JSONL logs into DB
 *   node pipeline/index.js analytics       — Run detection analytics
 *   node pipeline/index.js tune [--apply]  — Bayesian threshold tuning
 *   node pipeline/index.js reputation      — Domain reputation report
 *   node pipeline/index.js health [hours]  — Shield health metrics
 *   node pipeline/index.js feedback        — Feedback summary
 *   node pipeline/index.js calibrate ...   — IDF weight calibration
 *   node pipeline/index.js cycle           — Run full learning cycle
 */

const db = require('./db');
const ingest = require('./ingest');
const adaptive = require('./adaptive-thresholds');
const reputation = require('./reputation');
const ab = require('./ab-testing');
const feedback = require('./feedback');
const health = require('./health-metrics');
const threatFeeds = require('./threat-feeds');
const calibrate = require('./calibrate-idf');

// ═══════════════════════════════════════════════════════════════════════
// FULL LEARNING CYCLE
//
// Designed to run periodically (daily cron or manual trigger).
// 1. Ingest any new JSONL logs into SQLite
// 2. Compute detection analytics
// 3. Check for overridden detectors
// 4. Run Bayesian threshold tuning (dry run)
// 5. Evaluate A/B shadow tests
// 6. Generate health report
// ═══════════════════════════════════════════════════════════════════════

function runLearningCycle(opts = {}) {
  const dryRun = opts.dryRun !== false;
  const report = { ts: new Date().toISOString(), stages: {} };

  // Stage 1: Ingest new logs
  try {
    const ingestResult = ingest.backfill();
    report.stages.ingest = ingestResult;
  } catch (e) {
    report.stages.ingest = { error: e.message };
  }

  // Stage 2: Analytics
  try {
    const analyticsResult = ingest.analytics();
    report.stages.analytics = {
      detectorHits: analyticsResult.detectorHits?.length || 0,
      uniqueTools: analyticsResult.targetedTools?.length || 0,
      volumeHours: analyticsResult.volumeByHour?.length || 0,
    };
  } catch (e) {
    report.stages.analytics = { error: e.message };
  }

  // Stage 3: Check for overridden detectors
  try {
    const overrides = feedback.getOverriddenDetectors();
    report.stages.overrides = {
      count: overrides.length,
      detectors: overrides,
    };
  } catch (e) {
    report.stages.overrides = { error: e.message };
  }

  // Stage 4: Bayesian threshold tuning
  try {
    const adjustments = adaptive.computeAdjustments();
    if (adjustments.length > 0) {
      const results = adaptive.applyAdjustments(adjustments, dryRun);
      report.stages.tuning = {
        adjustments: results.length,
        dryRun,
        results,
      };
    } else {
      report.stages.tuning = { adjustments: 0, reason: 'no_adjustments_needed' };
    }
  } catch (e) {
    report.stages.tuning = { error: e.message };
  }

  // Stage 5: Evaluate A/B tests
  try {
    const activeTests = ab.getActiveTests();
    const testReports = [];
    for (const test of activeTests) {
      const analysis = ab.analyzeTest(test.name);
      testReports.push({
        name: test.name,
        evaluations: analysis.test?.totalEvaluations || 0,
        recommendation: analysis.recommendation,
        additionalFpRate: analysis.additionalFpRate,
      });
    }
    report.stages.abTests = {
      active: activeTests.length,
      tests: testReports,
    };
  } catch (e) {
    report.stages.abTests = { error: e.message };
  }

  // Stage 6: Health metrics
  try {
    const healthReport = health.getHealthReport(24);
    report.stages.health = healthReport;
  } catch (e) {
    report.stages.health = { error: e.message };
  }

  // Stage 7: Feedback summary
  try {
    const fbSummary = feedback.getFeedbackSummary();
    report.stages.feedback = {
      detectors: fbSummary.length,
      summary: fbSummary,
    };
  } catch (e) {
    report.stages.feedback = { error: e.message };
  }

  return report;
}

// ═══════════════════════════════════════════════════════════════════════
// PIPELINE STATUS
// ═══════════════════════════════════════════════════════════════════════

function getStatus() {
  try {
    const d = db.getDb();
    return {
      database: db.DB_PATH,
      tables: {
        detections: d.prepare('SELECT COUNT(*) as cnt FROM detections').get().cnt,
        feedback: d.prepare('SELECT COUNT(*) as cnt FROM feedback').get().cnt,
        url_reputation: d.prepare('SELECT COUNT(*) as cnt FROM url_reputation').get().cnt,
        ab_tests: d.prepare('SELECT COUNT(*) as cnt FROM ab_tests').get().cnt,
        health_metrics: d.prepare('SELECT COUNT(*) as cnt FROM health_metrics').get().cnt,
        threshold_history: d.prepare('SELECT COUNT(*) as cnt FROM threshold_history').get().cnt,
        idf_calibrations: d.prepare('SELECT COUNT(*) as cnt FROM idf_calibrations').get().cnt,
        threat_feeds: d.prepare('SELECT COUNT(*) as cnt FROM threat_feeds').get().cnt,
      },
      status: 'ok',
    };
  } catch (e) {
    return { status: 'error', error: e.message };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const cmd = process.argv[2];

  switch (cmd) {
    case 'status':
      console.log(JSON.stringify(getStatus(), null, 2));
      break;
    case 'backfill':
      console.log(JSON.stringify(ingest.backfill(), null, 2));
      break;
    case 'analytics':
      ingest.backfill();
      console.log(JSON.stringify(ingest.analytics(), null, 2));
      break;
    case 'tune':
      console.log(JSON.stringify(
        adaptive.applyAdjustments(
          adaptive.computeAdjustments(),
          !process.argv.includes('--apply')
        ), null, 2
      ));
      break;
    case 'reputation':
      console.log(JSON.stringify(reputation.getReputationReport(), null, 2));
      break;
    case 'health':
      console.log(JSON.stringify(health.getHealthReport(parseInt(process.argv[3]) || 24), null, 2));
      break;
    case 'feedback':
      console.log(JSON.stringify(feedback.getFeedbackSummary(), null, 2));
      break;
    case 'cycle':
      console.log(JSON.stringify(runLearningCycle({
        dryRun: !process.argv.includes('--apply'),
      }), null, 2));
      break;
    default:
      console.log(`
Agent Content Shield — Learning Pipeline

Usage: node pipeline/index.js <command>

Commands:
  status              Pipeline health and table counts
  backfill            Import JSONL logs into SQLite
  analytics           Detection analytics report
  tune [--apply]      Bayesian threshold tuning
  reputation          Domain reputation report
  health [hours]      Shield health metrics (default: 24h)
  feedback            Feedback summary by detector
  cycle [--apply]     Run full learning cycle

Sub-pipelines (run directly):
  node pipeline/ingest.js [backfill|tail|analytics]
  node pipeline/adaptive-thresholds.js [tune|history] [--apply]
  node pipeline/reputation.js [report|check <url>|malicious]
  node pipeline/ab-testing.js [list|analyze <name>|promote <name>]
  node pipeline/feedback.js [fp <id>|fn [notes]|summary|overrides]
  node pipeline/health-metrics.js [report [hours]|recent [minutes]]
  node pipeline/threat-feeds.js [ingest <file>|list|register <name> <url>]
  node pipeline/calibrate-idf.js [calibrate <benign-dir> [injection.jsonl]]
`);
  }
}

module.exports = {
  // Components
  db,
  ingest,
  adaptive,
  reputation,
  ab,
  feedback,
  health,
  threatFeeds,
  calibrate,
  // Orchestration
  runLearningCycle,
  getStatus,
};
