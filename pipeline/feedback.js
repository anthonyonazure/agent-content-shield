/**
 * Agent Content Shield — Learning Pipeline: Feedback Loop
 *
 * Component 6: Captures signals about shield accuracy from user behavior.
 *
 * Signal sources:
 *   - User override: Shield blocks/warns, user continues anyway = potential FP
 *   - User report:   User says "that was bad" after content passed = FN
 *   - User confirm:  User acknowledges a detection was correct = TP
 *   - Implicit:      Content blocked, no override for 30s = assumed TP
 *
 * Integration points:
 *   - hooks.js: After every block/warn decision, log the detection + outcome
 *   - CLI:      shield feedback fp <detection-id>  — mark as false positive
 *   - CLI:      shield feedback fn <content-hash>   — mark as false negative
 *   - Auto:     After N overrides of the same detector, auto-flag for review
 *
 * The feedback data feeds into:
 *   - adaptive-thresholds.js (Bayesian updating)
 *   - reputation.js (domain rehabilitation on FP)
 *   - ab-testing.js (ground truth for shadow rules)
 */

const crypto = require('crypto');
const { getDb } = require('./db');

// ═══════════════════════════════════════════════════════════════════════
// FEEDBACK RECORDING
// ═══════════════════════════════════════════════════════════════════════

let _stmts = null;
function getStmts() {
  if (_stmts) return _stmts;
  const db = getDb();
  _stmts = {
    insertFeedback: db.prepare(`
      INSERT INTO feedback
        (ts, detection_id, feedback_type, hook, detector, severity, user_action, content_hash, notes)
      VALUES
        (@ts, @detectionId, @feedbackType, @hook, @detector, @severity, @userAction, @contentHash, @notes)
    `),
    getDetection: db.prepare(`SELECT * FROM detections WHERE id = ?`),
    recentByDetector: db.prepare(`
      SELECT
        detector,
        feedback_type,
        COUNT(*) as count
      FROM feedback
      WHERE ts > datetime('now', '-7 days')
      GROUP BY detector, feedback_type
      ORDER BY count DESC
    `),
    overrideCount: db.prepare(`
      SELECT detector, COUNT(*) as override_count
      FROM feedback
      WHERE feedback_type = 'false_positive'
        AND user_action = 'override'
        AND ts > datetime('now', '-24 hours')
      GROUP BY detector
      HAVING override_count >= @threshold
    `),
    feedbackSummary: db.prepare(`
      SELECT
        detector,
        SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as fp,
        SUM(CASE WHEN feedback_type = 'false_negative' THEN 1 ELSE 0 END) as fn,
        SUM(CASE WHEN feedback_type = 'confirmed_true' THEN 1 ELSE 0 END) as tp,
        COUNT(*) as total,
        ROUND(
          CAST(SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) AS REAL)
          / NULLIF(COUNT(*), 0), 4
        ) as fp_rate
      FROM feedback
      GROUP BY detector
      ORDER BY fp_rate DESC
    `),
  };
  return _stmts;
}

/**
 * Record a false positive: shield flagged it, but it was actually benign.
 *
 * @param {Object} opts
 * @param {number} opts.detectionId - ID from detections table (optional)
 * @param {string} opts.hook - Which hook fired
 * @param {string} opts.detector - Which detector was wrong
 * @param {number} opts.severity - What severity was assigned
 * @param {string} opts.contentHash - SHA-256 of the content (for dedup)
 * @param {string} opts.userAction - 'override' | 'report' | 'manual'
 * @param {string} opts.notes - Optional human note
 */
function recordFalsePositive(opts) {
  return getStmts().insertFeedback.run({
    ts: new Date().toISOString(),
    detectionId: opts.detectionId || null,
    feedbackType: 'false_positive',
    hook: opts.hook || null,
    detector: opts.detector || null,
    severity: opts.severity || null,
    userAction: opts.userAction || 'manual',
    contentHash: opts.contentHash || null,
    notes: opts.notes || null,
  });
}

/**
 * Record a false negative: content passed the shield but was actually malicious.
 */
function recordFalseNegative(opts) {
  return getStmts().insertFeedback.run({
    ts: new Date().toISOString(),
    detectionId: null,
    feedbackType: 'false_negative',
    hook: opts.hook || null,
    detector: opts.detector || null,
    severity: opts.severity || null,
    userAction: opts.userAction || 'report',
    contentHash: opts.contentHash || null,
    notes: opts.notes || null,
  });
}

/**
 * Record a confirmed true positive: shield was right to flag this.
 */
function recordTruePositive(opts) {
  return getStmts().insertFeedback.run({
    ts: new Date().toISOString(),
    detectionId: opts.detectionId || null,
    feedbackType: 'confirmed_true',
    hook: opts.hook || null,
    detector: opts.detector || null,
    severity: opts.severity || null,
    userAction: opts.userAction || 'confirm',
    contentHash: opts.contentHash || null,
    notes: opts.notes || null,
  });
}

// ═══════════════════════════════════════════════════════════════════════
// CONTENT HASHING — Used to deduplicate feedback and link to A/B tests
// ═══════════════════════════════════════════════════════════════════════

function hashContent(content) {
  return crypto.createHash('sha256')
    .update(content || '')
    .digest('hex');
}

// ═══════════════════════════════════════════════════════════════════════
// OVERRIDE TRACKING — Detect when a detector is consistently wrong
// ═══════════════════════════════════════════════════════════════════════

/**
 * Check if any detectors have been overridden too many times recently.
 * Returns detectors that need human review of their thresholds.
 */
function getOverriddenDetectors(threshold = 5) {
  return getStmts().overrideCount.all({ threshold });
}

/**
 * Get the full feedback summary by detector.
 */
function getFeedbackSummary() {
  return getStmts().feedbackSummary.all();
}

/**
 * Get recent feedback activity.
 */
function getRecentFeedback() {
  return getStmts().recentByDetector.all();
}

// ═══════════════════════════════════════════════════════════════════════
// AUTO-FEEDBACK FROM HOOK BEHAVIOR
//
// Called by hooks.js after a decision. If the hook blocked/warned and
// the user's next action is to continue (override), we automatically
// record a false_positive signal. This is the primary feedback source
// for most users who won't use the manual CLI.
// ═══════════════════════════════════════════════════════════════════════

/**
 * Record that a detection occurred and is pending user action.
 * Returns a feedback token that the hook can pass back if the user overrides.
 */
function createPendingFeedback(detectionData) {
  const token = crypto.randomBytes(16).toString('hex');
  const contentHash = hashContent(detectionData.content);

  // Store in a lightweight in-memory map (no need to persist pending items)
  if (!createPendingFeedback._pending) createPendingFeedback._pending = new Map();
  createPendingFeedback._pending.set(token, {
    ...detectionData,
    contentHash,
    ts: Date.now(),
  });

  // Clean old pending items (>5 min)
  const cutoff = Date.now() - 300000;
  for (const [k, v] of createPendingFeedback._pending) {
    if (v.ts < cutoff) createPendingFeedback._pending.delete(k);
  }

  return { token, contentHash };
}

/**
 * User overrode a detection — record as false_positive automatically.
 */
function resolveOverride(token) {
  const pending = createPendingFeedback._pending?.get(token);
  if (!pending) return { resolved: false, reason: 'token_expired_or_invalid' };

  recordFalsePositive({
    detectionId: pending.detectionId,
    hook: pending.hook,
    detector: pending.detector,
    severity: pending.severity,
    contentHash: pending.contentHash,
    userAction: 'override',
  });

  createPendingFeedback._pending.delete(token);
  return { resolved: true, feedbackType: 'false_positive' };
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const cmd = process.argv[2];
  switch (cmd) {
    case 'fp': {
      const detectionId = parseInt(process.argv[3]);
      if (isNaN(detectionId)) {
        console.error('Usage: feedback fp <detection-id> [notes]');
        process.exit(1);
      }
      const stmts = getStmts();
      const detection = stmts.getDetection.get(detectionId);
      if (!detection) {
        console.error(`Detection #${detectionId} not found`);
        process.exit(1);
      }
      recordFalsePositive({
        detectionId,
        hook: detection.hook,
        detector: detection.findings ? JSON.parse(detection.findings)[0] : null,
        severity: detection.max_severity,
        userAction: 'manual',
        notes: process.argv.slice(4).join(' ') || null,
      });
      console.log(`Recorded false positive for detection #${detectionId}`);
      break;
    }
    case 'fn': {
      const notes = process.argv.slice(3).join(' ');
      recordFalseNegative({
        userAction: 'report',
        notes: notes || 'Manually reported false negative',
      });
      console.log('Recorded false negative report');
      break;
    }
    case 'summary':
      console.log(JSON.stringify(getFeedbackSummary(), null, 2));
      break;
    case 'overrides':
      console.log(JSON.stringify(getOverriddenDetectors(), null, 2));
      break;
    default:
      console.log('Usage: node pipeline/feedback.js [fp <id>|fn [notes]|summary|overrides]');
  }
}

module.exports = {
  recordFalsePositive,
  recordFalseNegative,
  recordTruePositive,
  hashContent,
  getOverriddenDetectors,
  getFeedbackSummary,
  getRecentFeedback,
  createPendingFeedback,
  resolveOverride,
};
