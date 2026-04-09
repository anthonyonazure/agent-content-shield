/**
 * Agent Content Shield — Learning Pipeline: Adaptive Threshold Tuning
 *
 * Component 2: Uses historical detection + feedback data to automatically
 * adjust detector thresholds via Bayesian updating.
 *
 * Logic:
 *   - If detector X fires 100 times but only 5 are confirmed true positives
 *     (user didn't override), lower its threshold.
 *   - If detector Y fires rarely but every firing is confirmed, raise sensitivity.
 *   - Uses Beta distribution conjugate prior: Beta(alpha, beta) where
 *     alpha = true positive count + prior, beta = false positive count + prior.
 *
 * Safety rails:
 *   - Never adjusts more than 15% per tuning cycle
 *   - Requires minimum 20 feedback samples before adjusting
 *   - Critical detectors (severity >= 9) have floor thresholds
 *   - All changes are logged to threshold_history table
 */

const { getDb } = require('./db');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const CONFIG_PATH = path.join(__dirname, '..', 'config', 'default.yaml');
const MIN_SAMPLES = 20;     // Minimum feedback samples before adjusting
const MAX_DELTA = 0.15;     // Maximum threshold change per cycle (15%)
const PRIOR_ALPHA = 2;      // Beta prior: assumes 2 true positives
const PRIOR_BETA = 2;       // Beta prior: assumes 2 false positives

// Critical detectors that should never go below these thresholds
const FLOOR_THRESHOLDS = {
  'reverse_shell': 0.1,
  'credential_harvesting': 0.2,
  'data_exfiltration': 0.2,
  'canary': 0.0,            // Canary should always fire
};

// Ceiling thresholds — these detectors should never become too insensitive
const CEILING_THRESHOLDS = {
  'semantic_injection': 0.95,
  'instruction_override': 0.90,
};

// ═══════════════════════════════════════════════════════════════════════
// BAYESIAN THRESHOLD COMPUTATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Compute the posterior mean of a Beta distribution.
 * Beta(alpha + tp, beta + fp) posterior mean = (alpha + tp) / (alpha + tp + beta + fp)
 *
 * This gives us P(true positive | data), which we use to adjust thresholds.
 * High P(TP) = detector is accurate, keep/lower threshold (more sensitive)
 * Low P(TP) = detector fires too much on false positives, raise threshold
 */
function betaPosteriorMean(truePositives, falsePositives) {
  const alpha = PRIOR_ALPHA + truePositives;
  const beta = PRIOR_BETA + falsePositives;
  return alpha / (alpha + beta);
}

/**
 * Compute the 95% credible interval lower bound.
 * Used to be conservative — only adjust when we're confident.
 * Uses normal approximation for Beta distribution.
 */
function betaCredibleLower(truePositives, falsePositives) {
  const alpha = PRIOR_ALPHA + truePositives;
  const beta = PRIOR_BETA + falsePositives;
  const mean = alpha / (alpha + beta);
  const variance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1));
  const stddev = Math.sqrt(variance);
  return mean - 1.96 * stddev; // 95% lower bound
}

// ═══════════════════════════════════════════════════════════════════════
// THRESHOLD TUNING ENGINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Analyze feedback data and compute recommended threshold adjustments.
 * Returns an array of { detector, currentThreshold, recommendedThreshold, reason, stats }
 */
function computeAdjustments() {
  const db = getDb();

  // Get feedback aggregated by detector
  const detectorStats = db.prepare(`
    SELECT
      detector,
      COUNT(*) as total_feedback,
      SUM(CASE WHEN feedback_type = 'false_positive' THEN 1 ELSE 0 END) as fp_count,
      SUM(CASE WHEN feedback_type = 'confirmed_true' THEN 1 ELSE 0 END) as tp_count,
      SUM(CASE WHEN feedback_type = 'false_negative' THEN 1 ELSE 0 END) as fn_count,
      AVG(severity) as avg_severity
    FROM feedback
    GROUP BY detector
    HAVING total_feedback >= ${MIN_SAMPLES}
  `).all();

  const adjustments = [];

  for (const stat of detectorStats) {
    const { detector, tp_count, fp_count, fn_count, total_feedback, avg_severity } = stat;

    // Posterior probability that a detection by this detector is a true positive
    const tpRate = betaPosteriorMean(tp_count, fp_count);
    const tpLower = betaCredibleLower(tp_count, fp_count);

    // Current FP rate
    const fpRate = fp_count / Math.max(1, tp_count + fp_count);

    // Determine adjustment direction
    let direction = 0; // -1 = more sensitive, 0 = no change, +1 = less sensitive
    let reason = '';

    if (fpRate > 0.5 && total_feedback >= MIN_SAMPLES * 2) {
      // More than half the detections are false positives — raise threshold
      direction = 1;
      reason = `High FP rate (${(fpRate * 100).toFixed(1)}%) — reducing sensitivity`;
    } else if (fpRate > 0.3 && total_feedback >= MIN_SAMPLES) {
      // Moderate FP rate — slight raise
      direction = 0.5;
      reason = `Moderate FP rate (${(fpRate * 100).toFixed(1)}%) — slight sensitivity reduction`;
    } else if (fn_count > tp_count && total_feedback >= MIN_SAMPLES) {
      // More false negatives than true positives — lower threshold
      direction = -1;
      reason = `High FN rate — increasing sensitivity`;
    } else if (tpRate > 0.9 && total_feedback >= MIN_SAMPLES) {
      // Very accurate detector — could be slightly more sensitive
      direction = -0.3;
      reason = `High TP rate (${(tpRate * 100).toFixed(1)}%) — may increase sensitivity`;
    }

    if (direction === 0) continue;

    // Compute the delta (clamped to MAX_DELTA)
    const rawDelta = direction * MAX_DELTA * Math.abs(0.5 - tpRate);
    const delta = Math.sign(rawDelta) * Math.min(Math.abs(rawDelta), MAX_DELTA);

    adjustments.push({
      detector,
      delta,
      direction: delta > 0 ? 'raise' : 'lower',
      reason,
      stats: {
        total_feedback,
        tp_count,
        fp_count,
        fn_count,
        fp_rate: fpRate,
        tp_rate: tpRate,
        tp_lower_95: tpLower,
        avg_severity,
      },
    });
  }

  return adjustments;
}

/**
 * Apply computed adjustments to the semantic detector thresholds.
 * Updates both the in-memory config and the YAML config file.
 * Logs all changes to threshold_history.
 */
function applyAdjustments(adjustments, dryRun = true) {
  const db = getDb();
  const results = [];

  // Load current config
  let config;
  try {
    config = yaml.load(fs.readFileSync(CONFIG_PATH, 'utf-8'));
  } catch {
    config = {};
  }

  if (!config.semantic) config.semantic = {};
  if (!config.adaptive_thresholds) config.adaptive_thresholds = {};

  const logStmt = db.prepare(`
    INSERT INTO threshold_history
      (ts, detector, old_threshold, new_threshold, reason, fp_rate, tp_rate, sample_count)
    VALUES (@ts, @detector, @old, @new, @reason, @fp_rate, @tp_rate, @sample_count)
  `);

  for (const adj of adjustments) {
    // Map detector name to config key
    const configKey = mapDetectorToConfigKey(adj.detector);
    const currentThreshold = config.adaptive_thresholds[configKey] ??
                             getDefaultThreshold(adj.detector);

    let newThreshold = currentThreshold + adj.delta;

    // Apply floor and ceiling constraints
    const floor = FLOOR_THRESHOLDS[adj.detector] ?? 0.1;
    const ceiling = CEILING_THRESHOLDS[adj.detector] ?? 0.95;
    newThreshold = Math.max(floor, Math.min(ceiling, newThreshold));

    // Skip if change is trivially small
    if (Math.abs(newThreshold - currentThreshold) < 0.001) continue;

    const result = {
      detector: adj.detector,
      configKey,
      old: currentThreshold,
      new: parseFloat(newThreshold.toFixed(4)),
      delta: parseFloat((newThreshold - currentThreshold).toFixed(4)),
      reason: adj.reason,
      stats: adj.stats,
      applied: !dryRun,
    };

    if (!dryRun) {
      config.adaptive_thresholds[configKey] = result.new;

      logStmt.run({
        ts: new Date().toISOString(),
        detector: adj.detector,
        old: currentThreshold,
        new: result.new,
        reason: adj.reason,
        fp_rate: adj.stats.fp_rate,
        tp_rate: adj.stats.tp_rate,
        sample_count: adj.stats.total_feedback,
      });
    }

    results.push(result);
  }

  // Write updated config (only if not dry run and there are changes)
  if (!dryRun && results.length > 0) {
    config.adaptive_thresholds._last_tuned = new Date().toISOString();
    // Note: We write to a separate adaptive config, not the main default.yaml
    // The main config is protected by the shield's own rules
    const adaptivePath = path.join(__dirname, '..', 'config', 'adaptive.yaml');
    fs.writeFileSync(adaptivePath, yaml.dump(config.adaptive_thresholds));
    process.stderr.write(`adaptive: wrote ${results.length} threshold updates to ${adaptivePath}\n`);
  }

  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function mapDetectorToConfigKey(detector) {
  // Map detector names from findings to config keys
  const map = {
    'injection:instruction_override': 'semantic.embed_alert_threshold',
    'injection:role_hijacking': 'semantic.embed_alert_threshold',
    'injection:data_exfiltration': 'semantic.embed_alert_threshold',
    'semantic_injection': 'semantic.classifier_threshold',
    'bash_guard:reverse_shell': 'bash.block_severity',
    'bash_guard:sensitive_file_pipe': 'bash.block_severity',
  };
  return map[detector] || `detector.${detector}`;
}

function getDefaultThreshold(detector) {
  // Default thresholds for known detectors
  const defaults = {
    'semantic_injection': 0.78,
    'injection:instruction_override': 0.78,
    'injection:role_hijacking': 0.78,
    'injection:data_exfiltration': 0.78,
    'tfidf_threat': 0.35,
    'statistical_anomaly': 0.30,
  };
  return defaults[detector] ?? 0.5;
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const cmd = process.argv[2];
  const dryRun = !process.argv.includes('--apply');

  if (cmd === 'tune' || cmd === '--tune') {
    const adjustments = computeAdjustments();
    if (adjustments.length === 0) {
      console.log('No adjustments needed (insufficient feedback data or no significant drift).');
      process.exit(0);
    }
    const results = applyAdjustments(adjustments, dryRun);
    console.log(JSON.stringify(results, null, 2));
    if (dryRun) {
      console.log('\n[DRY RUN] — Pass --apply to write changes.');
    }
  } else if (cmd === 'history') {
    const db = getDb();
    const history = db.prepare(`
      SELECT * FROM threshold_history ORDER BY ts DESC LIMIT 50
    `).all();
    console.log(JSON.stringify(history, null, 2));
  } else {
    console.log('Usage: node pipeline/adaptive-thresholds.js [tune|history] [--apply]');
  }
}

module.exports = {
  computeAdjustments,
  applyAdjustments,
  betaPosteriorMean,
  betaCredibleLower,
  FLOOR_THRESHOLDS,
  CEILING_THRESHOLDS,
};
