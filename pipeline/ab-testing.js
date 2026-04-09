/**
 * Agent Content Shield — Learning Pipeline: A/B Testing Framework
 *
 * Component 5: Run new detection rules in shadow mode (log but don't block)
 * to measure false positive impact before promoting to production.
 *
 * Workflow:
 *   1. Create a shadow rule: ab.createTest({ name, ruleType, ruleConfig })
 *   2. On each scan, evaluate shadow rules: ab.evaluateShadow(content, hookResult)
 *   3. Shadow rules log whether they WOULD have fired, alongside production result
 *   4. After enough data, check: ab.analyzeTest(testName)
 *   5. If FP rate is acceptable, promote: ab.promoteTest(testName)
 *   6. Retirement: ab.retireTest(testName)
 *
 * Rule types:
 *   - regex:     { pattern: "...", flags: "i", severity: 8 }
 *   - threshold: { detector: "tfidf", threshold: 0.30 }
 *   - signature: { category: "injection_patterns", patterns: ["..."] }
 */

const { getDb } = require('./db');

// ═══════════════════════════════════════════════════════════════════════
// TEST MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════

/**
 * Create a new shadow test.
 */
function createTest({ name, description, ruleType, ruleConfig }) {
  const db = getDb();
  const stmt = db.prepare(`
    INSERT INTO ab_tests (name, description, rule_type, rule_config, status, created_at)
    VALUES (@name, @description, @ruleType, @ruleConfig, 'shadow', @createdAt)
  `);
  return stmt.run({
    name,
    description: description || '',
    ruleType,
    ruleConfig: typeof ruleConfig === 'string' ? ruleConfig : JSON.stringify(ruleConfig),
    createdAt: new Date().toISOString(),
  });
}

/**
 * Get all active shadow tests.
 */
function getActiveTests() {
  const db = getDb();
  return db.prepare(`SELECT * FROM ab_tests WHERE status = 'shadow'`).all().map(t => ({
    ...t,
    rule_config: JSON.parse(t.rule_config),
  }));
}

// ═══════════════════════════════════════════════════════════════════════
// SHADOW EVALUATION ENGINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Evaluate all active shadow rules against content.
 * Called after every production scan to compare results.
 *
 * @param {string} content - The scanned text
 * @param {boolean} productionFired - Whether production rules flagged this content
 * @param {string} hook - Which hook invoked the scan
 * @returns {Array} Results of shadow evaluation
 */
function evaluateShadow(content, productionFired, hook = 'unknown') {
  const db = getDb();
  const tests = getActiveTests();
  if (tests.length === 0) return [];

  const crypto = require('crypto');
  const contentHash = crypto.createHash('sha256').update(content.slice(0, 4000)).digest('hex');
  const results = [];

  const evalStmt = db.prepare(`
    INSERT INTO ab_evaluations (test_id, ts, would_fire, production_fired, content_hash, hook)
    VALUES (@testId, @ts, @wouldFire, @productionFired, @contentHash, @hook)
  `);

  const updateCountsStmt = db.prepare(`
    UPDATE ab_tests SET total_evaluations = total_evaluations + 1 WHERE id = @id
  `);

  const ts = new Date().toISOString();

  for (const test of tests) {
    const wouldFire = evaluateRule(test.rule_type, test.rule_config, content);

    evalStmt.run({
      testId: test.id,
      ts,
      wouldFire: wouldFire ? 1 : 0,
      productionFired: productionFired ? 1 : 0,
      contentHash,
      hook,
    });

    updateCountsStmt.run({ id: test.id });

    results.push({
      testName: test.name,
      wouldFire,
      productionFired,
    });
  }

  return results;
}

/**
 * Evaluate a single rule against content.
 */
function evaluateRule(ruleType, ruleConfig, content) {
  switch (ruleType) {
    case 'regex': {
      try {
        const rx = new RegExp(ruleConfig.pattern, ruleConfig.flags || 'i');
        return rx.test(content);
      } catch {
        return false;
      }
    }

    case 'threshold': {
      // Requires the semantic detector to be available
      try {
        const semantic = require('../core/semantic-detector');
        if (ruleConfig.detector === 'tfidf') {
          const result = semantic.tfidfThreatScore(content);
          return result.score >= ruleConfig.threshold;
        }
        if (ruleConfig.detector === 'statistical') {
          const result = semantic.statisticalAnomalyScore(content);
          return result.score >= ruleConfig.threshold;
        }
      } catch {
        return false;
      }
      return false;
    }

    case 'signature': {
      // Test a set of regex patterns as a potential signature group
      const patterns = ruleConfig.patterns || [];
      for (const p of patterns) {
        try {
          if (new RegExp(p, 'i').test(content)) return true;
        } catch {}
      }
      return false;
    }

    default:
      return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ANALYSIS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Analyze a shadow test's performance.
 * Computes confusion matrix relative to production rules + any feedback.
 */
function analyzeTest(testName) {
  const db = getDb();
  const test = db.prepare(`SELECT * FROM ab_tests WHERE name = ?`).get(testName);
  if (!test) return { error: `Test "${testName}" not found` };

  // Confusion matrix: shadow vs production
  const matrix = db.prepare(`
    SELECT
      SUM(CASE WHEN would_fire = 1 AND production_fired = 1 THEN 1 ELSE 0 END) as agree_positive,
      SUM(CASE WHEN would_fire = 0 AND production_fired = 0 THEN 1 ELSE 0 END) as agree_negative,
      SUM(CASE WHEN would_fire = 1 AND production_fired = 0 THEN 1 ELSE 0 END) as shadow_only,
      SUM(CASE WHEN would_fire = 0 AND production_fired = 1 THEN 1 ELSE 0 END) as production_only,
      COUNT(*) as total
    FROM ab_evaluations
    WHERE test_id = ?
  `).get(test.id);

  // Fire rate
  const fireRate = matrix.total > 0
    ? (matrix.agree_positive + matrix.shadow_only) / matrix.total
    : 0;

  // Additional false positives the shadow rule would introduce
  // (fires when production says clean)
  const additionalFpRate = matrix.total > 0
    ? matrix.shadow_only / matrix.total
    : 0;

  // Check against confirmed feedback
  const feedbackComparison = db.prepare(`
    SELECT
      SUM(CASE WHEN ae.would_fire = 1 AND f.feedback_type = 'false_positive' THEN 1 ELSE 0 END) as shadow_fp_confirmed,
      SUM(CASE WHEN ae.would_fire = 1 AND f.feedback_type = 'confirmed_true' THEN 1 ELSE 0 END) as shadow_tp_confirmed,
      SUM(CASE WHEN ae.would_fire = 0 AND f.feedback_type = 'false_negative' THEN 1 ELSE 0 END) as shadow_fn,
      COUNT(f.id) as total_with_feedback
    FROM ab_evaluations ae
    LEFT JOIN feedback f ON ae.content_hash = f.content_hash
    WHERE ae.test_id = ?
  `).get(test.id);

  // Recommendation
  let recommendation = 'continue_monitoring';
  if (matrix.total < 50) {
    recommendation = 'insufficient_data';
  } else if (additionalFpRate > 0.10) {
    recommendation = 'too_noisy_retire';
  } else if (additionalFpRate < 0.02 && fireRate > 0.01) {
    recommendation = 'ready_to_promote';
  } else if (additionalFpRate < 0.05) {
    recommendation = 'promising_keep_monitoring';
  }

  return {
    test: {
      name: test.name,
      status: test.status,
      ruleType: test.rule_type,
      ruleConfig: JSON.parse(test.rule_config),
      created: test.created_at,
      totalEvaluations: test.total_evaluations,
    },
    matrix,
    fireRate: parseFloat(fireRate.toFixed(4)),
    additionalFpRate: parseFloat(additionalFpRate.toFixed(4)),
    feedbackComparison,
    recommendation,
  };
}

/**
 * Promote a shadow test to production.
 * This marks it in the DB; the actual rule integration is done by
 * the caller (e.g., adding regex to signatures.json or updating thresholds).
 */
function promoteTest(testName) {
  const db = getDb();
  const result = db.prepare(`
    UPDATE ab_tests SET status = 'promoted', promoted_at = @now WHERE name = @name AND status = 'shadow'
  `).run({ name: testName, now: new Date().toISOString() });

  if (result.changes === 0) return { error: 'Test not found or not in shadow status' };

  const test = db.prepare('SELECT * FROM ab_tests WHERE name = ?').get(testName);
  return {
    promoted: true,
    test: { ...test, rule_config: JSON.parse(test.rule_config) },
    note: 'Rule promoted. Integrate into production config manually or via threat-feeds pipeline.',
  };
}

/**
 * Retire a shadow test (too noisy or no longer needed).
 */
function retireTest(testName) {
  const db = getDb();
  db.prepare(`UPDATE ab_tests SET status = 'retired' WHERE name = ?`).run(testName);
  return { retired: true, name: testName };
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const cmd = process.argv[2];
  switch (cmd) {
    case 'list':
      console.log(JSON.stringify(getActiveTests(), null, 2));
      break;
    case 'analyze': {
      const name = process.argv[3];
      if (!name) { console.error('Usage: ab-testing analyze <name>'); process.exit(1); }
      console.log(JSON.stringify(analyzeTest(name), null, 2));
      break;
    }
    case 'promote': {
      const name = process.argv[3];
      if (!name) { console.error('Usage: ab-testing promote <name>'); process.exit(1); }
      console.log(JSON.stringify(promoteTest(name), null, 2));
      break;
    }
    case 'create': {
      // Example: node ab-testing.js create "test-name" regex '{"pattern":"foo","severity":5}'
      const [, , , name, ruleType, config] = process.argv;
      if (!name || !ruleType || !config) {
        console.error('Usage: ab-testing create <name> <regex|threshold|signature> <json_config>');
        process.exit(1);
      }
      createTest({ name, ruleType, ruleConfig: JSON.parse(config) });
      console.log(`Created shadow test: ${name}`);
      break;
    }
    default:
      console.log('Usage: node pipeline/ab-testing.js [list|analyze <name>|promote <name>|create <name> <type> <config>]');
  }
}

module.exports = {
  createTest,
  getActiveTests,
  evaluateShadow,
  evaluateRule,
  analyzeTest,
  promoteTest,
  retireTest,
};
