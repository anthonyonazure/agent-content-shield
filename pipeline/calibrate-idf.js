/**
 * Agent Content Shield — Learning Pipeline: TF-IDF Weight Calibration
 *
 * The current THREAT_IDF lexicon has ~240 hand-picked terms with hand-assigned
 * IDF weights. The comment says "pre-computed from a corpus of 10K injection
 * samples vs 50K benign web pages" but that corpus doesn't exist — the weights
 * are educated guesses. This module computes REAL IDF weights.
 *
 * Approach: Discriminative IDF (not standard IDF)
 *
 *   Standard IDF = log(N / df) — measures rarity across ALL documents.
 *   Problem: "ignore" is common in benign text too ("ignore this warning").
 *
 *   Discriminative IDF uses TWO corpora:
 *     - Injection corpus (positive class)
 *     - Benign corpus (negative class)
 *
 *   For each term:
 *     df_inj  = fraction of injection docs containing the term
 *     df_ben  = fraction of benign docs containing the term
 *     weight  = log((df_inj + smooth) / (df_ben + smooth)) * log(N / df_total + 1)
 *
 *   This produces:
 *     - High positive weight for terms frequent in injection, rare in benign
 *     - Near-zero weight for terms equally common in both
 *     - Negative weight for terms more common in benign (downweight)
 *
 *   We then clamp to [0.5, 6.5] to match the existing scale and only keep
 *   terms with positive discriminative weight.
 *
 * Corpus sources:
 *   - Benign: any directory of .txt/.md files (web scrapes, docs, articles)
 *   - Injection: the shield's own INJECTION_SEEDS + any JSONL feed files
 *   - Can also ingest from HuggingFace deepset/prompt-injections dataset
 *
 * Output: A new THREAT_IDF object that replaces the hand-tuned one.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getDb } = require('./db');

// ═══════════════════════════════════════════════════════════════════════
// TOKENIZER — Consistent with semantic-detector.js
// ═══════════════════════════════════════════════════════════════════════

function tokenize(text) {
  return text.toLowerCase().split(/[^a-z]+/).filter(w => w.length > 1);
}

function uniqueTokens(text) {
  return new Set(tokenize(text));
}

// ═══════════════════════════════════════════════════════════════════════
// CORPUS LOADING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Load documents from a directory of text files.
 * Returns array of strings (one per document).
 */
function loadCorpusDir(dirPath, extensions = ['.txt', '.md', '.html']) {
  const docs = [];
  const walk = (dir) => {
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          walk(full);
        } else if (extensions.some(ext => entry.name.endsWith(ext))) {
          try {
            const content = fs.readFileSync(full, 'utf-8');
            if (content.length > 50) docs.push(content);
          } catch {}
        }
      }
    } catch {}
  };
  walk(dirPath);
  return docs;
}

/**
 * Load injection samples from JSONL feed files.
 */
function loadInjectionJsonl(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  return content.trim().split('\n')
    .map(line => {
      try {
        const rec = JSON.parse(line);
        const text = rec.text || rec.prompt || rec.content || '';
        const label = rec.label || rec.is_injection || '';
        if ((label === 1 || label === '1' || label === 'injection') && text.length > 20) {
          return text;
        }
      } catch {}
      return null;
    })
    .filter(Boolean);
}

/**
 * Load the existing INJECTION_SEEDS as injection corpus.
 */
function loadBuiltinSeeds() {
  try {
    const semantic = require('../core/semantic-detector');
    return semantic.INJECTION_SEEDS || [];
  } catch {
    return [];
  }
}

// ═══════════════════════════════════════════════════════════════════════
// DISCRIMINATIVE IDF COMPUTATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Compute discriminative IDF weights from two labeled corpora.
 *
 * @param {string[]} injectionDocs - Array of injection text samples
 * @param {string[]} benignDocs - Array of benign text samples
 * @param {Object} opts - Configuration
 * @param {number} opts.smoothing - Laplace smoothing (default 1)
 * @param {number} opts.minDf - Minimum document frequency to include term (default 2)
 * @param {number} opts.minWeight - Minimum discriminative weight to keep (default 0.5)
 * @param {number} opts.maxWeight - Maximum weight cap (default 6.5)
 * @returns {{ weights: Object, stats: Object }}
 */
function computeDiscriminativeIdf(injectionDocs, benignDocs, opts = {}) {
  const smoothing = opts.smoothing ?? 1;
  const minDf = opts.minDf ?? 2;
  const minWeight = opts.minWeight ?? 0.5;
  const maxWeight = opts.maxWeight ?? 6.5;

  const nInj = injectionDocs.length;
  const nBen = benignDocs.length;
  const nTotal = nInj + nBen;

  if (nInj < 10 || nBen < 10) {
    throw new Error(`Insufficient corpus: ${nInj} injection, ${nBen} benign. Need at least 10 each.`);
  }

  // Step 1: Count document frequency per term in each corpus
  const dfInj = new Map();  // term -> count of injection docs containing it
  const dfBen = new Map();  // term -> count of benign docs containing it

  for (const doc of injectionDocs) {
    for (const term of uniqueTokens(doc)) {
      dfInj.set(term, (dfInj.get(term) || 0) + 1);
    }
  }

  for (const doc of benignDocs) {
    for (const term of uniqueTokens(doc)) {
      dfBen.set(term, (dfBen.get(term) || 0) + 1);
    }
  }

  // Step 2: Compute discriminative weight for each term
  const allTerms = new Set([...dfInj.keys(), ...dfBen.keys()]);
  const rawWeights = new Map();

  for (const term of allTerms) {
    const injCount = dfInj.get(term) || 0;
    const benCount = dfBen.get(term) || 0;
    const totalDf = injCount + benCount;

    // Skip very rare terms
    if (totalDf < minDf) continue;

    // Document frequency ratios (with smoothing)
    const injRate = (injCount + smoothing) / (nInj + smoothing * 2);
    const benRate = (benCount + smoothing) / (nBen + smoothing * 2);

    // Log-odds ratio: positive = more common in injection
    const logOdds = Math.log(injRate / benRate);

    // Scale by overall rarity (standard IDF component)
    const idfComponent = Math.log(nTotal / (totalDf + 1)) + 1;

    // Combined discriminative weight
    const weight = logOdds * idfComponent;

    if (weight > 0) { // Only keep terms that discriminate toward injection
      rawWeights.set(term, weight);
    }
  }

  // Step 3: Normalize to [minWeight, maxWeight] range using log scaling
  // Log scaling preserves discriminative magnitude better than linear
  const logWeights = new Map();
  for (const [term, raw] of rawWeights) {
    logWeights.set(term, Math.log1p(raw));
  }
  const maxLog = Math.max(...logWeights.values());

  const weights = {};
  const termStats = [];

  for (const [term, logVal] of logWeights) {
    const raw = rawWeights.get(term);
    weights[term] = parseFloat((minWeight + (logVal / maxLog) * (maxWeight - minWeight)).toFixed(1));
    termStats.push({
      term,
      weight: weights[term],
      rawScore: parseFloat(raw.toFixed(4)),
      injDf: dfInj.get(term) || 0,
      benDf: dfBen.get(term) || 0,
      injRate: parseFloat(((dfInj.get(term) || 0) / nInj * 100).toFixed(1)),
      benRate: parseFloat(((dfBen.get(term) || 0) / nBen * 100).toFixed(1)),
    });
  }

  // Sort by weight descending
  termStats.sort((a, b) => b.weight - a.weight);

  return {
    weights,
    stats: {
      injectionCorpusSize: nInj,
      benignCorpusSize: nBen,
      totalTermsAnalyzed: allTerms.size,
      termsRetained: Object.keys(weights).length,
      termsDropped: allTerms.size - Object.keys(weights).length,
      topTerms: termStats.slice(0, 30),
      bottomTerms: termStats.slice(-10),
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// COMPARISON WITH EXISTING WEIGHTS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Compare calibrated weights with the hand-tuned THREAT_IDF.
 * Identifies terms that are over/under-weighted.
 */
function compareWithExisting(calibratedWeights) {
  let existingWeights;
  try {
    const semantic = require('../core/semantic-detector');
    existingWeights = semantic.THREAT_IDF;
  } catch {
    return { error: 'Cannot load existing THREAT_IDF' };
  }

  const overweighted = [];  // Existing weight much higher than calibrated
  const underweighted = []; // Existing weight much lower than calibrated
  const missingFromExisting = []; // In calibrated but not in existing
  const missingFromCalibrated = []; // In existing but not discriminative

  for (const [term, calWeight] of Object.entries(calibratedWeights)) {
    if (existingWeights[term] == null) {
      missingFromExisting.push({ term, calibratedWeight: calWeight });
      continue;
    }
    const delta = existingWeights[term] - calWeight;
    if (delta > 1.5) {
      overweighted.push({ term, existing: existingWeights[term], calibrated: calWeight, delta: parseFloat(delta.toFixed(1)) });
    } else if (delta < -1.5) {
      underweighted.push({ term, existing: existingWeights[term], calibrated: calWeight, delta: parseFloat(delta.toFixed(1)) });
    }
  }

  for (const [term, weight] of Object.entries(existingWeights)) {
    if (calibratedWeights[term] == null) {
      missingFromCalibrated.push({ term, existingWeight: weight });
    }
  }

  overweighted.sort((a, b) => b.delta - a.delta);
  underweighted.sort((a, b) => a.delta - b.delta);

  return {
    overweighted: overweighted.slice(0, 20),
    underweighted: underweighted.slice(0, 20),
    missingFromExisting: missingFromExisting.sort((a, b) => b.calibratedWeight - a.calibratedWeight).slice(0, 20),
    missingFromCalibrated,
    summary: {
      existingTermCount: Object.keys(existingWeights).length,
      calibratedTermCount: Object.keys(calibratedWeights).length,
      overweightedCount: overweighted.length,
      underweightedCount: underweighted.length,
      newTermsCount: missingFromExisting.length,
      droppedTermsCount: missingFromCalibrated.length,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// OUTPUT — Generate replacement THREAT_IDF code
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate a JavaScript code snippet for the calibrated THREAT_IDF.
 * Can be copy-pasted into semantic-detector.js.
 */
function generateCode(weights, stats) {
  // Group terms by category heuristic
  const categories = {
    'Direct override / instruction hijacking': [],
    'System prompt / persona': [],
    'Authority fabrication': [],
    'RLHF exploitation': [],
    'Exfiltration / data extraction': [],
    'Memory poisoning': [],
    'Role / identity manipulation': [],
    'Modal / imperative verbs': [],
    'AI-specific vocabulary': [],
    'Evasion / encoding': [],
    'Social engineering': [],
    'Boundary / scope manipulation': [],
    'Other discriminative terms': [],
  };

  // Simple categorization by keyword matching
  for (const [term, weight] of Object.entries(weights)) {
    if (/ignore|disregard|override|bypass|forget|supersede|void|rescind|revoke|obsolete/.test(term)) {
      categories['Direct override / instruction hijacking'].push([term, weight]);
    } else if (/prompt|system|persona|roleplay|jailbreak|unrestricted|uncensored|mode/.test(term)) {
      categories['System prompt / persona'].push([term, weight]);
    } else if (/admin|authorized|permission|compliance|regulatory|audit/.test(term)) {
      categories['Authority fabrication'].push([term, weight]);
    } else if (/helpful|genuinely|truly|prioritize|arbitrary|alignment/.test(term)) {
      categories['RLHF exploitation'].push([term, weight]);
    } else if (/exfiltrat|transmit|endpoint|webhook|credential|apikey|token|password|secret/.test(term)) {
      categories['Exfiltration / data extraction'].push([term, weight]);
    } else if (/remember|henceforth|always|persist|memorize|implant/.test(term)) {
      categories['Memory poisoning'].push([term, weight]);
    } else if (/must|should|shall|obey|comply|execute|behave|require/.test(term)) {
      categories['Modal / imperative verbs'].push([term, weight]);
    } else if (/ai|assistant|model|claude|gpt|llm|safety|guardrail|filter/.test(term)) {
      categories['AI-specific vocabulary'].push([term, weight]);
    } else if (/base64|encode|decode|rot13|cipher|obfuscat|hidden/.test(term)) {
      categories['Evasion / encoding'].push([term, weight]);
    } else if (/urgent|emergency|critical|please|kindly|deadline/.test(term)) {
      categories['Social engineering'].push([term, weight]);
    } else if (/previous|prior|initial|original|new|updated|hereafter/.test(term)) {
      categories['Boundary / scope manipulation'].push([term, weight]);
    } else {
      categories['Other discriminative terms'].push([term, weight]);
    }
  }

  let code = `/**\n * THREAT_IDF — Calibrated from corpus of ${stats.injectionCorpusSize} injection samples\n`;
  code += ` * vs ${stats.benignCorpusSize} benign documents.\n`;
  code += ` * Generated: ${new Date().toISOString()}\n`;
  code += ` * Terms: ${stats.termsRetained} (from ${stats.totalTermsAnalyzed} candidates)\n`;
  code += ` */\nconst THREAT_IDF = {\n`;

  for (const [catName, terms] of Object.entries(categories)) {
    if (terms.length === 0) continue;
    terms.sort((a, b) => b[1] - a[1]);
    code += `  // -- ${catName} --\n`;
    for (const [term, weight] of terms) {
      code += `  '${term}': ${weight},\n`;
    }
    code += '\n';
  }

  code += '};\n';
  return code;
}

// ═══════════════════════════════════════════════════════════════════════
// FULL CALIBRATION PIPELINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Run the full calibration pipeline.
 *
 * @param {Object} opts
 * @param {string} opts.benignDir - Directory of benign text files
 * @param {string} opts.injectionDir - Directory of injection samples (optional)
 * @param {string} opts.injectionJsonl - JSONL file of injection samples (optional)
 * @param {boolean} opts.includeBuiltinSeeds - Include INJECTION_SEEDS (default true)
 * @param {boolean} opts.writeOutput - Write calibrated weights to file
 */
function calibrate(opts = {}) {
  // Load benign corpus
  if (!opts.benignDir) {
    throw new Error('benignDir is required. Provide a directory of benign .txt/.md files.');
  }
  const benignDocs = loadCorpusDir(opts.benignDir);
  if (benignDocs.length < 10) {
    throw new Error(`Only ${benignDocs.length} benign docs found. Need at least 10.`);
  }

  // Load injection corpus
  const injectionDocs = [];
  if (opts.includeBuiltinSeeds !== false) {
    injectionDocs.push(...loadBuiltinSeeds());
  }
  if (opts.injectionDir) {
    injectionDocs.push(...loadCorpusDir(opts.injectionDir));
  }
  if (opts.injectionJsonl) {
    injectionDocs.push(...loadInjectionJsonl(opts.injectionJsonl));
  }

  if (injectionDocs.length < 10) {
    throw new Error(`Only ${injectionDocs.length} injection docs. Need at least 10.`);
  }

  // Compute weights
  const { weights, stats } = computeDiscriminativeIdf(injectionDocs, benignDocs, {
    smoothing: opts.smoothing ?? 1,
    minDf: opts.minDf ?? 2,
    minWeight: 0.5,
    maxWeight: 6.5,
  });

  // Compare with existing
  const comparison = compareWithExisting(weights);

  // Generate code
  const code = generateCode(weights, stats);

  // Record calibration in database
  try {
    const db = getDb();
    const hash = crypto.createHash('sha256').update(JSON.stringify(weights)).digest('hex');
    db.prepare(`
      INSERT INTO idf_calibrations
        (ts, benign_corpus_size, injection_corpus_size, term_count, calibration_config, result_hash)
      VALUES (@ts, @benign, @injection, @terms, @config, @hash)
    `).run({
      ts: new Date().toISOString(),
      benign: benignDocs.length,
      injection: injectionDocs.length,
      terms: Object.keys(weights).length,
      config: JSON.stringify({ smoothing: opts.smoothing ?? 1, minDf: opts.minDf ?? 2 }),
      hash,
    });
  } catch {}

  // Write output files
  if (opts.writeOutput) {
    const outDir = path.join(__dirname, '..', 'data', 'calibration');
    fs.mkdirSync(outDir, { recursive: true });

    fs.writeFileSync(
      path.join(outDir, 'threat-idf-calibrated.json'),
      JSON.stringify(weights, null, 2)
    );
    fs.writeFileSync(
      path.join(outDir, 'threat-idf-calibrated.js'),
      code
    );
    fs.writeFileSync(
      path.join(outDir, 'calibration-report.json'),
      JSON.stringify({ stats, comparison }, null, 2)
    );
  }

  return { weights, stats, comparison, code };
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const cmd = process.argv[2];
  if (cmd === 'calibrate' || cmd === '--calibrate') {
    const benignDir = process.argv[3];
    const injectionJsonl = process.argv[4];

    if (!benignDir) {
      console.error('Usage: calibrate-idf calibrate <benign-dir> [injection.jsonl]');
      console.error('  benign-dir:       Directory of benign .txt/.md files');
      console.error('  injection.jsonl:  Optional JSONL file with {text, label} records');
      process.exit(1);
    }

    const result = calibrate({
      benignDir,
      injectionJsonl,
      includeBuiltinSeeds: true,
      writeOutput: true,
    });

    console.log(`\nCalibration complete:`);
    console.log(`  Benign corpus:    ${result.stats.benignCorpusSize} documents`);
    console.log(`  Injection corpus: ${result.stats.injectionCorpusSize} documents`);
    console.log(`  Terms analyzed:   ${result.stats.totalTermsAnalyzed}`);
    console.log(`  Terms retained:   ${result.stats.termsRetained}`);
    console.log(`  Terms dropped:    ${result.stats.termsDropped}`);
    console.log(`\nComparison with existing weights:`);
    console.log(`  Overweighted:     ${result.comparison.summary?.overweightedCount || 0}`);
    console.log(`  Underweighted:    ${result.comparison.summary?.underweightedCount || 0}`);
    console.log(`  New terms:        ${result.comparison.summary?.newTermsCount || 0}`);
    console.log(`  Dropped terms:    ${result.comparison.summary?.droppedTermsCount || 0}`);
    console.log(`\nOutput written to data/calibration/`);
  } else if (cmd === 'compare') {
    // Just compare existing weights against a calibration result
    const calFile = process.argv[3];
    if (!calFile) { console.error('Usage: calibrate-idf compare <calibrated.json>'); process.exit(1); }
    const weights = JSON.parse(fs.readFileSync(calFile, 'utf-8'));
    console.log(JSON.stringify(compareWithExisting(weights), null, 2));
  } else {
    console.log('Usage: node pipeline/calibrate-idf.js [calibrate <benign-dir> [injection.jsonl]|compare <calibrated.json>]');
  }
}

module.exports = {
  computeDiscriminativeIdf,
  compareWithExisting,
  generateCode,
  calibrate,
  loadCorpusDir,
  loadInjectionJsonl,
  loadBuiltinSeeds,
  tokenize,
  uniqueTokens,
};
