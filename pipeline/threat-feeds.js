/**
 * Agent Content Shield — Learning Pipeline: Threat Feed Ingestion
 *
 * Component 3: Subscribe to public prompt injection datasets and
 * automatically add new patterns to signatures.json and INJECTION_SEEDS.
 *
 * Supported feeds:
 *   - HuggingFace prompt injection datasets (JSONL/CSV)
 *   - OWASP LLM Top 10 pattern updates
 *   - Local corpus directories (for custom feeds)
 *
 * Safety: New patterns are ALWAYS added to A/B testing shadow mode first.
 * They only enter production after passing the ab-testing evaluation pipeline.
 *
 * This module does NOT fetch from the network directly (the shield's own
 * security rules would block it). Instead, it processes pre-downloaded files
 * or uses the CLI to manage feed ingestion.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { getDb } = require('./db');
const ab = require('./ab-testing');

const SIGNATURES_PATH = path.join(__dirname, '..', 'core', 'signatures.json');
const FEEDS_DIR = path.join(__dirname, '..', 'data', 'feeds');

// ═══════════════════════════════════════════════════════════════════════
// FEED REGISTRATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Register a new threat feed.
 */
function registerFeed({ name, url, type = 'jsonl' }) {
  const db = getDb();
  db.prepare(`
    INSERT OR REPLACE INTO threat_feeds (feed_name, feed_url, status)
    VALUES (@name, @url, 'active')
  `).run({ name, url });
  return { registered: true, name };
}

/**
 * List all registered feeds.
 */
function listFeeds() {
  const db = getDb();
  return db.prepare('SELECT * FROM threat_feeds ORDER BY feed_name').all();
}

// ═══════════════════════════════════════════════════════════════════════
// PATTERN EXTRACTION FROM FEEDS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Process a JSONL file containing prompt injection samples.
 * Expected format: {"text": "...", "label": "injection"|1, ...}
 * Returns extracted patterns suitable for shadow testing.
 */
function processJsonlFeed(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.trim().split('\n').filter(Boolean);
  const patterns = [];

  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      const text = record.text || record.prompt || record.content || record.input || '';
      const label = record.label || record.is_injection || record.class || '';

      // Only process injection samples
      const isInjection = label === 'injection' || label === 1 || label === '1' ||
                          label === 'malicious' || label === true;
      if (!isInjection || text.length < 20) continue;

      patterns.push({
        text: text.slice(0, 500),
        source: path.basename(filePath),
        hash: crypto.createHash('sha256').update(text).digest('hex').slice(0, 16),
      });
    } catch {} // Skip malformed lines
  }

  return patterns;
}

/**
 * Process a CSV file (HuggingFace format: text,label).
 */
function processCsvFeed(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.trim().split('\n');
  const patterns = [];

  // Skip header
  const header = lines[0].toLowerCase();
  const textIdx = header.includes('prompt') ? header.split(',').indexOf('prompt') :
                  header.includes('text') ? header.split(',').indexOf('text') : 0;
  const labelIdx = header.includes('label') ? header.split(',').indexOf('label') :
                   header.split(',').length - 1;

  for (let i = 1; i < lines.length; i++) {
    // Basic CSV parsing (handles quoted fields)
    const fields = parseCSVLine(lines[i]);
    const text = fields[textIdx] || '';
    const label = fields[labelIdx] || '';

    const isInjection = label === '1' || label.toLowerCase() === 'injection';
    if (!isInjection || text.length < 20) continue;

    patterns.push({
      text: text.slice(0, 500),
      source: path.basename(filePath),
      hash: crypto.createHash('sha256').update(text).digest('hex').slice(0, 16),
    });
  }

  return patterns;
}

function parseCSVLine(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      fields.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current.trim());
  return fields;
}

// ═══════════════════════════════════════════════════════════════════════
// PATTERN CONVERSION — Turn raw injection text into detection rules
// ═══════════════════════════════════════════════════════════════════════

/**
 * Extract regex patterns from a set of injection samples.
 * Uses common substring extraction and keyword clustering.
 */
function extractRegexPatterns(patterns) {
  // Count distinctive n-grams across all injection samples
  const ngramCounts = new Map();
  const totalSamples = patterns.length;

  for (const p of patterns) {
    const words = p.text.toLowerCase().split(/\s+/);
    const seen = new Set();

    // 2-grams and 3-grams
    for (let n = 2; n <= 3; n++) {
      for (let i = 0; i <= words.length - n; i++) {
        const ngram = words.slice(i, i + n).join(' ');
        if (!seen.has(ngram)) {
          seen.add(ngram);
          ngramCounts.set(ngram, (ngramCounts.get(ngram) || 0) + 1);
        }
      }
    }
  }

  // Keep n-grams that appear in at least 3% of samples but less than 50%
  // (too common = not discriminative, too rare = not generalizable)
  const minCount = Math.max(2, Math.ceil(totalSamples * 0.03));
  const maxCount = Math.ceil(totalSamples * 0.50);

  const candidatePatterns = [];
  for (const [ngram, count] of ngramCounts) {
    if (count >= minCount && count <= maxCount) {
      // Convert to regex: escape special chars, allow flexible whitespace
      const escaped = ngram.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = '(?i)' + escaped.replace(/\s+/g, '\\s+');
      candidatePatterns.push({
        pattern: regex,
        frequency: count,
        pct: parseFloat((count / totalSamples * 100).toFixed(1)),
        ngram,
      });
    }
  }

  // Sort by frequency (most common first)
  candidatePatterns.sort((a, b) => b.frequency - a.frequency);
  return candidatePatterns.slice(0, 50); // Top 50 candidate patterns
}

/**
 * Convert injection samples to INJECTION_SEEDS format.
 * Selects representative, diverse samples using simple clustering.
 */
function extractSeeds(patterns, maxSeeds = 20) {
  if (patterns.length <= maxSeeds) return patterns.map(p => p.text);

  // Simple diversity selection: bin by first significant word and pick one per bin
  const bins = new Map();
  for (const p of patterns) {
    const words = p.text.toLowerCase().split(/\s+/).filter(w => w.length > 4);
    const key = words.slice(0, 3).join('_');
    if (!bins.has(key)) bins.set(key, []);
    bins.get(key).push(p);
  }

  const seeds = [];
  const sortedBins = [...bins.entries()].sort((a, b) => b[1].length - a[1].length);

  for (const [, bin] of sortedBins) {
    if (seeds.length >= maxSeeds) break;
    // Pick the shortest sample from each bin (more focused = better seed)
    const best = bin.sort((a, b) => a.text.length - b.text.length)[0];
    seeds.push(best.text);
  }

  return seeds;
}

// ═══════════════════════════════════════════════════════════════════════
// INGESTION PIPELINE — Process feed file and create shadow rules
// ═══════════════════════════════════════════════════════════════════════

/**
 * Ingest a feed file: extract patterns, create shadow A/B tests.
 * Does NOT modify production signatures.json directly.
 */
function ingestFeedFile(filePath, feedName) {
  const ext = path.extname(filePath).toLowerCase();
  let patterns;

  if (ext === '.jsonl' || ext === '.ndjson') {
    patterns = processJsonlFeed(filePath);
  } else if (ext === '.csv') {
    patterns = processCsvFeed(filePath);
  } else {
    return { error: `Unsupported file type: ${ext}` };
  }

  if (patterns.length === 0) {
    return { error: 'No injection patterns found in file' };
  }

  // Extract regex patterns for shadow testing
  const regexCandidates = extractRegexPatterns(patterns);
  const seedCandidates = extractSeeds(patterns);

  // Create shadow A/B tests for the top regex candidates
  let testsCreated = 0;
  for (const candidate of regexCandidates.slice(0, 10)) {
    try {
      ab.createTest({
        name: `feed:${feedName}:${candidate.ngram.replace(/\s+/g, '_').slice(0, 30)}`,
        description: `Auto-generated from ${feedName} feed (${candidate.pct}% frequency)`,
        ruleType: 'regex',
        ruleConfig: { pattern: candidate.pattern, severity: 7, source: feedName },
      });
      testsCreated++;
    } catch {} // Ignore duplicates
  }

  // Update feed tracking
  const db = getDb();
  const contentHash = crypto.createHash('sha256')
    .update(fs.readFileSync(filePath, 'utf-8').slice(0, 10000))
    .digest('hex');

  db.prepare(`
    UPDATE threat_feeds SET
      last_fetched = @now,
      last_hash = @hash,
      patterns_added = patterns_added + @patterns,
      seeds_added = seeds_added + @seeds
    WHERE feed_name = @name
  `).run({
    name: feedName,
    now: new Date().toISOString(),
    hash: contentHash,
    patterns: testsCreated,
    seeds: seedCandidates.length,
  });

  return {
    feedName,
    filePath,
    totalSamples: patterns.length,
    regexCandidates: regexCandidates.length,
    seedCandidates: seedCandidates.length,
    shadowTestsCreated: testsCreated,
    topPatterns: regexCandidates.slice(0, 5).map(c => ({
      pattern: c.ngram,
      frequency: `${c.pct}%`,
    })),
    topSeeds: seedCandidates.slice(0, 5),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

if (require.main === module) {
  const cmd = process.argv[2];
  switch (cmd) {
    case 'ingest': {
      const file = process.argv[3];
      const name = process.argv[4] || path.basename(file, path.extname(file));
      if (!file) { console.error('Usage: threat-feeds ingest <file> [name]'); process.exit(1); }
      registerFeed({ name, url: `file://${file}` });
      console.log(JSON.stringify(ingestFeedFile(file, name), null, 2));
      break;
    }
    case 'list':
      console.log(JSON.stringify(listFeeds(), null, 2));
      break;
    case 'register': {
      const name = process.argv[3];
      const url = process.argv[4];
      if (!name || !url) { console.error('Usage: threat-feeds register <name> <url>'); process.exit(1); }
      registerFeed({ name, url });
      console.log(`Registered feed: ${name}`);
      break;
    }
    default:
      console.log('Usage: node pipeline/threat-feeds.js [ingest <file> [name]|list|register <name> <url>]');
  }
}

module.exports = {
  registerFeed,
  listFeeds,
  processJsonlFeed,
  processCsvFeed,
  extractRegexPatterns,
  extractSeeds,
  ingestFeedFile,
};
