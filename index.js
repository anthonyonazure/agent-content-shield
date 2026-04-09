/**
 * Agent Content Shield — Public API
 *
 * Usage:
 *   const shield = require('agent-content-shield');
 *
 *   // Full pipeline scan (regex + semantic + NLI + LLM)
 *   const result = await shield.scan(text, { context: 'web_fetch' });
 *
 *   // Regex-only scan (fast, no Ollama needed)
 *   const result = shield.scanContent(text, { context: 'general' });
 *
 *   // URL validation (SSRF + blocked domains)
 *   const urlResult = shield.validateUrl('http://localhost:8080');
 *
 *   // Memory write validation
 *   const memResult = shield.validateMemoryWrite(content, 'grug-brain');
 *
 *   // Shield status
 *   const status = await shield.status();
 */

const { scanContent, sanitizeContent, validateUrl, formatWarning, verifySigsIntegrity, deepExtractText, preprocess, SIGS, MIN_SCAN_LENGTH } = require('./core/detectors');
const scanner = require('./core/scanner');

// Re-export semantic functions if available
let semanticScan = null;
let tfidfThreatScore = null;
let tokenEntropyAnomaly = null;
let structuralAnomalyScore = null;
try {
  const sem = require('./core/semantic-detector');
  semanticScan = sem.semanticScan;
  tfidfThreatScore = sem.tfidfThreatScore;
  tokenEntropyAnomaly = sem.tokenEntropyAnomaly;
  structuralAnomalyScore = sem.structuralAnomalyScore;
} catch {}

async function status() {
  const sigsOk = verifySigsIntegrity();
  let ollamaAvailable = false;
  try {
    const res = await fetch('http://localhost:11434/api/tags', {
      signal: AbortSignal.timeout(2000),
    });
    ollamaAvailable = res.ok;
  } catch {}

  return {
    version: require('./package.json').version,
    signatures_integrity: sigsOk,
    ollama_available: ollamaAvailable,
    semantic_available: !!semanticScan,
  };
}

module.exports = {
  // Full pipeline (async, uses Ollama if available)
  scan: scanner.scan,
  validateUrl: scanner.validateUrl,
  validateMemoryWrite: scanner.validateMemoryWrite,
  classifyContext: scanner.classifyContext,

  // Regex layer only (sync, no external deps)
  scanContent,
  sanitizeContent,
  formatWarning,
  preprocess,
  deepExtractText,
  verifySigsIntegrity,

  // Semantic layer (async, requires Ollama)
  semanticScan,
  tfidfThreatScore,
  tokenEntropyAnomaly,
  structuralAnomalyScore,

  // Utilities
  status,
  SIGS,
  MIN_SCAN_LENGTH,
  config: scanner.CONFIG,
};
