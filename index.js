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

// Wave10: Transport-layer defense modules
let packageIntegrity = null;
try { packageIntegrity = require('./core/package-integrity'); } catch {}
let responseConsistency = null;
try { responseConsistency = require('./core/response-consistency'); } catch {}
let responseHashLog = null;
try { responseHashLog = require('./core/response-hash-log'); } catch {}
let routerTrust = null;
try { routerTrust = require('./core/router-trust'); } catch {}
let yoloDetector = null;
try { yoloDetector = require('./core/yolo-detector'); } catch {}
let providerSignature = null;
try { providerSignature = require('./core/provider-signature'); } catch {}

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

  // Wave10: Transport-layer defenses ("Your Agent Is Mine" paper)
  checkPackageIntegrity: scanner.checkPackageIntegrity,
  checkResponseConsistency: scanner.checkResponseConsistency,
  logResponseHash: scanner.logResponseHash,
  assessRouter: scanner.assessRouter,
  detectYoloMode: scanner.detectYoloMode,
  verifyProviderSignature: scanner.verifyProviderSignature,

  // Direct module access (for advanced use)
  packageIntegrity,
  responseConsistency,
  responseHashLog,
  routerTrust,
  yoloDetector,
  providerSignature,

  // Utilities
  status,
  SIGS,
  MIN_SCAN_LENGTH,
  config: scanner.CONFIG,
};
