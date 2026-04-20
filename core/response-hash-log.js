/**
 * Agent Content Shield — Append-Only Response Hash Log
 *
 * Per the "Your Agent Is Mine" paper (Liu et al., 2026), transparency
 * logging preserves forensic evidence to scope exposure after an incident.
 * No client-side defense can prove a response wasn't tampered with, but
 * an append-only hash log creates an auditable trail.
 *
 * Design:
 *   1. Before any tool executes, hash the raw response JSON
 *   2. Append to an integrity-protected JSONL log (HMAC-chained)
 *   3. Each entry links to the previous via hash chain (tamper-evident)
 *   4. Log can be diffed against provider-side records when available
 *
 * Storage: ~1.2 KB/entry, ~12 MB/1000 sessions (matches paper's measurement)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const LOG_DIR = path.join(__dirname, '..', 'logs');
const HASH_LOG_FILE = path.join(LOG_DIR, 'response-hashes.jsonl');
const MAX_LOG_SIZE = 50 * 1024 * 1024; // 50MB before rotation
const MAX_ROTATED = 10;

// Chain key derived from machine + shield install identity
const CHAIN_KEY = crypto.createHash('sha256')
  .update(`shield-chain-${os.hostname()}-${__dirname}`)
  .digest('hex');

let _lastChainHash = 'GENESIS';
let _initialized = false;

// ── Initialization ────────────────────────────────────────────────

function ensureLogDir() {
  try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch {}
}

function initialize() {
  if (_initialized) return;
  ensureLogDir();

  // Resume chain from last entry in existing log
  try {
    const content = fs.readFileSync(HASH_LOG_FILE, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    if (lines.length > 0) {
      const last = JSON.parse(lines[lines.length - 1]);
      _lastChainHash = last.chainHash || 'GENESIS';
    }
  } catch {
    // No existing log — start fresh
  }
  _initialized = true;
}

// ── Log Rotation ──────────────────────────────────────────────────

function rotateIfNeeded() {
  try {
    const stats = fs.statSync(HASH_LOG_FILE);
    if (stats.size >= MAX_LOG_SIZE) {
      const rotated = path.join(LOG_DIR, `response-hashes-${Date.now()}.jsonl`);
      fs.renameSync(HASH_LOG_FILE, rotated);

      // Prune old rotated files
      const files = fs.readdirSync(LOG_DIR)
        .filter(f => f.startsWith('response-hashes-') && f.endsWith('.jsonl'))
        .sort().reverse();
      for (const old of files.slice(MAX_ROTATED)) {
        fs.unlinkSync(path.join(LOG_DIR, old));
      }

      // Reset chain for new file
      _lastChainHash = 'ROTATED';
    }
  } catch {
    // File doesn't exist yet
  }
}

// ── Hashing ───────────────────────────────────────────────────────

function hashResponse(responseBody) {
  return crypto.createHash('sha256')
    .update(typeof responseBody === 'string' ? responseBody : JSON.stringify(responseBody))
    .digest('hex');
}

function computeChainHash(prevHash, entryHash, timestamp) {
  return crypto.createHmac('sha256', CHAIN_KEY)
    .update(`${prevHash}:${entryHash}:${timestamp}`)
    .digest('hex');
}

// ── Core API ──────────────────────────────────────────────────────

/**
 * Log a tool-call response with hash chain integrity.
 *
 * @param {object} opts
 * @param {string} opts.sessionId - Session identifier
 * @param {string} opts.toolName - Tool that was called
 * @param {object|string} opts.toolInput - Tool input (secrets redacted)
 * @param {object|string} opts.responseBody - Raw response from provider
 * @param {string} opts.routerUrl - Base URL of the router/provider endpoint
 * @param {object} opts.tlsMeta - TLS metadata if available { protocol, cipher, cert }
 * @param {string} opts.requestNonce - Client-generated nonce for this request
 * @returns {object} The logged entry (for verification)
 */
function logResponse(opts) {
  initialize();
  rotateIfNeeded();

  const ts = Date.now();
  const responseHash = hashResponse(opts.responseBody);

  // Redact secrets from tool input before logging
  const redactedInput = redactSecrets(opts.toolInput);

  // Compute chain hash linking to previous entry
  const chainHash = computeChainHash(_lastChainHash, responseHash, ts);

  const entry = {
    ts,
    iso: new Date(ts).toISOString(),
    sessionId: opts.sessionId || 'unknown',
    toolName: opts.toolName || 'unknown',
    toolInput: truncate(redactedInput, 500),
    responseHash,
    responseSize: typeof opts.responseBody === 'string'
      ? opts.responseBody.length
      : JSON.stringify(opts.responseBody).length,
    routerUrl: opts.routerUrl || null,
    tlsProtocol: opts.tlsMeta?.protocol || null,
    requestNonce: opts.requestNonce || null,
    prevChainHash: _lastChainHash,
    chainHash,
  };

  try {
    fs.appendFileSync(HASH_LOG_FILE, JSON.stringify(entry) + '\n');
    _lastChainHash = chainHash;
  } catch (e) {
    process.stderr.write(`shield-hashlog: write error: ${e.message}\n`);
  }

  return entry;
}

// ── Secret Redaction ──────────────────────────────────────────────

const SECRET_PATTERNS = [
  /(?:sk-[a-zA-Z0-9]{20,})/g,        // OpenAI/Anthropic API keys
  /(?:AKIA[A-Z0-9]{16})/g,           // AWS access key IDs
  /(?:ghp_[a-zA-Z0-9]{36})/g,        // GitHub PATs
  /(?:xox[bpras]-[a-zA-Z0-9-]+)/g,   // Slack tokens
  /(?:password|secret|token|key)\s*[=:]\s*['"]?[^\s'"]{8,}/gi,
];

function redactSecrets(input) {
  let text = typeof input === 'string' ? input : JSON.stringify(input || '');
  for (const rx of SECRET_PATTERNS) {
    text = text.replace(rx, '[REDACTED]');
  }
  // Truncate to avoid bloating the log
  return text.length > 1000 ? text.slice(0, 1000) + '...' : text;
}

function truncate(str, maxLen) {
  if (!str) return '';
  const s = typeof str === 'string' ? str : JSON.stringify(str);
  return s.length > maxLen ? s.slice(0, maxLen) + '...' : s;
}

// ── Verification ──────────────────────────────────────────────────

/**
 * Verify the integrity of the hash log chain.
 * Returns { valid, entries, breaks[] }
 */
function verifyChain() {
  initialize();
  try {
    const content = fs.readFileSync(HASH_LOG_FILE, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    const breaks = [];

    let prevHash = 'GENESIS';
    for (let i = 0; i < lines.length; i++) {
      const entry = JSON.parse(lines[i]);

      // Check that prevChainHash matches our tracking
      if (entry.prevChainHash !== prevHash && entry.prevChainHash !== 'ROTATED') {
        breaks.push({
          line: i + 1,
          expected: prevHash,
          found: entry.prevChainHash,
        });
      }

      // Verify chain hash computation
      const expectedChain = computeChainHash(entry.prevChainHash, entry.responseHash, entry.ts);
      if (entry.chainHash !== expectedChain) {
        breaks.push({
          line: i + 1,
          type: 'chain_hash_mismatch',
          expected: expectedChain,
          found: entry.chainHash,
        });
      }

      prevHash = entry.chainHash;
    }

    return {
      valid: breaks.length === 0,
      entries: lines.length,
      breaks,
    };
  } catch (e) {
    return { valid: false, entries: 0, breaks: [{ type: 'read_error', message: e.message }] };
  }
}

/**
 * Query the log for entries matching a filter.
 * Useful for forensic investigation after an incident.
 */
function queryLog(filter = {}) {
  initialize();
  try {
    const content = fs.readFileSync(HASH_LOG_FILE, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    let entries = lines.map(l => JSON.parse(l));

    if (filter.sessionId) entries = entries.filter(e => e.sessionId === filter.sessionId);
    if (filter.toolName) entries = entries.filter(e => e.toolName === filter.toolName);
    if (filter.routerUrl) entries = entries.filter(e => e.routerUrl === filter.routerUrl);
    if (filter.since) entries = entries.filter(e => e.ts >= filter.since);
    if (filter.until) entries = entries.filter(e => e.ts <= filter.until);
    if (filter.limit) entries = entries.slice(-filter.limit);

    return entries;
  } catch {
    return [];
  }
}

module.exports = {
  logResponse,
  verifyChain,
  queryLog,
  hashResponse,
  // For testing
  _internals: {
    initialize,
    computeChainHash,
    redactSecrets,
    HASH_LOG_FILE,
    CHAIN_KEY,
    reset: () => { _lastChainHash = 'GENESIS'; _initialized = false; },
  },
};
