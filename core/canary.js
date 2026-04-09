/**
 * Agent Content Shield — Canary Token System (v2)
 *
 * Wave7 rewrite addressing Forge's strawman analysis:
 * - PERSISTENT canary (survives process restarts via file storage)
 * - HIGH ENTROPY (128-bit / 32 hex chars, not 32-bit / 8 hex chars)
 * - STRUCTURED matching (check full phrase, not bare hex substring)
 * - PLANTED in warning banners (actually armed, not just built)
 * - ROTATED weekly with overlap window (current + previous canary checked)
 *
 * Architecture:
 *   1. On first run, generate canary and store in ~/.shield/canary.json
 *   2. On subsequent runs, load persisted canary
 *   3. Canary phrase is embedded in all shield warning banners
 *   4. Incoming content is checked for the structured canary phrase
 *   5. Match = CONFIRMED targeted exfiltration (severity 10)
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const CANARY_DIR = path.join(os.homedir(), '.shield');
const CANARY_FILE = path.join(CANARY_DIR, 'canary.json');
const ROTATION_MS = 7 * 24 * 60 * 60 * 1000; // 1 week

function generateCanaryId() {
  return crypto.randomBytes(16).toString('hex'); // 128-bit, 32 hex chars
}

function loadOrCreateCanary() {
  try {
    if (fs.existsSync(CANARY_FILE)) {
      const data = JSON.parse(fs.readFileSync(CANARY_FILE, 'utf-8'));
      const age = Date.now() - (data.createdAt || 0);

      // Rotate if older than 1 week, but keep previous for overlap
      if (age > ROTATION_MS) {
        const newCanary = {
          id: generateCanaryId(),
          previousId: data.id,
          createdAt: Date.now(),
        };
        fs.writeFileSync(CANARY_FILE, JSON.stringify(newCanary, null, 2));
        return newCanary;
      }
      return data;
    }
  } catch {}

  // First run — create canary
  const canary = {
    id: generateCanaryId(),
    previousId: null,
    createdAt: Date.now(),
  };
  try {
    fs.mkdirSync(CANARY_DIR, { recursive: true });
    fs.writeFileSync(CANARY_FILE, JSON.stringify(canary, null, 2));
  } catch (e) {
    process.stderr.write(`shield: canary persist error: ${e.message}\n`);
  }
  return canary;
}

const CANARY_DATA = loadOrCreateCanary();
const CANARY_ID = CANARY_DATA.id;
const CANARY_PHRASE = `[ref:shield-${CANARY_ID}]`;

// Match the STRUCTURED phrase, not bare hex — eliminates false positives
// from commit hashes, UUIDs, color codes etc.
const CANARY_PATTERNS = [
  new RegExp(`shield-${CANARY_ID}`, 'i'),
];
// Also check previous canary during rotation overlap
if (CANARY_DATA.previousId) {
  CANARY_PATTERNS.push(new RegExp(`shield-${CANARY_DATA.previousId}`, 'i'));
}

/**
 * Check if text contains any canary tokens (current or previous).
 * @param {string} text - Content to check
 * @returns {{ detected: boolean, canaryId: string|null, severity: number }}
 */
function checkForCanary(text) {
  if (!text || text.length < 20) return { detected: false, canaryId: null };
  for (const rx of CANARY_PATTERNS) {
    if (rx.test(text)) {
      return {
        detected: true,
        canaryId: '[REDACTED]', // Never leak the ID in output
        severity: 10,
        reason: 'Content contains shield canary token — confirmed targeted exfiltration',
      };
    }
  }
  return { detected: false, canaryId: null };
}

/**
 * Get the canary phrase for embedding in warning banners.
 * This is how the canary gets PLANTED — include it in shield output
 * that becomes part of the agent's context.
 */
function getCanaryPhrase() {
  return CANARY_PHRASE;
}

module.exports = {
  checkForCanary,
  getCanaryPhrase,
  CANARY_ID,
  CANARY_PHRASE,
};
