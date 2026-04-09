/**
 * Agent Content Shield — Canary Token System
 *
 * Active exfiltration detection via planted canary phrases.
 *
 * How it works:
 *   1. On startup, generate a unique canary token (random phrase)
 *   2. The canary is injected into shield warnings / system context
 *   3. If any fetched content contains the canary, it proves the content
 *      was crafted AFTER reading our system context — confirming targeted attack
 *
 * This is a detection-by-design approach: instead of only detecting known
 * attack patterns, we plant tripwires that only trigger if exfiltration happened.
 */

const crypto = require('crypto');

// Generate a unique canary that looks like a plausible internal reference
// but is actually random and unique to this process
const CANARY_ID = crypto.randomBytes(4).toString('hex');
const CANARY_PHRASE = `[ref:shield-${CANARY_ID}]`;

// Additional canary variants that might appear in different contexts
const CANARY_VARIANTS = [
  `shield-session-${CANARY_ID}`,
  `internal-ref-${CANARY_ID}`,
  `ctx-${CANARY_ID}`,
];

// All canary patterns to check for (as regex)
const CANARY_PATTERNS = [
  new RegExp(CANARY_ID, 'i'),  // The core ID appears anywhere
];

/**
 * Check if text contains any canary tokens.
 * If found, this proves the content was crafted after reading our context.
 * @param {string} text - Content to check
 * @returns {{ detected: boolean, canaryId: string|null }}
 */
function checkForCanary(text) {
  if (!text || text.length < 8) return { detected: false, canaryId: null };
  for (const rx of CANARY_PATTERNS) {
    if (rx.test(text)) {
      return {
        detected: true,
        canaryId: CANARY_ID,
        severity: 10,  // Confirmed targeted attack
        reason: `Content contains canary token ${CANARY_ID} — confirms targeted exfiltration`,
      };
    }
  }
  return { detected: false, canaryId: null };
}

/**
 * Get the canary phrase to inject into system context / warnings.
 */
function getCanaryPhrase() {
  return CANARY_PHRASE;
}

module.exports = {
  checkForCanary,
  getCanaryPhrase,
  CANARY_ID,
  CANARY_PHRASE,
  CANARY_VARIANTS,
};
