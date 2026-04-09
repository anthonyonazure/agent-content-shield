/**
 * Agent Content Shield — Active Deception Layer
 *
 * Plants fake high-value targets (honeypots) into the agent's context.
 * When manipulated content tricks an agent into referencing a honeypot,
 * it proves the agent has been compromised (severity 10).
 *
 * Honeypot types:
 *   1. Fake API key:       sk-ant-api1-{random32hex}
 *   2. Fake credential path: ~/.config/cloud-credentials-{random8hex}.json
 *   3. Fake internal URL:  https://internal-{random8hex}.corp.example.com/api/admin
 *
 * Zero false positives: all honeypots contain random hex that cannot
 * appear naturally in any legitimate content.
 *
 * Persistence: ~/.shield/honeypots.json (survives restarts, like canary.js)
 * Rotation: weekly, previous set still checked during overlap window.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const SHIELD_DIR = path.join(os.homedir(), '.shield');
const HONEYPOT_FILE = path.join(SHIELD_DIR, 'honeypots.json');
const ROTATION_MS = 7 * 24 * 60 * 60 * 1000; // 1 week

function hex(n) { return crypto.randomBytes(n).toString('hex'); }

function generateHoneypots() {
  return {
    apiKey: `sk-ant-api1-${hex(16)}`,
    credPath: `~/.config/cloud-credentials-${hex(4)}.json`,
    internalUrl: `https://internal-${hex(4)}.corp.example.com/api/admin`,
  };
}

function loadOrCreateHoneypots() {
  try {
    if (fs.existsSync(HONEYPOT_FILE)) {
      const data = JSON.parse(fs.readFileSync(HONEYPOT_FILE, 'utf-8'));
      const age = Date.now() - (data.createdAt || 0);

      if (age > ROTATION_MS) {
        const rotated = {
          current: generateHoneypots(),
          previous: data.current,
          createdAt: Date.now(),
        };
        fs.writeFileSync(HONEYPOT_FILE, JSON.stringify(rotated, null, 2));
        return rotated;
      }
      return data;
    }
  } catch {}

  const fresh = {
    current: generateHoneypots(),
    previous: null,
    createdAt: Date.now(),
  };
  try {
    fs.mkdirSync(SHIELD_DIR, { recursive: true });
    fs.writeFileSync(HONEYPOT_FILE, JSON.stringify(fresh, null, 2));
  } catch (e) {
    process.stderr.write(`shield: honeypot persist error: ${e.message}\n`);
  }
  return fresh;
}

const HONEYPOT_DATA = loadOrCreateHoneypots();

/**
 * Build a flat list of { type, marker } from a honeypot set.
 */
function markersFromSet(hSet) {
  if (!hSet) return [];
  return [
    { type: 'fake_api_key', marker: hSet.apiKey },
    { type: 'fake_credential_path', marker: hSet.credPath },
    { type: 'fake_internal_url', marker: hSet.internalUrl },
  ];
}

/** All active markers (current + previous for overlap). */
function allMarkers() {
  return [
    ...markersFromSet(HONEYPOT_DATA.current),
    ...markersFromSet(HONEYPOT_DATA.previous),
  ];
}

/**
 * Check if any tool input references a planted honeypot.
 * @param {string} toolName
 * @param {object} toolInput
 * @returns {{ compromised: boolean, severity?: number, honeypotType?: string, explanation?: string }}
 */
function checkAction(toolName, toolInput) {
  const blob = typeof toolInput === 'string'
    ? toolInput
    : JSON.stringify(toolInput || '');

  for (const { type, marker } of allMarkers()) {
    if (blob.includes(marker)) {
      return {
        compromised: true,
        severity: 10,
        honeypotType: type,
        explanation: `Agent referenced planted honeypot (${type}). This confirms the agent is acting on injected instructions.`,
      };
    }
  }
  return { compromised: false };
}

/**
 * Get subtle reference strings suitable for embedding in warning banners.
 * These enter the agent's context so an attacker who reads them and
 * instructs the agent to use them will trigger detection.
 */
function getHoneypotReferences() {
  const h = HONEYPOT_DATA.current;
  return [
    `[auth:${h.apiKey.slice(-12)}]`,
    `[cfg:${path.basename(h.credPath)}]`,
    `[endpoint:${h.internalUrl.split('//')[1].split('.')[0]}]`,
  ];
}

/**
 * Plant honeypots (called at module load; idempotent via file check).
 * Returns the current honeypot set for inspection/testing.
 */
function plantHoneypots() {
  return { ...HONEYPOT_DATA.current };
}

module.exports = {
  plantHoneypots,
  checkAction,
  getHoneypotReferences,
  // Exposed for testing only
  _HONEYPOT_DATA: HONEYPOT_DATA,
  _allMarkers: allMarkers,
};
