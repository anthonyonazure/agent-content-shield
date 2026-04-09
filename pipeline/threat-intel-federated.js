/**
 * Agent Content Shield — Federated Threat Intelligence Protocol
 *
 * Opt-in anonymous sharing of attack patterns across shield instances.
 * Privacy-first: only structural patterns shared, never content.
 * Local-only mode (default): patterns extracted and learned locally.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const SHIELD_DIR = path.join(os.homedir(), '.shield');
const INSTANCE_FILE = path.join(SHIELD_DIR, 'instance.json');
const PATTERNS_FILE = path.join(SHIELD_DIR, 'federated-patterns.json');

const TOOL_ABSTRACTION = {
  Read: 'READ', read_file: 'READ', cat: 'READ',
  Write: 'WRITE', write_file: 'WRITE', Edit: 'WRITE',
  Bash: 'EXEC', exec: 'EXEC', shell: 'EXEC',
  WebFetch: 'FETCH', fetch: 'FETCH', curl: 'FETCH', wget: 'FETCH',
  mempalace: 'MEMORY', grug: 'MEMORY', memory: 'MEMORY',
};

function abstractTool(name) {
  if (!name) return 'UNKNOWN';
  const lower = name.toLowerCase();
  for (const [key, val] of Object.entries(TOOL_ABSTRACTION)) {
    if (lower.includes(key.toLowerCase())) return val;
  }
  return 'OTHER';
}

function getOrCreateInstanceId() {
  try {
    if (fs.existsSync(INSTANCE_FILE)) {
      const data = JSON.parse(fs.readFileSync(INSTANCE_FILE, 'utf-8'));
      if (data.instanceId) return data.instanceId;
    }
  } catch {}
  const instanceId = crypto.randomBytes(16).toString('hex');
  fs.mkdirSync(SHIELD_DIR, { recursive: true });
  fs.writeFileSync(INSTANCE_FILE, JSON.stringify({ instanceId, created: new Date().toISOString() }));
  return instanceId;
}

function loadLocalPatterns() {
  try {
    if (fs.existsSync(PATTERNS_FILE)) return JSON.parse(fs.readFileSync(PATTERNS_FILE, 'utf-8'));
  } catch {}
  return { patterns: [], lastSync: null, contributions: [], rateWindow: [] };
}

function saveLocalPatterns(store) {
  fs.mkdirSync(SHIELD_DIR, { recursive: true });
  fs.writeFileSync(PATTERNS_FILE, JSON.stringify(store, null, 2));
}

class FederatedThreatIntel {
  constructor(opts = {}) {
    this.endpoint = opts.endpoint || null;
    this.shareEnabled = opts.shareEnabled === true;
    this.instanceId = opts.instanceId || getOrCreateInstanceId();
    this.store = loadLocalPatterns();
    this.maxContributionsPerHour = 10;
  }

  /** Strip all sensitive data, keep only structural patterns. */
  anonymize(detection) {
    if (!detection) return null;
    const anon = {
      ts: new Date().toISOString(),
      patternHash: crypto.createHash('sha256')
        .update(JSON.stringify(detection.findings || [])).digest('hex').slice(0, 12),
    };
    if (detection.toolSequence || detection.tools) {
      const tools = detection.toolSequence || detection.tools || [];
      anon.toolSequence = (Array.isArray(tools) ? tools : [tools]).map(abstractTool);
    }
    if (detection.findings) {
      anon.categories = [...new Set(detection.findings.map(f => f.detector || f.category).filter(Boolean))];
      anon.layers = [...new Set(detection.findings.map(f => f.layer || f.detector).filter(Boolean))];
    }
    if (detection.influenceType) anon.influenceType = detection.influenceType;
    if (detection.surpriseScore != null) anon.surpriseScore = Math.round(detection.surpriseScore * 10) / 10;
    if (detection.maxSeverity != null) anon.severity = detection.maxSeverity;
    return anon;
  }

  /** POST anonymized pattern to endpoint (fire-and-forget, 5s timeout, rate-limited). */
  contribute(detection) {
    const anon = this.anonymize(detection);
    if (!anon) return { contributed: false, reason: 'empty_detection' };

    // Always store locally
    this.store.patterns.push(anon);
    if (this.store.patterns.length > 1000) this.store.patterns = this.store.patterns.slice(-500);
    saveLocalPatterns(this.store);

    if (!this.shareEnabled || !this.endpoint)
      return { contributed: false, reason: this.shareEnabled ? 'no_endpoint' : 'sharing_disabled', local: true };

    // Rate limiting: max 10/hour to prevent timing fingerprinting
    const now = Date.now();
    this.store.rateWindow = (this.store.rateWindow || []).filter(t => now - t < 3600000);
    if (this.store.rateWindow.length >= this.maxContributionsPerHour)
      return { contributed: false, reason: 'rate_limited', local: true };
    if (!this.endpoint.startsWith('https://'))
      return { contributed: false, reason: 'https_required', local: true };

    this.store.rateWindow.push(now);
    this.store.contributions.push({ ts: anon.ts, hash: anon.patternHash });
    if (this.store.contributions.length > 200) this.store.contributions = this.store.contributions.slice(-100);
    saveLocalPatterns(this.store);

    const payload = JSON.stringify({ instanceId: this.instanceId, pattern: anon });
    try {
      const https = require('https');
      const req = https.request(new URL('/v1/patterns', this.endpoint), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
        timeout: 5000,
      });
      req.on('error', () => {});
      req.on('timeout', () => req.destroy());
      req.write(payload);
      req.end();
    } catch {}
    return { contributed: true, hash: anon.patternHash };
  }

  /** GET new patterns from endpoint since last sync. */
  sync() {
    if (!this.shareEnabled || !this.endpoint)
      return { synced: false, reason: this.shareEnabled ? 'no_endpoint' : 'sharing_disabled' };
    if (!this.endpoint.startsWith('https://'))
      return { synced: false, reason: 'https_required' };

    const since = this.store.lastSync || '1970-01-01T00:00:00Z';
    const url = new URL(`/v1/patterns?since=${encodeURIComponent(since)}`, this.endpoint);

    return new Promise((resolve) => {
      try {
        const https = require('https');
        const req = https.get(url, { timeout: 5000 }, (res) => {
          let data = '';
          res.on('data', chunk => { data += chunk; });
          res.on('end', () => {
            try {
              const result = JSON.parse(data);
              const patterns = result.patterns || [];
              this.store.lastSync = new Date().toISOString();
              saveLocalPatterns(this.store);
              resolve({ synced: true, count: patterns.length, patterns });
            } catch { resolve({ synced: false, reason: 'invalid_response' }); }
          });
        });
        req.on('error', () => resolve({ synced: false, reason: 'network_error' }));
        req.on('timeout', () => { req.destroy(); resolve({ synced: false, reason: 'timeout' }); });
      } catch { resolve({ synced: false, reason: 'request_failed' }); }
    });
  }

  /** Convert shared patterns into local detection rules. */
  applyPatterns(patterns) {
    if (!Array.isArray(patterns) || patterns.length === 0) return { applied: 0, rules: [] };
    const rules = [];
    for (const p of patterns) {
      if (p.toolSequence && p.surpriseScore >= 0.7)
        rules.push({ type: 'behavioral', sequence: p.toolSequence, surprise: p.surpriseScore, source: 'federated' });
      if (p.layers && p.layers.length >= 2 && p.severity >= 7)
        rules.push({ type: 'threshold_adjust', layers: p.layers, severity: p.severity, source: 'federated' });
      if (p.influenceType && p.categories)
        rules.push({ type: 'taxonomy_weight', influenceType: p.influenceType, categories: p.categories, source: 'federated' });
    }
    return { applied: rules.length, rules };
  }

  /** Local stats for CLI display. */
  getStats() {
    const store = loadLocalPatterns();
    const now = Date.now();
    const recentContribs = (store.rateWindow || []).filter(t => now - t < 3600000).length;
    return {
      instanceId: this.instanceId.slice(0, 8) + '...',
      shareEnabled: this.shareEnabled,
      endpoint: this.endpoint || 'none',
      localPatterns: store.patterns.length,
      totalContributions: (store.contributions || []).length,
      contributionsThisHour: recentContribs,
      rateLimit: `${recentContribs}/${this.maxContributionsPerHour}`,
      lastSync: store.lastSync || 'never',
    };
  }
}

if (require.main === module) {
  const intel = new FederatedThreatIntel();
  const stats = intel.getStats();
  console.log('Federated Threat Intelligence — Local Stats\n');
  for (const [key, val] of Object.entries(stats)) console.log(`  ${key.padEnd(24)} ${val}`);
}

module.exports = { FederatedThreatIntel, abstractTool, getOrCreateInstanceId };
