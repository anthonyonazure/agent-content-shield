/**
 * Agent Content Shield — NLI Intent Classifier (Layer 2.5)
 *
 * Replaces embedding-similarity with Natural Language Inference.
 * Instead of "does this text LOOK LIKE known injection?"
 * asks "does this text INTEND to do something malicious?"
 *
 * This is vocabulary-independent: passive voice, synonym chains,
 * legal framing, Socratic questions — all caught because the
 * classifier reasons about INTENT, not WORDS.
 *
 * Uses Claude Haiku for speed (~200ms) with Sonnet fallback for
 * borderline cases. Falls back to local deepseek-r1:8b if no API key.
 *
 * Architecture:
 *   Layer 1: Regex (instant, pattern matching)
 *   Layer 2: Embedding scan (50ms, catches near-matches to seeds)
 *   Layer 2.5: NLI Intent Classifier (200ms, catches paraphrased intent) ← NEW
 *   Layer 3: Full LLM analysis (500ms, borderline tiebreaker)
 */

// ═══════════════════════════════════════════════════════════════════════
// THREAT INTENTS — What the attacker is TRYING TO DO, not how they say it
// ═══════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

// ═══════════════════════════════════════════════════════════════════════
// SHARED INTENT TAXONOMY
// v0.4.2: THREAT_INTENTS + NLI_SYSTEM_PROMPT are loaded from
// core/nli-intents.json so the Python port reads identical data. Before
// v0.4.2 the JS kept inline copies that drifted whenever either language
// was tuned. The JSON is the source of truth.
// ═══════════════════════════════════════════════════════════════════════
function loadSharedIntents() {
  const p = require('path').join(__dirname, 'nli-intents.json');
  try {
    return JSON.parse(require('fs').readFileSync(p, 'utf-8'));
  } catch (e) {
    throw new Error(
      'agent-content-shield: failed to load ' + p + ': ' + e.message
    );
  }
}
const _INTENTS_FILE = loadSharedIntents();
const THREAT_INTENTS = _INTENTS_FILE.intents;
const NLI_SYSTEM_PROMPT = _INTENTS_FILE.system_prompt;

// ═══════════════════════════════════════════════════════════════════════
// Wave6-Fix: Shared JSON extraction with intent validation.
// Both Claude and Ollama paths now use this to prevent attacker-embedded
// JSON with fake "benign: true" from being accepted.
const VALID_INTENT_IDS = new Set(THREAT_INTENTS.map(t => t.id));

function extractAndValidateJson(content) {
  const jsonObjects = [];
  const jsonRx = /\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}/g;
  let jm;
  while ((jm = jsonRx.exec(content)) !== null) {
    try { jsonObjects.push(JSON.parse(jm[0])); } catch {}
  }
  // Take the last valid JSON object (model's response, not echoed input)
  const parsed = jsonObjects[jsonObjects.length - 1];
  if (!parsed) return null;
  // Validate that matched intents use known IDs — attacker can't invent fake "benign" intents
  const validMatches = (parsed.matches || []).filter(m => VALID_INTENT_IDS.has(m.intent));
  return {
    matches: validMatches,
    benign: validMatches.length === 0 ? (parsed.benign ?? true) : false,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// NLI CLASSIFICATION VIA CLAUDE API
// ═══════════════════════════════════════════════════════════════════════

let anthropicClient = null;
let apiAvailable = null;

// Load API key from .env file if not in environment
function loadApiKey() {
  if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY;
  try {
    const fs = require('fs');
    const path = require('path');
    const envPath = path.join(__dirname, '..', '.env');
    const envText = fs.readFileSync(envPath, 'utf-8');
    for (const line of envText.split('\n')) {
      const m = line.match(/^ANTHROPIC_API_KEY\s*=\s*(.+)$/);
      if (m) {
        process.env.ANTHROPIC_API_KEY = m[1].trim();
        return m[1].trim();
      }
    }
  } catch {}
  return null;
}

function getClient() {
  if (anthropicClient) return anthropicClient;
  try {
    const key = loadApiKey();
    if (!key) return null;
    const Anthropic = require('@anthropic-ai/sdk');
    anthropicClient = new Anthropic({ apiKey: key });
    return anthropicClient;
  } catch {
    return null;
  }
}


async function classifyWithClaude(text, model = 'claude-haiku-4-5-20251001') {
  const client = getClient();
  if (!client) return null;

  try {
    const response = await client.messages.create({
      model,
      max_tokens: 512,
      system: NLI_SYSTEM_PROMPT,
      // Wave5-Fix W5-04: Scan more content — attackers placed payloads past 3000 chars
      // Haiku supports 200k context, so we can safely send more
      messages: [{ role: 'user', content: `Classify this text:\n\n${text.slice(0, 8000)}` }],
    });

    const content = response.content[0]?.text || '';

    // Wave6-Fix: Validate parsed intents against known set to prevent
    // attacker-embedded JSON with fake "benign: true" from being accepted.
    const parsed = extractAndValidateJson(content);
    if (!parsed) return null;
    return { ...parsed, model, raw: content.slice(0, 300) };
  } catch (e) {
    // API error — return null to signal fallback
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// FALLBACK: NLI via local Ollama (deepseek-r1:8b)
// ═══════════════════════════════════════════════════════════════════════

const OLLAMA_BASE = process.env.OLLAMA_URL || 'http://localhost:11434';

async function classifyWithOllama(text) {
  // Wave6-Fix: Removed /no_think — let the model reason for security decisions
  const prompt = `${NLI_SYSTEM_PROMPT}

Classify this text:

${text.slice(0, 2000)}`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    const res = await fetch(`${OLLAMA_BASE}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: process.env.SHIELD_CLASSIFIER_MODEL || 'deepseek-r1:8b',
        prompt,
        stream: false,
        options: { temperature: 0.0, num_predict: 512, num_ctx: 4096 },
      }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;

    const data = await res.json();
    const content = (data.response || '').replace(/<think>[\s\S]*?<\/think>/g, '').trim();

    // Wave6-Fix: Use same validated JSON extraction as Claude path
    const parsed = extractAndValidateJson(content);
    if (!parsed) return null;
    return { ...parsed, model: 'deepseek-r1:8b', raw: content.slice(0, 300) };
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN NLI CLASSIFICATION FUNCTION
// ═══════════════════════════════════════════════════════════════════════

/**
 * nliClassify(text) — Classify text via NLI intent matching
 *
 * Tries Claude Haiku first (fast, high quality), falls back to
 * Claude Sonnet (if Haiku uncertain), then Ollama deepseek-r1:8b.
 *
 * Returns: {
 *   injection: boolean,
 *   confidence: number,
 *   intents: [{id, confidence, evidence}],
 *   model: string,
 *   latencyMs: number,
 * }
 */
async function nliClassify(text) {
  const start = Date.now();

  // Try Claude Haiku first (fastest, cheapest)
  let result = await classifyWithClaude(text, 'claude-haiku-4-5-20251001');

  // If Haiku returns borderline results, escalate to Sonnet
  if (result && result.matches.length > 0) {
    const maxConf = Math.max(...result.matches.map(m => m.confidence));
    if (maxConf > 0.3 && maxConf < 0.7) {
      // Borderline — escalate to Sonnet for higher quality
      const sonnetResult = await classifyWithClaude(text, 'claude-sonnet-4-6');
      if (sonnetResult) result = sonnetResult;
    }
  }

  // Fallback to Ollama if no API
  if (!result) {
    result = await classifyWithOllama(text);
  }

  // Wave4-Fix: Fail CLOSED when all classifiers are unavailable
  // Previously returned injection: false, which was the most critical bypass
  if (!result) {
    return {
      injection: true,  // Assume hostile when we can't classify
      confidence: 0.5,
      intents: [{ intent: 'classifier_unavailable', confidence: 0.5, severity: 7 }],
      maxSeverity: 7,
      model: 'none',
      latencyMs: Date.now() - start,
      warning: 'All classifiers unavailable — failing closed',
    };
  }

  // Compute aggregate injection signal
  const highConfMatches = (result.matches || []).filter(m => m.confidence >= 0.6);
  const maxConf = result.matches.length > 0
    ? Math.max(...result.matches.map(m => m.confidence || 0))
    : 0;

  // Map matched intents to severity scores
  const matchedIntents = (result.matches || []).map(m => {
    const intent = THREAT_INTENTS.find(t => t.id === m.intent);
    return {
      ...m,
      severity: intent?.severity || 7,
    };
  });

  return {
    injection: highConfMatches.length > 0,
    confidence: maxConf,
    intents: matchedIntents,
    maxSeverity: matchedIntents.length > 0 ? Math.max(...matchedIntents.map(m => m.severity)) : 0,
    model: result.model,
    benign: result.benign,
    latencyMs: Date.now() - start,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════

module.exports = {
  nliClassify,
  classifyWithClaude,
  classifyWithOllama,
  THREAT_INTENTS,
  NLI_SYSTEM_PROMPT,
};
