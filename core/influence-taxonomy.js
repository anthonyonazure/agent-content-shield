/**
 * Agent Content Shield — Influence Taxonomy Classifier
 *
 * Categorizes detected threats into 4 influence types with graduated responses.
 * Each type represents a distinct axis of AI agent manipulation:
 *
 *   SCOPE_ESCALATION    — agent accessing resources outside normal scope
 *   AUTHORITY_INVERSION — agent treating external content as authoritative
 *   AUTONOMY_REDUCTION  — agent decision-making being funneled
 *   EPISTEMIC_CORRUPTION — agent's world model being distorted
 *
 * Usage:
 *   const { classifyInfluence } = require('./influence-taxonomy');
 *   const classifications = classifyInfluence(scanResult, context);
 */

// ── Signal Patterns ───────────────────────────────────────────────

const SIGNALS = {
  SCOPE_ESCALATION: {
    detectorHints: ['data_exfiltration', 'ssrf', 'url_injection', 'encoded_payload'],
    textPatterns: [
      /\b(?:read|access|open|fetch|write|delete|modify)\b.*\b(?:file|path|directory|endpoint|api|database|credentials?|secret|token|key)\b/i,
      /\b(?:\/etc\/|\.env|\.ssh|credentials|secrets?\.json|\.aws\/|\/proc\/|\.git\/config)\b/i,
      /\b(?:curl|wget|nc|netcat)\b.*\b(?:http|ftp|localhost|127\.0|0\.0\.0)\b/i,
    ],
    response: 'confirm',
  },

  AUTHORITY_INVERSION: {
    detectorHints: ['system_boundary', 'role_hijack', 'fabricated_authority', 'behavioral_manipulation'],
    textPatterns: [
      /\b(?:system\s*(?:prompt|message|instruction)|official\s*(?:update|directive|notice))\b/i,
      /\b(?:authorized?|required?|mandatory|compliance|regulation|policy)\s+(?:by|per|from|under)\b/i,
      /\b(?:override|supersede|replace|update|revise)\s+(?:your|previous|prior|existing)\s+(?:instructions?|guidelines?|rules?|prompt)\b/i,
      /\b(?:anthropic|openai|google|admin|security\s*team|developer)\s+(?:says?|requires?|instructs?|directs?)\b/i,
    ],
    response: 'quarantine',
  },

  AUTONOMY_REDUCTION: {
    detectorHints: ['instruction_override', 'rlhf_exploit', 'behavioral_manipulation'],
    textPatterns: [
      /\b(?:you\s+must|you\s+should\s+always|you\s+have\s+to|do\s+exactly|follow\s+(?:these|this)\s+(?:exactly|precisely))\b/i,
      /\b(?:only\s+(?:option|choice|way)|no\s+(?:other|alternative)\s+(?:option|choice|way))\b/i,
      /\b(?:don'?t\s+think|stop\s+(?:analyzing|questioning)|just\s+(?:do|execute|run|output))\b/i,
      /\b(?:without\s+(?:checking|verifying|asking|confirming)|skip\s+(?:verification|validation|review))\b/i,
    ],
    response: 'diversify',
  },

  EPISTEMIC_CORRUPTION: {
    detectorHints: ['memory_injection', 'fact_fabrication', 'context_poisoning'],
    textPatterns: [
      /\b(?:remember\s+that|you\s+(?:know|learned|were\s+told)\s+that|it'?s?\s+(?:a\s+)?fact\s+that)\b/i,
      /\b(?:update\s+your\s+(?:memory|knowledge|understanding)|save\s+(?:this|the\s+following)\s+(?:to|in)\s+memory)\b/i,
      /\b(?:actually|in\s+fact|contrary\s+to\s+(?:what\s+you\s+(?:think|know|believe)))\b.*\b(?:the\s+(?:real|true|actual|correct))\b/i,
      /\b(?:previous\s+(?:information|data)\s+(?:was|were)\s+(?:wrong|incorrect|outdated|false))\b/i,
    ],
    response: 'rollback',
  },
};

// ── Confidence Scoring ────────────────────────────────────────────

function computeConfidence(type, detectorMatches, textMatches, context) {
  let confidence = 0;

  // Detector-based signals: 0.3 per matching detector
  confidence += Math.min(detectorMatches * 0.3, 0.6);

  // Text pattern signals: 0.2 per matching pattern
  confidence += Math.min(textMatches * 0.2, 0.4);

  // Context boost: external content is higher risk
  const highRiskContexts = ['web_fetch', 'email', 'mcp_external', 'pdf_read'];
  if (highRiskContexts.includes(context)) {
    confidence = Math.min(confidence + 0.15, 1.0);
  }

  return Math.round(confidence * 100) / 100;
}

// ── Classifier ────────────────────────────────────────────────────

/**
 * Classify scan findings into influence taxonomy types.
 *
 * @param {Object} scanResult — output from scanner.scan() or detectors.scanContent()
 * @param {Object} context — { context: string, toolName?: string, text?: string }
 * @returns {Array<{ type, confidence, evidence, recommendedResponse }>}
 */
function classifyInfluence(scanResult, context = {}) {
  if (!scanResult || scanResult.clean) return [];

  const findings = scanResult.findings || [];
  const detectorNames = findings.map(f => f.detector);
  const text = context.text || '';
  const ctx = context.context || 'general';

  const classifications = [];

  for (const [type, signals] of Object.entries(SIGNALS)) {
    const evidence = [];

    // Check detector hint matches
    const detectorMatches = signals.detectorHints.filter(hint =>
      detectorNames.some(d => d.includes(hint) || hint.includes(d))
    );
    if (detectorMatches.length > 0) {
      evidence.push(`detectors: ${detectorMatches.join(', ')}`);
    }

    // Check text pattern matches (only if text provided)
    let textMatches = 0;
    if (text) {
      for (const pattern of signals.textPatterns) {
        const match = text.match(pattern);
        if (match) {
          textMatches++;
          evidence.push(`pattern: "${match[0].slice(0, 80)}"`);
        }
      }
    }

    // Require at least one signal to classify
    if (detectorMatches.length === 0 && textMatches === 0) continue;

    const confidence = computeConfidence(type, detectorMatches.length, textMatches, ctx);
    if (confidence < 0.15) continue; // noise floor

    classifications.push({
      type,
      confidence,
      evidence,
      recommendedResponse: signals.response,
    });
  }

  // Sort by confidence descending
  classifications.sort((a, b) => b.confidence - a.confidence);

  return classifications;
}

/**
 * Get human-readable description for a response type.
 */
function describeResponse(responseType) {
  const descriptions = {
    confirm: 'Ask user to confirm before proceeding — agent may be accessing out-of-scope resources.',
    quarantine: 'Isolate content — external source is asserting false authority over the agent.',
    diversify: 'Force consideration of alternatives — agent decisions are being funneled.',
    rollback: 'Discard potentially corrupted context — agent world model may be distorted.',
  };
  return descriptions[responseType] || 'Unknown response type.';
}

module.exports = {
  classifyInfluence,
  describeResponse,
  SIGNALS,
  computeConfidence,
};
