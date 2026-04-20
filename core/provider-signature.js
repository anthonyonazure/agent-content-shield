/**
 * Agent Content Shield — Provider Signature Verification Stub
 *
 * Per the "Your Agent Is Mine" paper (Liu et al., 2026), the fundamental
 * fix for router-in-the-middle attacks is provider-signed response
 * envelopes — DKIM-like signatures over tool-call JSON that bind the
 * response to what the model actually produced.
 *
 * As of April 2026, NO major provider ships response signatures.
 * This module builds the verification interface NOW so that when
 * Anthropic/OpenAI/Google implement signing, the shield is ready.
 *
 * Expected signature format (proposed in paper's Appendix C):
 *   {
 *     "provider": "anthropic",
 *     "model": "claude-opus-4-6",
 *     "content_hash": "<sha256 of canonical response>",
 *     "tool_calls_hash": "<sha256 of canonical tool_calls array>",
 *     "finish_reason": "end_turn",
 *     "request_nonce": "<client-provided nonce>",
 *     "issued_at": 1712700000,
 *     "expires_at": 1712703600,
 *     "key_id": "prov-sig-key-2026-04",
 *     "signature": "<base64 Ed25519 signature>"
 *   }
 *
 * Headers to check:
 *   x-provider-signature: <base64 signature>
 *   x-provider-key-id: <key identifier>
 *   x-provider-content-hash: <sha256>
 */

const crypto = require('crypto');

// ── Provider Public Keys (populated when providers publish them) ──

const PROVIDER_KEYS = {
  // Placeholder entries — replace with real keys when published
  // 'anthropic': { keyId: 'prov-sig-key-2026-04', publicKey: '<Ed25519 PEM>', algorithm: 'Ed25519' },
  // 'openai': { keyId: 'oai-sig-key-2026-04', publicKey: '<Ed25519 PEM>', algorithm: 'Ed25519' },
  // 'google': { keyId: 'gcp-sig-key-2026-04', publicKey: '<Ed25519 PEM>', algorithm: 'Ed25519' },
};

// ── Status ────────────────────────────────────────────────────────

/**
 * Check if any provider has published signing keys.
 * This is the canary for when the ecosystem catches up.
 */
function isSigningAvailable() {
  return Object.keys(PROVIDER_KEYS).length > 0;
}

function supportedProviders() {
  return Object.keys(PROVIDER_KEYS);
}

// ── Canonicalization ──────────────────────────────────────────────
// The paper specifies canonical JSON (RFC 8785) for signing.
// This ensures deterministic serialization across implementations.

function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';

  // Sort keys lexicographically (RFC 8785 JCS)
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k]));
  return '{' + pairs.join(',') + '}';
}

function hashCanonical(obj) {
  return crypto.createHash('sha256').update(canonicalize(obj)).digest('hex');
}

// ── Nonce Generation ──────────────────────────────────────────────

/**
 * Generate a request nonce to include in API calls.
 * The provider should echo this nonce in the signed response.
 */
function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

// ── Signature Extraction ──────────────────────────────────────────

/**
 * Extract signature metadata from response headers.
 * Returns null if no signature headers are present.
 */
function extractSignature(headers) {
  if (!headers) return null;

  // Normalize header names to lowercase
  const normalized = {};
  for (const [k, v] of Object.entries(headers)) {
    normalized[k.toLowerCase()] = v;
  }

  const signature = normalized['x-provider-signature'];
  const keyId = normalized['x-provider-key-id'];
  const contentHash = normalized['x-provider-content-hash'];
  const provider = normalized['x-provider-name'] || normalized['x-provider'];

  if (!signature) return null;

  return {
    signature,
    keyId: keyId || null,
    contentHash: contentHash || null,
    provider: provider || null,
    // Also check for structured signature envelope in body
    raw: { signature, keyId, contentHash, provider },
  };
}

/**
 * Extract signature from response body (some providers may embed it).
 */
function extractBodySignature(responseBody) {
  if (!responseBody) return null;

  const body = typeof responseBody === 'string'
    ? (() => { try { return JSON.parse(responseBody); } catch { return null; } })()
    : responseBody;

  if (!body) return null;

  // Check for _signature or _integrity field
  if (body._signature || body._integrity) {
    return body._signature || body._integrity;
  }

  // Check for nested signature in metadata
  if (body.metadata?.signature) {
    return body.metadata.signature;
  }

  return null;
}

// ── Verification ──────────────────────────────────────────────────

/**
 * Verify a provider signature against the response content.
 *
 * @param {object} opts
 * @param {object} opts.responseBody - The full response JSON
 * @param {object} opts.headers - Response headers
 * @param {string} opts.requestNonce - The nonce sent with the request
 * @param {string} opts.expectedProvider - Expected provider name
 * @returns {object} Verification result
 */
function verify(opts) {
  // Step 1: Extract signature
  const headerSig = extractSignature(opts.headers);
  const bodySig = extractBodySignature(opts.responseBody);
  const sig = headerSig || bodySig;

  if (!sig) {
    return {
      status: 'unsigned',
      verified: false,
      reason: 'No provider signature found. Response integrity cannot be verified. ' +
              'This is expected as of April 2026 — no major provider ships response signatures yet.',
      recommendation: 'Monitor for provider signing support. When available, unsigned responses should be rejected.',
    };
  }

  // Step 2: Look up provider key
  const provider = sig.provider || opts.expectedProvider;
  const providerKey = PROVIDER_KEYS[provider];

  if (!providerKey) {
    return {
      status: 'unknown_provider',
      verified: false,
      provider,
      reason: `Signature present but no known public key for provider "${provider}".`,
      recommendation: 'Check for updated provider key configuration.',
    };
  }

  // Step 3: Verify content hash
  const expectedHash = hashCanonical(opts.responseBody);
  if (sig.contentHash && sig.contentHash !== expectedHash) {
    return {
      status: 'hash_mismatch',
      verified: false,
      provider,
      reason: 'Content hash does not match response body. POSSIBLE TAMPERING.',
      severity: 10,
      expected: expectedHash,
      found: sig.contentHash,
    };
  }

  // Step 4: Verify cryptographic signature
  try {
    const verifier = crypto.createVerify('SHA256');
    const signedPayload = canonicalize({
      provider,
      content_hash: expectedHash,
      request_nonce: opts.requestNonce,
      key_id: sig.keyId,
    });
    verifier.update(signedPayload);

    const valid = verifier.verify(providerKey.publicKey, sig.signature, 'base64');

    if (!valid) {
      return {
        status: 'signature_invalid',
        verified: false,
        provider,
        reason: 'Cryptographic signature verification FAILED. Response has been tampered with.',
        severity: 10,
      };
    }

    return {
      status: 'verified',
      verified: true,
      provider,
      keyId: sig.keyId,
      reason: 'Response signature verified — content matches provider output.',
    };
  } catch (e) {
    return {
      status: 'verification_error',
      verified: false,
      provider,
      reason: `Signature verification error: ${e.message}`,
    };
  }
}

/**
 * Check a response and return a shield-compatible finding if tampering detected.
 * For integration into the scan pipeline.
 */
function checkResponse(responseBody, headers, requestNonce) {
  const result = verify({
    responseBody,
    headers,
    requestNonce,
    expectedProvider: null,
  });

  if (result.status === 'hash_mismatch' || result.status === 'signature_invalid') {
    return {
      tampered: true,
      severity: 10,
      finding: {
        detector: `provider_signature:${result.status}`,
        severity: 10,
        count: 1,
        matches: [result.reason],
      },
      details: result,
    };
  }

  return {
    tampered: false,
    status: result.status,
    verified: result.verified,
    details: result,
  };
}

module.exports = {
  isSigningAvailable,
  supportedProviders,
  verify,
  checkResponse,
  generateNonce,
  extractSignature,
  extractBodySignature,
  canonicalize,
  hashCanonical,
  // For future use when providers publish keys
  PROVIDER_KEYS,
  // For testing
  _internals: { PROVIDER_KEYS },
};
