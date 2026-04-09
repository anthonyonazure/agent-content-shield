# Agent Content Shield

Defense framework against AI agent content injection, memory poisoning, and RAG attacks. Platform-agnostic with adapters for Claude Code, MCP middleware, and CLI.

## Why This Exists

AI agents (Claude Code, MCP-connected tools, RAG pipelines) consume content from untrusted sources: web pages, emails, PDFs, knowledge bases, user-uploaded documents. That content can contain prompt injection attacks that hijack the agent's behavior, exfiltrate data, poison memory stores, or escalate privileges.

Most prompt injection defenses live inside the model. Agent Content Shield works **outside the model** as an independent content firewall. It scans everything flowing into and out of agent tools before the model ever sees it, catching attacks at the infrastructure layer rather than relying on the model to self-police.

This project was born from a real need: protecting a Claude Code setup with 15+ MCP servers, long-term memory systems, and knowledge bases from content injection across those trust boundaries. After building it, a coordinated red team of 6 specialized AI agents stress-tested it with 95+ attack vectors across 5 waves, hardening it to a 98% catch rate.

## What It Does

### 4-Layer Defense-in-Depth Pipeline

```
Content In
    |
    v
[Layer 1: Regex + Heuristics]  <5ms
    |  500+ patterns, 23 languages, 40+ semantic heuristics
    |  Catches: direct injection, role hijacking, credential access,
    |  system boundary faking, SSRF, hidden content, encoding tricks
    |
    v
[Layer 2: Embedding Similarity]  ~50ms
    |  77-phrase injection seed bank (Ollama nomic-embed-text)
    |  Cosine similarity against known attack embeddings
    |  <0.78 pass | 0.78-0.88 escalate | >0.88 block
    |
    v
[Layer 3: LLM Classifier]  ~500ms
    |  Intent classification via local LLM (Ollama deepseek-r1:8b)
    |  Detects: polymorphic paraphrases, narrative embedding,
    |  metaphorical attacks, fabricated authority
    |
    v
[Layer 4: NLI Intent Classifier]  ~200ms  (opt-in)
    |  Claude Haiku API or Ollama fallback
    |  Resolves metaphorical/domain-framed attacks
    |
    v
Result: PASS | WARN | SANITIZE | BLOCK
```

Only content that passes Layer 1 reaches Layer 2. Only borderline Layer 2 cases reach Layer 3. Most benign content exits at Layer 1 in under 5ms.

### What It Catches

**Direct Attacks** -- instruction override, role hijacking, system boundary faking (`[SYSTEM]`, `[INST]`, `<|system|>`), behavioral manipulation, data exfiltration, credential harvesting

**Encoding Evasion** -- base64, hex, HTML entities, JavaScript unicode escapes, CSS unicode escapes, URL encoding, zero-width character insertion, Unicode NFKC bypass

**Homoglyph Attacks** -- Cyrillic (a/e/o/p/c/x), Greek, Armenian, Cherokee character substitution

**Hidden Content** -- CSS `display:none`, `visibility:hidden`, `opacity:0`, `@font-face` glyph remapping, CSS `var()` reconstruction, HTML comment injection

**Semantic Injection** -- passive voice exfiltration, legal/regulatory framing, educational/red-team pretexts, Socratic question framing, metaphorical extraction, completion priming, authority fabrication

**Infrastructure** -- SSRF (localhost, metadata endpoints, decimal/hex/octal IPs), blocked exfiltration domains (webhook.site, requestbin, ngrok, etc.), DNS rebinding patterns

**Multilingual** -- injection patterns in 23 languages (Spanish, French, German, Chinese, Russian, Japanese, Korean, Arabic, Hindi, and more)

**Memory Poisoning** -- behavioral override attempts, internal file reference probing (`.env`, `CLAUDE.md`, `settings.json`)

**Document Injection** -- PDF JavaScript/URI injection, markdown tracking beacons, HTML `<script>`/`<iframe>`/`<object>` tags

### Preprocessing

Before any detection runs, content goes through:
- Zero-width character stripping (ZWS, ZWNJ, ZWJ, soft hyphens, bidi overrides)
- Unicode NFKC normalization (fullwidth to ASCII)
- HTML entity decoding
- Homoglyph translation (Cyrillic/Greek/Armenian/Cherokee to Latin)
- Diacritical mark stripping
- Base64/hex payload extraction and decode
- Recursive text extraction from nested objects (depth limit 20)
- Integrity verification of signature database (SHA-256)

## What It Doesn't Do

- **It's not a WAF.** It doesn't sit in front of a web server. It sits between an AI agent and its tool outputs.
- **It can't read images.** Steganographic injection in images (pixel-level instructions) is flagged with a warning but not analyzed. Image analysis would require a vision model in the pipeline.
- **It doesn't replace model-level safety.** This is defense-in-depth. The model's own guardrails are still your first line. This catches what gets past them, or what arrives before the model processes it.
- **Bash monitoring is new and pattern-based.** The `pre-bash` hook (v0.3.0) scans commands before execution for exfiltration, reverse shells, sensitive file access, and rogue script execution. It's regex-based, so novel obfuscation may evade it.
- **It's not production-hardened for high-throughput.** Designed for developer workstation use (single agent, moderate request volume). Not benchmarked for thousands of concurrent scans.
- **Cross-temporal analysis is limited.** It scans content per-source. Benign fragments that reconstitute as attacks across multiple sources or sessions are not yet detected.
- **Python parity is incomplete.** The Python detector (`core/detectors.py`) lacks the Wave 2-5 Unicode defenses that the JavaScript engine has.

## Architecture

```
agent-content-shield/
  core/
    detectors.js          # Main regex + heuristic engine (Layer 1)
    semantic-detector.js   # Embedding + LLM classifier (Layers 2-3)
    nli-classifier.js      # NLI intent classifier (Layer 4, opt-in)
    signatures.json        # Threat pattern library (500+ patterns)
    detectors.py           # Python equivalent (partial parity)
  adapters/
    claude-code/
      hooks.js             # Claude Code PreToolUse/PostToolUse hooks
    mcp-middleware/         # MCP protocol adapter
    stdin-pipe/
      scan.js              # Universal pipe adapter
  cli/
    shield.js              # CLI commands (scan, scan-dir, validate-url)
  config/
    default.yaml           # Thresholds, trusted/blocked domains, tool mappings
  test/
    detectors.test.js      # Core detector tests (50+ cases)
    semantic.test.js       # Semantic layer tests
    run.js                 # Test orchestrator
  logs/                    # Detection logs (JSONL)
```

## Requirements

### Minimum (Layer 1 only)
- **Node.js >= 18**
- No other dependencies for regex-based detection

### Full Pipeline (Layers 1-3)
- **Ollama** running locally at `localhost:11434`
- **nomic-embed-text** model (~270MB) for embedding extraction
- **deepseek-r1:8b** model (~4.7GB) for LLM classification

### Layer 4 (NLI, opt-in)
- **Anthropic API key** for Claude Haiku classification, or falls back to Ollama

### Install

```bash
git clone https://github.com/anthonyonazure/agent-content-shield.git
cd agent-content-shield
npm install

# For semantic layers (optional):
ollama pull nomic-embed-text
ollama pull deepseek-r1:8b
```

## Usage

### Claude Code Hooks

Register in your Claude Code `settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "WebFetch",
        "hooks": [{
          "type": "command",
          "command": "node /path/to/agent-content-shield/adapters/claude-code/hooks.js pre-fetch"
        }]
      },
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "node /path/to/agent-content-shield/adapters/claude-code/hooks.js pre-bash"
        }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [{
          "type": "command",
          "command": "node /path/to/agent-content-shield/adapters/claude-code/hooks.js postContentScanner"
        }]
      }
    ]
  }
}
```

### CLI

```bash
# Scan a file
npx shield scan document.md

# Scan a directory recursively
npx shield scan-dir ./downloaded-docs

# Validate a URL against SSRF/blocklist
npx shield validate-url https://webhook.site/abc123
```

### Pipe

```bash
curl https://example.com | node adapters/stdin-pipe/scan.js --context web_fetch
cat untrusted-doc.md | node adapters/stdin-pipe/scan.js --sanitize
```

### Programmatic

```javascript
const { scanContent, validateUrl } = require('./core/detectors');

const result = scanContent(untrustedText, { context: 'web_fetch' });
if (result.maxSeverity >= 8) {
  console.log('Blocked:', result.findings);
}

const urlCheck = validateUrl('http://169.254.169.254/metadata', SIGS);
if (urlCheck.blocked) {
  console.log('SSRF attempt blocked');
}
```

## Configuration

Edit `config/default.yaml`:

```yaml
# Severity threshold for sanitization (strip payloads)
sanitize_threshold: 8

# Risk score threshold for blocking memory writes
block_threshold: 0.4

# Domains that bypass URL validation
trusted_domains:
  - github.com
  - docs.microsoft.com
  - anthropic.com
  # ...

# Domains that are always blocked (exfiltration endpoints)
blocked_domains:
  - webhook.site
  - requestbin.com
  - interact.sh
  # ...

# Semantic layer (requires Ollama)
semantic:
  enabled: true
  embed_alert_threshold: 0.78
  embed_block_threshold: 0.88
  classifier_threshold: 0.70
```

## Testing

```bash
# Fast: regex + heuristic tests only
npm test

# Include semantic layer tests (requires Ollama)
npm run test:semantic

# Everything
npm run test:all
```

The test suite includes 50+ core detector tests plus red team attack vectors from 5 progressive waves covering 21 attack classes.

## Red Team Results

The framework has been through a coordinated red team exercise using 6 specialized AI agents simulating nation-state threat actors (NSA TAO, Chinese MSS, Russian GRU, North Korean Lazarus). The full report is in [RED-TEAM-REPORT.md](RED-TEAM-REPORT.md).

**Results**: 4 CRITICAL, 6 HIGH, 6 MEDIUM findings across 95+ attack vectors. Post-remediation catch rate: **98%**.

Notable attack chains discovered:
- Cyrillic SSRF + Ollama DoS = permanent semantic bypass
- Python Unicode gap + classifier injection = double gate bypass
- Config theater + unmonitored Bash = invisible exfiltration
- Statistical short-circuit + passive voice injection = full pipeline evasion

## Known Gaps and Future Work

### Open Vulnerabilities
- **Ollama has no authentication** -- port squatting risk mitigated by model integrity checks (v0.3.0) but not fully solved
- **50+ languages uncovered** -- multilingual detection covers 23 of 70+ languages (expansion in progress)

### What Would Make It Better
- **Ollama mTLS or API key auth** to prevent port squatting
- **Image analysis pipeline** -- vision model to detect steganographic injection
- **Broader multilingual coverage** -- expand from 23 to 70+ languages
- **Embedding ensemble** -- two embedding models to resist adversarial suffix attacks
- **Statistical gate hardening** -- remove the score < 0.15 fast-path that allows semantic bypass
- **Metrics dashboard** -- visualize detection logs, false positive rates, latency percentiles
- **Write/Edit tool pre-hooks** -- scan content before file writes to config/settings

## Graceful Degradation

The shield is designed to degrade gracefully:

| Condition | Behavior |
|-----------|----------|
| Ollama not running | Layers 2-3 skipped, TF-IDF + entropy fallback active, Layer 1 (regex) still active |
| Anthropic API key missing | Layer 4 falls back to Ollama, or skips |
| `signatures.json` tampered | SHA-256 integrity check against known-good hash fails, scan aborts |
| Ollama model replaced | Canary embedding integrity check detects dimension/magnitude anomalies |
| Scan timeout (>30s) | Fail-open with warning logged |
| Unknown tool name | Classified as `general` context, full Layer 1 scan applied |

## License

MIT

## Author

Anthony Clendenen -- [@anthonyonazure](https://github.com/anthonyonazure)
