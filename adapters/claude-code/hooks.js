/**
 * Agent Content Shield — Claude Code Adapter
 *
 * Thin wrappers that translate Claude Code's hook contract
 * (stdin JSON → stdout JSON) to the core detection engine.
 *
 * Three hooks:
 *   1. pre-fetch    — PreToolUse on WebFetch (URL validation)
 *   2. post-content — PostToolUse on content tools (output scanning)
 *   3. pre-memory   — PreToolUse on memory write tools (input validation)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const yaml = require ? undefined : undefined; // yaml optional

const core = require('../../core/detectors');

// Load config
let CONFIG = {};
try {
  // Try yaml first, fall back to defaults
  const cfgPath = path.join(__dirname, '..', '..', 'config', 'default.yaml');
  const cfgText = fs.readFileSync(cfgPath, 'utf-8');
  // Simple yaml parser for flat config (no dependency needed)
  CONFIG = {};
  for (const line of cfgText.split('\n')) {
    const m = line.match(/^(\w+):\s+(\d+(?:\.\d+)?)\s*$/);
    if (m) CONFIG[m[1]] = parseFloat(m[2]);
  }
} catch {}

const SANITIZE_THRESHOLD = CONFIG.sanitize_threshold || 8;
const LOG_DIR = path.join(__dirname, '..', '..', 'logs');

function ensureLogDir() {
  try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch {}
}

function logDetection(data) {
  ensureLogDir();
  try {
    fs.appendFileSync(
      path.join(LOG_DIR, 'detections.jsonl'),
      JSON.stringify({ ts: new Date().toISOString(), ...data }) + '\n'
    );
  } catch {}
}

// ── Hook: Pre-Fetch Guard ───────────────────────────────────────────

function preFetchGuard() {
  const input = JSON.parse(fs.readFileSync(0, 'utf-8'));
  const { tool_name, tool_input } = input;

  if (tool_name !== 'WebFetch') {
    return respond({ decision: 'allow' });
  }

  const url = tool_input?.url || tool_input?.URL || '';
  if (!url) return respond({ decision: 'allow' });

  const result = core.validateUrl(url, core.SIGS);
  if (!result.allowed) {
    logDetection({ hook: 'pre-fetch', url, reason: result.reason });
    return respond({ decision: 'block', reason: `Content Shield: ${result.reason}` });
  }

  respond({ decision: 'allow' });
}

// ── Hook: Post-Content Scanner ──────────────────────────────────────

function postContentScanner() {
  const input = JSON.parse(fs.readFileSync(0, 'utf-8'));
  const { tool_name, tool_input, tool_output } = input;

  // Determine context from tool name
  let context = 'general';
  if (tool_name === 'WebFetch') context = 'web_fetch';
  else if (tool_name === 'Read' && tool_input?.file_path?.toLowerCase().endsWith('.pdf')) context = 'pdf_read';
  else if (tool_name?.includes('Gmail') || tool_name?.includes('email')) context = 'email';
  else if (tool_name?.includes('search') || tool_name?.includes('query')) context = 'knowledge_query';

  const text = extractText(tool_output);
  if (!text || text.length < 20) return respond({ decision: 'allow' });

  const result = core.scanContent(text, { context });
  if (result.clean) return respond({ decision: 'allow' });

  logDetection({
    hook: 'post-content',
    tool: tool_name,
    source: tool_input?.url || tool_input?.file_path || '',
    maxSev: result.maxSeverity,
    detections: result.totalDetections,
  });

  const warning = core.formatWarning(result);
  const output = result.maxSeverity >= SANITIZE_THRESHOLD
    ? warning + '\n[CONTENT SANITIZED]\n\n' + core.sanitizeContent(text)
    : warning + '\n' + text;

  respond({
    decision: 'allow',
    reason: `Content Shield: ${result.totalDetections} threat(s), severity ${result.maxSeverity}/10`,
    modified_output: output,
  });
}

// ── Hook: Pre-Memory Write Guard ────────────────────────────────────

function preMemoryGuard() {
  const input = JSON.parse(fs.readFileSync(0, 'utf-8'));
  const { tool_name, tool_input } = input;

  const content = extractMemoryContent(tool_name, tool_input);
  if (!content) return respond({ decision: 'allow' });

  // Use Python detector for memory validation (richer analysis)
  const result = validateViaPython(content, guessSource(tool_name), extractMetadata(tool_input));

  logDetection({
    hook: 'pre-memory',
    tool: tool_name,
    passed: result.passed,
    risk: result.risk_score,
    flags: result.flags,
  });

  if (!result.passed) {
    return respond({
      decision: 'block',
      reason: [
        'Content Shield: Memory write BLOCKED',
        `  Source: ${guessSource(tool_name)}`,
        `  Risk: ${result.risk_score.toFixed(2)}`,
        `  Flags: ${result.flags.join(', ')}`,
        '  Review the content and retry manually if legitimate.',
      ].join('\n'),
    });
  }

  respond({ decision: 'allow' });
}

// ── Helpers ─────────────────────────────────────────────────────────

function respond(obj) {
  process.stdout.write(JSON.stringify(obj));
}

function extractText(output) {
  if (!output) return '';
  if (typeof output === 'string') return output;
  if (output.stdout) return output.stdout;
  if (output.content) {
    if (typeof output.content === 'string') return output.content;
    if (Array.isArray(output.content)) return output.content.map(c => c.text || '').join('\n');
  }
  return JSON.stringify(output);
}

function extractMemoryContent(toolName, toolInput) {
  if (!toolInput) return null;
  // Generic extraction — works with any tool that has 'content' in input
  if (toolInput.content) return toolInput.content;
  if (toolInput.observation) return toolInput.observation;
  if (toolInput.text) return toolInput.text;
  // Forgetful-style nested arguments
  if (toolInput.arguments?.content) return toolInput.arguments.content;
  if (toolInput.arguments?.title) return toolInput.arguments.title;
  return null;
}

function guessSource(toolName) {
  if (!toolName) return 'unknown';
  const lower = toolName.toLowerCase();
  if (lower.includes('engram')) return 'engram';
  if (lower.includes('grug')) return 'grug-brain';
  if (lower.includes('forgetful') || lower.includes('mem0')) return 'forgetful';
  if (lower.includes('zep')) return 'zep';
  return 'unknown';
}

function extractMetadata(toolInput) {
  if (!toolInput?.arguments) return {};
  const a = toolInput.arguments;
  return {
    confidence: a.confidence,
    encoding_agent: a.encoding_agent,
    source_repo: a.source_repo,
  };
}

function validateViaPython(content, source, metadata) {
  const os = require('os');
  const tmpInput = path.join(os.tmpdir(), `shield-${process.pid}.json`);
  const tmpScript = path.join(os.tmpdir(), `shield-${process.pid}.py`);
  const coreDir = path.join(__dirname, '..', '..', 'core').replace(/\\/g, '/');

  try {
    fs.writeFileSync(tmpInput, JSON.stringify({ content, source, metadata }));
    const pyCode = `
import sys, json
sys.path.insert(0, r'${coreDir}')
from detectors import validate_memory_write
with open(r'${tmpInput.replace(/\\/g, '/')}', 'r', encoding='utf-8') as f:
    data = json.load(f)
r = validate_memory_write(data['content'], data['source'], data.get('metadata', {}))
print(json.dumps({"passed": r.passed, "risk_score": r.risk_score, "flags": r.flags}))
`;
    fs.writeFileSync(tmpScript, pyCode);
    const output = execSync(`python "${tmpScript}"`, {
      timeout: 8000, encoding: 'utf-8', windowsHide: true,
    });
    return JSON.parse(output.trim());
  } catch {
    return { passed: true, risk_score: 0, flags: ['validation_error'] };
  } finally {
    try { fs.unlinkSync(tmpInput); } catch {}
    try { fs.unlinkSync(tmpScript); } catch {}
  }
}

// ── Entrypoint ──────────────────────────────────────────────────────
// Determine which hook to run based on argv or environment

const hookType = process.argv[2] || process.env.SHIELD_HOOK || 'post-content';

switch (hookType) {
  case 'pre-fetch':    preFetchGuard(); break;
  case 'post-content': postContentScanner(); break;
  case 'pre-memory':   preMemoryGuard(); break;
  default:             postContentScanner(); break;
}
