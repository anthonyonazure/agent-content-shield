#!/usr/bin/env node
/**
 * Agent Content Shield — Claude Code Post-Flight Hook
 *
 * Registered against the `Stop` and `SubagentStop` hook events so it
 * runs after the model has emitted its final response for a turn. If
 * the response matches compliance patterns (system-prompt leak, role
 * drift, execution acknowledgment), this hook reports a verdict back
 * to Claude Code via stdout JSON.
 *
 * Hook wiring in ~/.claude/settings.json:
 *   {
 *     "hooks": {
 *       "Stop": [{
 *         "matcher": "*",
 *         "hooks": [{
 *           "type": "command",
 *           "command": "node /path/to/agent-content-shield/adapters/claude-code/post-flight-hook.js"
 *         }]
 *       }]
 *     }
 *   }
 *
 * stdin contract: `{ transcript_path, stop_hook_active, ... }` (Claude
 * Code Stop-hook shape). We read the last assistant turn's text from
 * the transcript_path JSONL file — Claude Code's own journal.
 *
 * stdout contract: either empty (PASS) or a JSON object with at least
 * { "continue": false, "reason": "..." } to abort the run.
 *
 * Exit codes:
 *   0  — PASS or WARN (reported in systemMessage, doesn't halt the turn)
 *   2  — BLOCK / REDACT (blocking decision emitted on stdout)
 *
 * Non-existent transcript, non-JSON stdin, or missing config all fall
 * through to exit 0 with no output — hooks must never make a failing
 * Claude Code worse.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

let postFlight = null;
try {
  postFlight = require('../../core/post-flight');
} catch {
  // Module missing; fail open.
  process.exit(0);
}

let logger = null;
try {
  logger = require('../../pipeline/ingest');
} catch {
  // Learning pipeline optional; continue without it.
}

function loadConfig() {
  try {
    const cfgPath = path.join(__dirname, '..', '..', 'config', 'default.yaml');
    const raw = fs.readFileSync(cfgPath, 'utf-8');
    return yaml.load(raw) || {};
  } catch {
    return {};
  }
}

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
    // Hooks that never get stdin should fall through cleanly.
    setTimeout(() => resolve(data), 500).unref();
  });
}

function lastAssistantMessage(transcriptPath) {
  // Claude Code writes the transcript as JSONL, one message per line.
  // We walk from the end to find the most recent assistant message that
  // contains text content. Bounded by 2 MB to cap worst-case IO.
  if (!transcriptPath) return '';
  let raw;
  try {
    const stat = fs.statSync(transcriptPath);
    if (stat.size > 2 * 1024 * 1024) {
      // Stream the tail only — full file is too large to slurp.
      const fd = fs.openSync(transcriptPath, 'r');
      const buf = Buffer.alloc(2 * 1024 * 1024);
      fs.readSync(fd, buf, 0, buf.length, stat.size - buf.length);
      fs.closeSync(fd);
      raw = buf.toString('utf-8');
    } else {
      raw = fs.readFileSync(transcriptPath, 'utf-8');
    }
  } catch {
    return '';
  }
  const lines = raw.split('\n').filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const msg = JSON.parse(lines[i]);
      if (msg?.type === 'assistant' && msg.message?.content) {
        const content = msg.message.content;
        if (typeof content === 'string') return content;
        if (Array.isArray(content)) {
          return content
            .filter((p) => p?.type === 'text' && typeof p.text === 'string')
            .map((p) => p.text)
            .join('\n');
        }
      }
    } catch {
      // Skip unparseable lines — transcript may be in flux.
    }
  }
  return '';
}

function logPostFlight(entry) {
  if (!logger?.log) return;
  try {
    logger.log({ ...entry, source: 'post-flight-hook' });
  } catch {
    // Logging failure must not break the hook.
  }
}

async function main() {
  let raw;
  try {
    raw = await readStdin();
  } catch {
    process.exit(0);
  }

  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    // No stdin or malformed — this hook can also be triggered from a
    // unit test or a manual invocation. Fall through silently.
    process.exit(0);
  }

  const output = lastAssistantMessage(input?.transcript_path);
  if (!output) {
    process.exit(0);
  }

  const config = loadConfig();
  const thresholds = config?.post_flight?.thresholds;
  const contextHint = config?.post_flight?.default_context || 'general';

  const result = postFlight.scanOutput(output, {
    context: contextHint,
    thresholds,
  });

  if (result.verdict === 'PASS') {
    process.exit(0);
  }

  logPostFlight({
    verdict: result.verdict,
    score: result.score,
    signals: result.signals.map((s) => ({ category: s.category, weight: s.weight })),
    session: input?.session_id,
  });

  if (result.verdict === 'WARN') {
    // WARN surfaces a note but doesn't halt. systemMessage is how Stop
    // hooks attach a note that's visible in the Claude Code UI.
    const payload = {
      systemMessage: `[shield post-flight WARN] ${result.reason} (score=${result.score})`,
    };
    process.stdout.write(JSON.stringify(payload));
    process.exit(0);
  }

  // REDACT and BLOCK both halt the Stop hook so the caller can decide
  // what to do next. Claude Code interprets `continue:false` as "do not
  // let the agent finalize this turn"; the reason is surfaced to the
  // operator. We attach the redacted / blocked body so downstream
  // integrations can replace the message entirely.
  const payload = {
    continue: false,
    reason: `[shield post-flight ${result.verdict}] ${result.reason} (score=${result.score})`,
    systemMessage: result.redactedOutput || result.reason,
  };
  process.stdout.write(JSON.stringify(payload));
  process.exit(2);
}

main().catch((err) => {
  process.stderr.write(`shield post-flight: fatal: ${err?.message || err}\n`);
  process.exit(0); // Never let shield crash the agent.
});
