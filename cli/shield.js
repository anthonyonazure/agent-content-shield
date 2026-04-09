#!/usr/bin/env node
/**
 * Agent Content Shield — CLI
 *
 * Usage:
 *   shield scan <file>              Scan a file for threats
 *   shield scan-dir <dir>           Scan all files in a directory
 *   shield validate-url <url>       Check if a URL is safe to fetch
 *   shield audit <db-path>          Show audit summary from integrity DB
 *
 * Options:
 *   --context <type>    web_fetch|pdf_read|email|memory_write|knowledge_doc|general
 *   --json              Output as JSON
 *   --quiet             Exit code only (0=clean, 1=threats, 2=error)
 */

const fs = require('fs');
const path = require('path');
const core = require('../core/detectors');

const args = process.argv.slice(2);
const command = args[0];

function getFlag(name) {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 ? args[idx + 1] : null;
}

const context = getFlag('context') || 'general';
const jsonOutput = args.includes('--json');
const quiet = args.includes('--quiet');

function printResult(filepath, result) {
  if (quiet) return;
  if (jsonOutput) {
    console.log(JSON.stringify({ file: filepath, ...result }));
    return;
  }
  const status = result.clean ? '\x1b[32mCLEAN\x1b[0m' : `\x1b[31mTHREAT (${result.maxSeverity}/10)\x1b[0m`;
  console.log(`  ${status}  ${filepath}`);
  if (!result.clean) {
    for (const f of result.findings) {
      console.log(`    [${f.detector}] sev=${f.severity} count=${f.count} — ${(f.matches || [])[0] || ''}`);
    }
  }
}

switch (command) {
  case 'scan': {
    const file = args[1];
    if (!file) { console.error('Usage: shield scan <file>'); process.exit(2); }
    const text = fs.readFileSync(file, 'utf-8');
    const result = core.scanContent(text, { context });
    printResult(file, result);
    process.exit(result.clean ? 0 : 1);
  }

  case 'scan-dir': {
    const dir = args[1];
    if (!dir) { console.error('Usage: shield scan-dir <dir>'); process.exit(2); }
    let threats = 0;
    let total = 0;
    const walk = (d) => {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, entry.name);
        if (entry.isDirectory()) {
          if (!entry.name.startsWith('.') && entry.name !== 'node_modules') walk(full);
        } else if (entry.name.endsWith('.md') || entry.name.endsWith('.txt') || entry.name.endsWith('.html')) {
          try {
            const text = fs.readFileSync(full, 'utf-8');
            const result = core.scanContent(text, { context: context || 'knowledge_doc' });
            total++;
            if (!result.clean) { threats++; printResult(full, result); }
          } catch {}
        }
      }
    };
    console.log(`Scanning ${dir}...\n`);
    walk(dir);
    console.log(`\n${total} files scanned, ${threats} with threats, ${total - threats} clean`);
    process.exit(threats > 0 ? 1 : 0);
  }

  case 'status': {
    const sigsOk = core.verifySigsIntegrity();
    const logFile = path.join(__dirname, '..', 'logs', 'detections.jsonl');
    let logLines = 0, lastDetection = 'never';
    try {
      const lines = fs.readFileSync(logFile, 'utf-8').trim().split('\n').filter(Boolean);
      logLines = lines.length;
      if (lines.length > 0) lastDetection = JSON.parse(lines[lines.length - 1]).ts;
    } catch {}
    // Check Ollama
    let ollamaStatus = 'unknown';
    try {
      const { execSync } = require('child_process');
      execSync('curl -sf http://localhost:11434/api/tags', { timeout: 3000, stdio: 'pipe' });
      ollamaStatus = 'running';
    } catch { ollamaStatus = 'down'; }

    const status = {
      version: require('../package.json').version,
      signatures_integrity: sigsOk ? 'OK' : 'TAMPERED',
      ollama: ollamaStatus,
      total_detections: logLines,
      last_detection: lastDetection,
      node_version: process.version,
      platform: process.platform,
    };
    if (jsonOutput) {
      console.log(JSON.stringify(status));
    } else {
      console.log(`Agent Content Shield v${status.version}`);
      console.log(`  Signatures:     ${sigsOk ? '\x1b[32mOK\x1b[0m' : '\x1b[31mTAMPERED\x1b[0m'}`);
      console.log(`  Ollama:         ${ollamaStatus === 'running' ? '\x1b[32mrunning\x1b[0m' : '\x1b[33m' + ollamaStatus + '\x1b[0m'}`);
      console.log(`  Detections:     ${logLines} total`);
      console.log(`  Last detection: ${lastDetection}`);
      console.log(`  Node:           ${process.version}`);
      console.log(`  Platform:       ${process.platform}`);
    }
    process.exit(sigsOk ? 0 : 1);
  }

  case 'validate-url': {
    const url = args[1];
    if (!url) { console.error('Usage: shield validate-url <url>'); process.exit(2); }
    const result = core.validateUrl(url, core.SIGS);
    if (jsonOutput) {
      console.log(JSON.stringify(result));
    } else {
      console.log(result.allowed ? `\x1b[32mALLOWED\x1b[0m ${url}` : `\x1b[31mBLOCKED\x1b[0m ${url} — ${result.reason}`);
    }
    process.exit(result.allowed ? 0 : 1);
  }

  default:
    console.log(`
Agent Content Shield — CLI

Usage:
  shield scan <file>              Scan a file for threats
  shield scan-dir <dir>           Scan all files in a directory
  shield validate-url <url>       Check if a URL is safe to fetch
  shield status                   Show shield health and detection stats

Options:
  --context <type>    web_fetch|pdf_read|email|memory_write|knowledge_doc|general
  --json              Output as JSON
  --quiet             Exit code only
`);
    process.exit(0);
}
