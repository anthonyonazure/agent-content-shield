#!/usr/bin/env node
/**
 * Agent Content Shield — stdin/stdout pipe adapter
 *
 * Universal adapter. Pipe any content through it:
 *   echo "some content" | node scan.js --context web_fetch
 *   cat document.md | node scan.js --context knowledge_doc
 *   curl -s https://example.com | node scan.js
 *
 * Output: JSON with scan results
 * Exit code: 0 = clean, 1 = threats detected, 2 = blocked
 */

const fs = require('fs');
const path = require('path');
const core = require('../../core/detectors');

const args = process.argv.slice(2);
const contextIdx = args.indexOf('--context');
const context = contextIdx >= 0 ? args[contextIdx + 1] : 'general';
const quiet = args.includes('--quiet') || args.includes('-q');
const sanitize = args.includes('--sanitize') || args.includes('-s');

let text = '';
try {
  text = fs.readFileSync(0, 'utf-8');
} catch {
  process.stderr.write('Error: No input on stdin\n');
  process.exit(2);
}

const result = core.scanContent(text, { context });

if (quiet) {
  // Just exit code
  process.exit(result.clean ? 0 : 1);
}

if (sanitize && !result.clean) {
  // Output sanitized content
  process.stdout.write(core.sanitizeContent(text));
  process.exit(result.clean ? 0 : 1);
}

// Full report
const report = {
  clean: result.clean,
  maxSeverity: result.maxSeverity,
  totalDetections: result.totalDetections,
  context,
  findings: result.findings.map(f => ({
    detector: f.detector,
    severity: f.severity,
    count: f.count,
    sample: (f.matches || [])[0] || '',
  })),
};

process.stdout.write(JSON.stringify(report, null, 2) + '\n');
process.exit(result.clean ? 0 : 1);
