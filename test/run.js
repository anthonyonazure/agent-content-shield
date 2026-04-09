#!/usr/bin/env node
/**
 * Agent Content Shield — Test Runner
 * Executes all test suites via node:test
 *
 * Usage:
 *   node test/run.js              # regex tests only (fast, no deps)
 *   node test/run.js --semantic   # include semantic layer tests (needs Ollama)
 *   node test/run.js --all        # all tests including semantic
 *   npm test                      # same as node test/run.js
 *   npm run test:all              # same as --all
 */

const { execSync } = require('child_process');
const path = require('path');

const args = process.argv.slice(2);
const runSemantic = args.includes('--semantic') || args.includes('--all');

const suites = [
  path.join(__dirname, 'detectors.test.js'),
];

if (runSemantic) {
  suites.push(path.join(__dirname, 'semantic.test.js'));
} else {
  console.log('[i] Skipping semantic tests (pass --semantic or --all to include)\n');
}

const cmd = `node --test ${suites.map(s => `"${s}"`).join(' ')}`;

try {
  execSync(cmd, { stdio: 'inherit', cwd: path.join(__dirname, '..') });
} catch (e) {
  process.exit(e.status || 1);
}
