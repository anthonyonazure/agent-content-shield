/**
 * Shared-lexicon drift test (JS side).
 *
 * v0.4.2 moved the injection seed bank, threat-IDF lexicon, and NLI
 * intent taxonomy out of inline code and into shared JSON files under
 * core/. Both language ports (JS + Python) read from the same files.
 *
 * This test pins the contract so future contributors can't accidentally
 * re-inline the data (or worse: inline a DIFFERENT version). It asserts
 * that the constants the JS modules export are byte-for-byte equal to
 * what the JSON contains.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const semantic = require('../core/semantic-detector');
const nli = require('../core/nli-classifier');

const lexicon = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'core', 'semantic-lexicon.json'), 'utf-8'),
);
const intents = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'core', 'nli-intents.json'), 'utf-8'),
);

function run(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    return true;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.message}`);
    return false;
  }
}

const results = [];

console.log('shared-lexicon: semantic lexicon drift');
results.push(
  run('INJECTION_SEEDS length matches JSON', () => {
    assert.strictEqual(
      semantic.INJECTION_SEEDS.length,
      lexicon.injection_seeds.length,
      'seed array lengths diverge — someone inlined new seeds without updating JSON',
    );
  }),
  run('INJECTION_SEEDS content matches JSON verbatim', () => {
    assert.deepStrictEqual(semantic.INJECTION_SEEDS, lexicon.injection_seeds);
  }),
  run('THREAT_IDF term count matches JSON', () => {
    assert.strictEqual(
      Object.keys(semantic.THREAT_IDF).length,
      Object.keys(lexicon.threat_idf).length,
    );
  }),
  run('THREAT_IDF weights match JSON', () => {
    assert.deepStrictEqual(semantic.THREAT_IDF, lexicon.threat_idf);
  }),
);

console.log('shared-lexicon: NLI intent drift');
results.push(
  run('THREAT_INTENTS length matches JSON', () => {
    assert.strictEqual(nli.THREAT_INTENTS.length, intents.intents.length);
  }),
  run('THREAT_INTENTS ids match JSON', () => {
    assert.deepStrictEqual(
      nli.THREAT_INTENTS.map((t) => t.id).sort(),
      intents.intents.map((t) => t.id).sort(),
    );
  }),
  run('THREAT_INTENTS full content matches JSON', () => {
    assert.deepStrictEqual(nli.THREAT_INTENTS, intents.intents);
  }),
  run('NLI_SYSTEM_PROMPT matches JSON', () => {
    assert.strictEqual(nli.NLI_SYSTEM_PROMPT, intents.system_prompt);
  }),
);

const passed = results.filter(Boolean).length;
const total = results.length;
console.log(`\nshared-lexicon: ${passed}/${total} passed`);
if (passed !== total) process.exit(1);
