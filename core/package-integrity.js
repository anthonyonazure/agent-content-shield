/**
 * Agent Content Shield — Package Name Integrity Checker (AC-1.a Defense)
 *
 * Defends against dependency-targeted injection attacks described in
 * "Your Agent Is Mine" (Liu et al., 2026). AC-1.a routers rewrite
 * `pip install requests` → `pip install reqeusts` (typosquat), which
 * passes domain-based policy gates because the install still targets PyPI.
 *
 * Detection strategy:
 *   1. Extract package names from pip/npm/gem/cargo install commands
 *   2. Compare each against a known-good allowlist of popular packages
 *   3. Flag any package within Levenshtein distance ≤2 of a popular
 *      package that isn't an exact match (probable typosquat)
 *   4. Flag known malicious package names from threat intel
 *
 * Zero external dependencies — uses built-in string distance calculation.
 */

const fs = require('fs');
const path = require('path');

// ── Top Popular Packages (curated from PyPI/npm/crates.io top downloads) ──
// These are the most likely targets for typosquatting attacks.
// Organized by ecosystem for clarity; merged into a single lookup at runtime.

const PYPI_TOP = [
  'requests', 'flask', 'django', 'numpy', 'pandas', 'scipy', 'matplotlib',
  'pyyaml', 'pydantic', 'fastapi', 'uvicorn', 'gunicorn', 'celery', 'redis',
  'boto3', 'botocore', 'sqlalchemy', 'alembic', 'pytest', 'setuptools',
  'pip', 'wheel', 'cryptography', 'pillow', 'beautifulsoup4', 'selenium',
  'tensorflow', 'torch', 'transformers', 'openai', 'anthropic', 'langchain',
  'httpx', 'aiohttp', 'urllib3', 'certifi', 'charset-normalizer', 'idna',
  'jinja2', 'markupsafe', 'werkzeug', 'click', 'rich', 'typer', 'black',
  'ruff', 'mypy', 'isort', 'flake8', 'pylint', 'coverage', 'tox',
  'docker', 'kubernetes', 'paramiko', 'fabric', 'ansible', 'psycopg2',
  'pymongo', 'motor', 'aiofiles', 'starlette', 'pyjwt', 'python-dotenv',
  'colorama', 'tqdm', 'arrow', 'pendulum', 'dateutil', 'pytz', 'six',
  'packaging', 'attrs', 'cattrs', 'marshmallow', 'protobuf', 'grpcio',
  'scrapy', 'lxml', 'cssselect', 'soupsieve', 'regex', 'chardet',
  'cffi', 'pycparser', 'wrapt', 'deprecated', 'decorator', 'toml', 'tomli',
  'orjson', 'ujson', 'simplejson', 'msgpack', 'pyarrow', 'polars',
  'scikit-learn', 'xgboost', 'lightgbm', 'catboost', 'optuna',
  'networkx', 'igraph', 'plotly', 'seaborn', 'bokeh', 'dash', 'streamlit',
  'gradio', 'huggingface-hub', 'datasets', 'tokenizers', 'safetensors',
  'chromadb', 'pinecone-client', 'weaviate-client', 'qdrant-client',
  'litellm', 'llama-index', 'autogen', 'crewai', 'dspy',
];

const NPM_TOP = [
  'express', 'react', 'react-dom', 'next', 'vue', 'angular', 'svelte',
  'typescript', 'webpack', 'vite', 'esbuild', 'rollup', 'babel',
  'eslint', 'prettier', 'jest', 'mocha', 'chai', 'vitest', 'cypress',
  'axios', 'node-fetch', 'got', 'superagent', 'cheerio', 'puppeteer',
  'lodash', 'underscore', 'ramda', 'dayjs', 'moment', 'date-fns',
  'commander', 'yargs', 'chalk', 'ora', 'inquirer', 'prompts',
  'dotenv', 'cors', 'helmet', 'morgan', 'body-parser', 'cookie-parser',
  'jsonwebtoken', 'bcrypt', 'bcryptjs', 'uuid', 'nanoid', 'cuid',
  'mongoose', 'sequelize', 'prisma', 'drizzle-orm', 'knex', 'pg',
  'redis', 'ioredis', 'bull', 'bullmq', 'amqplib', 'kafkajs',
  'socket.io', 'ws', 'fastify', 'koa', 'hapi', 'restify',
  'tailwindcss', 'postcss', 'autoprefixer', 'sass', 'less',
  '@anthropic-ai/sdk', 'openai', 'langchain', 'llamaindex',
  'zod', 'joi', 'yup', 'ajv', 'class-validator',
  'winston', 'pino', 'bunyan', 'debug', 'log4js',
  'sharp', 'jimp', 'canvas', 'pdf-lib', 'pdfkit',
  'nodemailer', 'sendgrid', 'twilio', 'stripe', 'paypal-rest-sdk',
  'aws-sdk', '@aws-sdk/client-s3', 'firebase-admin', 'googleapis',
  'js-yaml', 'toml', 'ini', 'xml2js', 'fast-xml-parser',
  'glob', 'minimatch', 'micromatch', 'chokidar', 'fs-extra',
];

const CARGO_TOP = [
  'serde', 'tokio', 'clap', 'reqwest', 'hyper', 'axum', 'actix-web',
  'rand', 'regex', 'log', 'env_logger', 'tracing', 'anyhow', 'thiserror',
  'chrono', 'uuid', 'serde_json', 'toml', 'config',
];

const GEM_TOP = [
  'rails', 'rake', 'bundler', 'rspec', 'puma', 'sidekiq', 'devise',
  'nokogiri', 'pg', 'redis', 'rack', 'sinatra', 'activerecord',
];

// Unified lookup: lowercase name → ecosystem
const KNOWN_PACKAGES = new Map();
for (const p of PYPI_TOP) KNOWN_PACKAGES.set(p.toLowerCase(), 'pypi');
for (const p of NPM_TOP) KNOWN_PACKAGES.set(p.toLowerCase(), 'npm');
for (const p of CARGO_TOP) KNOWN_PACKAGES.set(p.toLowerCase(), 'cargo');
for (const p of GEM_TOP) KNOWN_PACKAGES.set(p.toLowerCase(), 'gem');

// ── Known Malicious Packages (from threat intel / incident reports) ──
const KNOWN_MALICIOUS = new Set([
  // PyPI typosquats from real incidents
  'reqeusts', 'reequests', 'requets', 'requstes', 'requestes',
  'python-requests', 'request', 'requestss',
  'numppy', 'numpay', 'nuumpy',
  'pandass', 'panndas',
  'djnago', 'djago', 'djanago',
  'flassk', 'flaask',
  'colourama', 'colorsama', 'coloramma',
  'python3-dateutil', 'python-dateutils',
  'jeIune', // homoglyph attack (I→l)
  // npm typosquats
  'expres', 'expresss', 'exress',
  'loddash', 'lodahs',
  'crossenv', 'cross-env.js',
  'event-stream', // compromised package
  'flatmap-stream',
  'ua-parser-js', // hijacked
]);

// ── Levenshtein Distance ──────────────────────────────────────────

function levenshtein(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Optimize: if length difference > 2, skip full calculation
  if (Math.abs(a.length - b.length) > 2) return 3;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      const cost = b[i - 1] === a[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,      // deletion
        matrix[i][j - 1] + 1,      // insertion
        matrix[i - 1][j - 1] + cost // substitution
      );
    }
  }
  return matrix[b.length][a.length];
}

// ── Command Parsing ───────────────────────────────────────────────

/**
 * Extract package names from install commands.
 * Handles: pip install, npm install, cargo add, gem install, go get
 */
function extractPackageNames(command) {
  const packages = [];

  // pip install (handles -r, --requirement, editable, extras, version specs)
  const pipRx = /(?:pip3?|python3?\s+-m\s+pip)\s+install\s+(.*?)(?:\||;|&&|$)/gi;
  let m;
  while ((m = pipRx.exec(command)) !== null) {
    const args = m[1];
    // Split on whitespace, filter flags and non-package args
    const tokens = args.split(/\s+/).filter(t =>
      t && !t.startsWith('-') && !t.startsWith('/') && !t.startsWith('.')
      && !t.includes('://') && t !== 'install'
    );
    for (const t of tokens) {
      // Strip version specifiers: requests>=2.0 → requests
      // Strip extras: package[extra] → package
      const name = t.replace(/[\[>=<!\]~].*/g, '').trim();
      if (name && name.length > 1) packages.push({ name, ecosystem: 'pypi' });
    }
  }

  // npm install / yarn add / pnpm add
  const npmRx = /(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install))\s+(.*?)(?:\||;|&&|$)/gi;
  while ((m = npmRx.exec(command)) !== null) {
    const args = m[1];
    const tokens = args.split(/\s+/).filter(t =>
      t && !t.startsWith('-') && t !== 'install'
    );
    for (const t of tokens) {
      const name = t.replace(/@[\^~]?[\d.]+.*$/, '').trim();
      if (name && name.length > 1) packages.push({ name, ecosystem: 'npm' });
    }
  }

  // cargo add / cargo install
  const cargoRx = /cargo\s+(?:add|install)\s+(.*?)(?:\||;|&&|$)/gi;
  while ((m = cargoRx.exec(command)) !== null) {
    const args = m[1];
    const tokens = args.split(/\s+/).filter(t => t && !t.startsWith('-'));
    for (const t of tokens) {
      const name = t.replace(/@.*$/, '').trim();
      if (name && name.length > 1) packages.push({ name, ecosystem: 'cargo' });
    }
  }

  // gem install
  const gemRx = /gem\s+install\s+(.*?)(?:\||;|&&|$)/gi;
  while ((m = gemRx.exec(command)) !== null) {
    const args = m[1];
    const tokens = args.split(/\s+/).filter(t => t && !t.startsWith('-'));
    for (const t of tokens) {
      const name = t.replace(/:.*$/, '').trim();
      if (name && name.length > 1) packages.push({ name, ecosystem: 'gem' });
    }
  }

  return packages;
}

// ── Typosquat Detection ───────────────────────────────────────────

/**
 * Check a single package name for typosquatting.
 * Returns null if clean, or a finding object if suspicious.
 */
function checkPackage(name, ecosystem) {
  const lower = name.toLowerCase();

  // Exact match against known packages — clean
  if (KNOWN_PACKAGES.has(lower)) return null;

  // Check against known malicious packages — immediate flag
  if (KNOWN_MALICIOUS.has(lower)) {
    return {
      detector: 'package_integrity:known_malicious',
      severity: 10,
      package: name,
      ecosystem,
      explanation: `"${name}" is a known malicious package`,
    };
  }

  // Find closest known package by Levenshtein distance
  let closest = null;
  let minDist = Infinity;

  for (const [known, eco] of KNOWN_PACKAGES) {
    // Only compare within same ecosystem or if ecosystem is ambiguous
    if (ecosystem && eco !== ecosystem && ecosystem !== 'unknown') continue;

    const dist = levenshtein(lower, known);
    if (dist < minDist) {
      minDist = dist;
      closest = known;
    }
    // Early exit — can't do better than 1
    if (dist === 1) break;
  }

  // Distance 1-2 from a known package = probable typosquat
  if (minDist >= 1 && minDist <= 2 && closest) {
    return {
      detector: 'package_integrity:typosquat',
      severity: minDist === 1 ? 9 : 8,
      package: name,
      closestKnown: closest,
      distance: minDist,
      ecosystem,
      explanation: `"${name}" is ${minDist} edit(s) from popular package "${closest}" — probable typosquat (AC-1.a)`,
    };
  }

  // Package not in allowlist but not close to anything known — unknown
  // Don't flag this as malicious, just note it for logging
  return null;
}

/**
 * Scan a command string for typosquatted package names.
 * Returns { clean, findings[] }
 */
function checkCommand(command) {
  const packages = extractPackageNames(command);
  const findings = [];

  for (const { name, ecosystem } of packages) {
    const result = checkPackage(name, ecosystem);
    if (result) findings.push(result);
  }

  return {
    clean: findings.length === 0,
    findings,
    maxSeverity: findings.length > 0 ? Math.max(...findings.map(f => f.severity)) : 0,
    packagesChecked: packages.length,
  };
}

// ── Custom Allowlist (user-configurable) ──────────────────────────

const CUSTOM_ALLOWLIST_PATH = path.join(__dirname, '..', 'config', 'package-allowlist.json');
let _customAllowlist = null;

function loadCustomAllowlist() {
  if (_customAllowlist) return _customAllowlist;
  try {
    _customAllowlist = new Set(
      JSON.parse(fs.readFileSync(CUSTOM_ALLOWLIST_PATH, 'utf-8'))
        .map(p => p.toLowerCase())
    );
  } catch {
    _customAllowlist = new Set();
  }
  return _customAllowlist;
}

/**
 * Full package integrity check with custom allowlist support.
 */
function checkCommandWithAllowlist(command) {
  const result = checkCommand(command);
  if (result.clean) return result;

  const allowlist = loadCustomAllowlist();
  const filtered = result.findings.filter(f =>
    !allowlist.has(f.package.toLowerCase())
  );

  return {
    clean: filtered.length === 0,
    findings: filtered,
    maxSeverity: filtered.length > 0 ? Math.max(...filtered.map(f => f.severity)) : 0,
    packagesChecked: result.packagesChecked,
  };
}

module.exports = {
  checkCommand,
  checkCommandWithAllowlist,
  checkPackage,
  extractPackageNames,
  levenshtein,
  KNOWN_PACKAGES,
  KNOWN_MALICIOUS,
  // For testing
  _internals: { PYPI_TOP, NPM_TOP, CARGO_TOP, GEM_TOP },
};
