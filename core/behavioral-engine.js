/**
 * Behavioral Markov Anomaly Engine
 * Models agent behavior as a Markov chain over tool-call sequences.
 * Zero-dependency: sessions stored as JSONL, model as JSON.
 */
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const MODEL_PATH = path.join(DATA_DIR, 'behavioral-model.json');
const SESSIONS_PATH = path.join(DATA_DIR, 'sessions.jsonl');
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

// ── Tool Abstraction ───────────────────────────────────────────────
const TOOL_CATEGORIES = {
  Read: 'READ', Glob: 'READ', Grep: 'READ',
  Write: 'WRITE', Edit: 'WRITE',
  WebFetch: 'FETCH',
  Bash: 'EXEC',
};

function abstractTool(tool) {
  if (!tool) return 'OTHER';
  if (TOOL_CATEGORIES[tool]) return TOOL_CATEGORIES[tool];
  const lower = tool.toLowerCase();
  if (lower.startsWith('mem') || lower.startsWith('knowledge') || lower.includes('memory'))
    return 'MEMORY';
  return 'OTHER';
}

// ── Sensitivity Classification ─────────────────────────────────────
const HIGH_SENSITIVITY = [
  /\.env$/i, /\.ssh[/\\]/i, /credentials/i, /secrets?\b/i,
  /tokens?\.(json|yml|yaml)$/i, /settings\.json$/i,
  /\.gnupg[/\\]/i, /\.aws[/\\]credentials$/i, /\.mcp\.json$/i,
  /\.claude[/\\]settings\.json$/i, /id_rsa/i, /id_ed25519/i,
];

const MEDIUM_SENSITIVITY = [
  /\.bashrc$/i, /\.bash_profile$/i, /\.profile$/i, /\.zshrc$/i,
  /\.gitconfig$/i, /\.npmrc$/i, /config[/\\]/i, /\.yaml$/i,
  /\.yml$/i, /\.toml$/i, /crontab/i,
];

function classifySensitivity(toolInput) {
  const target = toolInput?.file_path || toolInput?.command || toolInput?.url || '';
  const normalized = target.replace(/\\/g, '/');
  if (HIGH_SENSITIVITY.some(rx => rx.test(normalized))) return 'high';
  if (MEDIUM_SENSITIVITY.some(rx => rx.test(normalized))) return 'medium';
  return 'low';
}

// ── State Encoding ─────────────────────────────────────────────────
function encodeState(history, n = 3) {
  if (!history || history.length === 0) return '__START__';
  const recent = history.slice(-n);
  return recent.map(a => `${a.category}:${a.sensitivity}`).join('->');
}

// ── Model (transition probabilities) ───────────────────────────────
let _model = null;

function ensureDataDir() {
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
}

function loadModel() {
  if (_model) return _model;
  try {
    _model = JSON.parse(fs.readFileSync(MODEL_PATH, 'utf-8'));
  } catch {
    _model = { transitions: {}, totalSessions: 0 };
  }
  return _model;
}

function saveModel(model) {
  ensureDataDir();
  fs.writeFileSync(MODEL_PATH, JSON.stringify(model, null, 2));
  _model = model;
}

/** Learn transition probabilities from session objects. */
function learn(sessions) {
  const model = { transitions: {}, totalSessions: sessions.length };

  for (const session of sessions) {
    const actions = session.actions || [];
    for (let i = 0; i < actions.length; i++) {
      // Build state from up to 3 preceding actions
      const history = actions.slice(0, i);
      const state = encodeState(history);
      const next = `${actions[i].category}:${actions[i].sensitivity}`;

      if (!model.transitions[state]) model.transitions[state] = {};
      model.transitions[state][next] = (model.transitions[state][next] || 0) + 1;
    }
  }

  saveModel(model);
  return model;
}

/** Score surprise of next action (0..1). Uses Laplace smoothing. */
function scoreAction(sessionActions, nextTool, nextInput) {
  const model = loadModel();
  const category = abstractTool(nextTool);
  const sensitivity = classifySensitivity(nextInput);
  const state = encodeState(sessionActions);
  const next = `${category}:${sensitivity}`;

  const dist = model.transitions[state];
  if (!dist) {
    // Unknown state — moderate surprise (not max, since novel states happen)
    return 0.6;
  }

  const total = Object.values(dist).reduce((a, b) => a + b, 0);
  const vocabSize = Object.keys(model.transitions).length || 1;
  // Laplace smoothing: (count + 1) / (total + vocabSize)
  const count = dist[next] || 0;
  const probability = (count + 1) / (total + vocabSize);

  // Surprise = -log2(probability), normalized to 0..1
  const surprise = -Math.log2(probability);
  const maxSurprise = Math.log2(total + vocabSize); // when count=0
  return Math.min(surprise / (maxSurprise || 1), 1.0);
}

/** Calibrate threshold from benign data. fpBudget = target FP rate. */
function calibrateThreshold(sessions, fpBudget = 0.001) {
  // First learn from these sessions
  learn(sessions);

  // Collect all surprise scores from benign sessions
  const scores = [];
  for (const session of sessions) {
    const actions = session.actions || [];
    for (let i = 0; i < actions.length; i++) {
      const history = actions.slice(0, i);
      const score = scoreAction(
        history,
        actions[i].tool || actions[i].category,
        actions[i].input || {}
      );
      scores.push(score);
    }
  }

  if (scores.length === 0) return 0.8; // conservative default

  // Set threshold at (1 - fpBudget) percentile
  scores.sort((a, b) => a - b);
  const idx = Math.min(Math.floor(scores.length * (1 - fpBudget)), scores.length - 1);
  const threshold = scores[idx];
  // Save threshold into model
  const model = loadModel();
  model.threshold = Math.max(threshold, 0.5); // floor at 0.5
  saveModel(model);
  return model.threshold;
}

// ── Session Management ─────────────────────────────────────────────
let _currentSession = null;

function getOrCreateSession() {
  const now = Date.now();

  if (_currentSession && (now - _currentSession.lastActivity) < SESSION_TIMEOUT_MS) {
    _currentSession.lastActivity = now;
    return _currentSession;
  }

  _currentSession = {
    id: `ses_${now}_${Math.random().toString(36).slice(2, 8)}`,
    startedAt: now,
    lastActivity: now,
    actions: [],
    cumulativeRisk: 0,
  };
  return _currentSession;
}

function appendAction(sessionId, action) {
  ensureDataDir();
  const session = _currentSession && _currentSession.id === sessionId
    ? _currentSession
    : getOrCreateSession();

  const entry = {
    tool: action.tool,
    category: abstractTool(action.tool),
    sensitivity: classifySensitivity(action.input || {}),
    timestamp: Date.now(),
  };
  session.actions.push(entry);
  session.lastActivity = entry.timestamp;

  // Persist to JSONL
  try {
    fs.appendFileSync(SESSIONS_PATH,
      JSON.stringify({
        sessionId: session.id,
        ...entry,
      }) + '\n'
    );
  } catch (e) {
    process.stderr.write(`shield-behavioral: session log error: ${e.message}\n`);
  }

  return entry;
}

// ── Cumulative Session Risk ────────────────────────────────────────
function computeSessionRisk(session) {
  if (!session || session.actions.length === 0) return 0;

  // Count high-sensitivity actions and risky transitions
  let risk = 0;
  const highCount = session.actions.filter(a => a.sensitivity === 'high').length;
  const fetchThenWrite = session.actions.some((a, i) => {
    if (i === 0) return false;
    return session.actions[i - 1].category === 'FETCH' && a.category === 'WRITE';
  });
  const execThenWrite = session.actions.some((a, i) => {
    if (i === 0) return false;
    return session.actions[i - 1].category === 'EXEC' && a.category === 'WRITE' && a.sensitivity === 'high';
  });

  risk += highCount * 0.15;
  if (fetchThenWrite) risk += 0.3;
  if (execThenWrite) risk += 0.4;

  return Math.min(risk, 1.0);
}

// ── Integration Hook ───────────────────────────────────────────────
function behavioralGuard(toolName, toolInput) {
  const session = getOrCreateSession();
  const model = loadModel();
  const threshold = model.threshold || 0.75;

  const category = abstractTool(toolName);
  const sensitivity = classifySensitivity(toolInput);
  const surprise = scoreAction(session.actions, toolName, toolInput);
  const sessionRisk = computeSessionRisk(session);
  const anomalous = surprise > threshold;

  let explanation = null;
  if (anomalous) {
    const state = encodeState(session.actions);
    explanation = `Unexpected ${category}:${sensitivity} after [${state}] `
      + `(surprise=${surprise.toFixed(3)}, threshold=${threshold.toFixed(3)})`;

    // Amplify if high-sensitivity target
    if (sensitivity === 'high') {
      explanation += ' | HIGH-SENSITIVITY TARGET';
    }
  }

  return { anomalous, surprise, explanation, sessionRisk };
}

// ── Exports ────────────────────────────────────────────────────────
module.exports = {
  // Core engine
  BehavioralEngine: {
    encodeState,
    abstractTool,
    classifySensitivity,
    scoreAction,
    learn,
    calibrateThreshold,
  },

  // Session management
  getOrCreateSession,
  appendAction,

  // Integration
  behavioralGuard,

  // Internals (for testing)
  _internals: {
    loadModel,
    saveModel,
    computeSessionRisk,
    TOOL_CATEGORIES,
    DATA_DIR,
    MODEL_PATH,
    SESSIONS_PATH,
  },
};
