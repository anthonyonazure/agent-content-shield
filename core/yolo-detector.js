/**
 * Agent Content Shield — YOLO Mode Detection & Warning
 *
 * Per the "Your Agent Is Mine" paper (Liu et al., 2026), 401 of 440
 * observed agent sessions were running in autonomous "YOLO mode"
 * (auto-approve all tool executions). This makes payload injection
 * trivial — the attacker doesn't need sophisticated evasion when
 * every tool call is auto-approved.
 *
 * This module:
 *   1. Detects if the current session is in YOLO/auto-approve mode
 *   2. Raises the shield's sensitivity floor when YOLO is detected
 *   3. Injects periodic warnings about the elevated risk
 *   4. Tracks YOLO mode statistics for security reporting
 *
 * Detection methods:
 *   - Environment variables (CLAUDE_AUTO_APPROVE, YOLO_MODE, etc.)
 *   - Config file inspection (.claude/settings.json permission mode)
 *   - Behavioral inference (all tool calls approved without delay)
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// ── YOLO Detection ────────────────────────────────────────────────

/**
 * Check environment variables for YOLO/auto-approve indicators.
 */
function checkEnvironment() {
  const indicators = [];

  // Common auto-approve environment variables
  const yoloEnvVars = {
    'CLAUDE_AUTO_APPROVE': 'Claude Code auto-approve mode',
    'DANGEROUSLY_SKIP_PERMISSIONS': 'Skip permissions flag',
    'AUTO_APPROVE': 'Generic auto-approve',
    'YOLO_MODE': 'YOLO mode flag',
    'CODEX_AUTO_APPROVE': 'Codex auto-approve',
    'AGENT_AUTO_EXECUTE': 'Agent auto-execute',
    'SKIP_CONFIRMATION': 'Skip confirmation flag',
  };

  for (const [envVar, desc] of Object.entries(yoloEnvVars)) {
    const val = process.env[envVar];
    if (val && val !== '0' && val.toLowerCase() !== 'false') {
      indicators.push({
        source: 'environment',
        variable: envVar,
        description: desc,
        value: val.slice(0, 20),
      });
    }
  }

  return indicators;
}

/**
 * Check Claude Code settings for permissive permission modes.
 */
function checkSettings() {
  const indicators = [];

  // Check Claude Code settings
  const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
  try {
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));

    // Check permission mode
    if (settings.permissions?.mode === 'auto' || settings.permissions?.mode === 'yolo') {
      indicators.push({
        source: 'settings',
        file: settingsPath,
        description: `Permission mode: ${settings.permissions.mode}`,
        severity: 'high',
      });
    }

    // Check auto-approve patterns
    if (settings.permissions?.autoApprove) {
      const autoApproved = settings.permissions.autoApprove;
      if (Array.isArray(autoApproved)) {
        const dangerousTools = autoApproved.filter(t =>
          /bash|exec|shell|write|edit/i.test(t)
        );
        if (dangerousTools.length > 0) {
          indicators.push({
            source: 'settings',
            file: settingsPath,
            description: `Auto-approved dangerous tools: ${dangerousTools.join(', ')}`,
            severity: 'high',
          });
        }
      }
    }

    // Check if allowedTools is extremely permissive
    if (settings.permissions?.allowedTools?.includes('*')) {
      indicators.push({
        source: 'settings',
        file: settingsPath,
        description: 'Wildcard tool approval (*)',
        severity: 'critical',
      });
    }
  } catch {
    // Settings file doesn't exist or isn't readable — not YOLO
  }

  // Check project-level .claude.json
  const projectSettings = path.join(process.cwd(), '.claude.json');
  try {
    const proj = JSON.parse(fs.readFileSync(projectSettings, 'utf-8'));
    if (proj.permissions?.mode === 'auto' || proj.autoApprove === true) {
      indicators.push({
        source: 'project_settings',
        file: projectSettings,
        description: 'Project-level auto-approve enabled',
        severity: 'high',
      });
    }
  } catch {
    // No project settings
  }

  return indicators;
}

/**
 * Behavioral inference: track approval latency to detect auto-approve.
 * If all recent tool calls were approved in <100ms, likely auto-approved.
 */
let _approvalTimings = [];
const TIMING_WINDOW = 20;

function recordApprovalTiming(latencyMs) {
  _approvalTimings.push(latencyMs);
  if (_approvalTimings.length > TIMING_WINDOW) {
    _approvalTimings = _approvalTimings.slice(-TIMING_WINDOW);
  }
}

function checkBehavioralYolo() {
  if (_approvalTimings.length < 5) return [];

  // If >80% of recent approvals were <100ms, likely auto-approved
  const fastApprovals = _approvalTimings.filter(t => t < 100).length;
  const ratio = fastApprovals / _approvalTimings.length;

  if (ratio > 0.8) {
    return [{
      source: 'behavioral',
      description: `${(ratio * 100).toFixed(0)}% of tool calls approved in <100ms — probable auto-approve`,
      severity: 'medium',
      ratio: ratio.toFixed(2),
    }];
  }
  return [];
}

// ── Main Detection ────────────────────────────────────────────────

/**
 * Full YOLO mode detection. Returns assessment with indicators and recommendations.
 *
 * @returns {{ yoloDetected: boolean, severity: string, indicators: object[], recommendations: string[] }}
 */
function detect() {
  const indicators = [
    ...checkEnvironment(),
    ...checkSettings(),
    ...checkBehavioralYolo(),
  ];

  const yoloDetected = indicators.length > 0;
  const hasCritical = indicators.some(i => i.severity === 'critical');
  const hasHigh = indicators.some(i => i.severity === 'high');

  const severity = hasCritical ? 'critical' : hasHigh ? 'high' : yoloDetected ? 'medium' : 'none';

  const recommendations = [];
  if (yoloDetected) {
    recommendations.push(
      'YOLO/auto-approve mode detected. Per "Your Agent Is Mine" (Liu et al., 2026):',
      '  - 401 of 440 observed autonomous sessions were vulnerable to simple payload injection',
      '  - Malicious routers specifically target YOLO-mode sessions with AC-1.b conditional delivery',
      '  - Consider switching to manual approval for tool calls involving shell execution',
    );

    if (hasCritical || hasHigh) {
      recommendations.push(
        '  - ELEVATED RISK: Shield sensitivity has been automatically raised',
        '  - All shell commands will undergo additional package integrity and response consistency checks',
      );
    }
  }

  return {
    yoloDetected,
    severity,
    indicators,
    recommendations,
  };
}

// ── Sensitivity Modifier ──────────────────────────────────────────

/**
 * Get sensitivity adjustment based on YOLO mode.
 * Returns a multiplier for detection thresholds.
 *
 * In YOLO mode:
 *   - Block threshold lowered (more aggressive blocking)
 *   - Behavioral surprise threshold lowered
 *   - Package integrity checks mandatory
 */
function getSensitivityModifier() {
  const result = detect();

  if (!result.yoloDetected) {
    return {
      active: false,
      blockThresholdModifier: 0,    // No change
      surpriseThresholdModifier: 0,  // No change
      forcePackageCheck: false,
      forceConsistencyCheck: false,
    };
  }

  const isHigh = result.severity === 'critical' || result.severity === 'high';

  return {
    active: true,
    severity: result.severity,
    blockThresholdModifier: isHigh ? -2 : -1,  // Lower block threshold by 1-2 severity levels
    surpriseThresholdModifier: isHigh ? -0.15 : -0.05,  // Lower behavioral surprise threshold
    forcePackageCheck: true,   // Always run package integrity in YOLO mode
    forceConsistencyCheck: true,  // Always run response consistency in YOLO mode
  };
}

/**
 * Generate a warning banner for YOLO mode sessions.
 */
function getWarningBanner() {
  const result = detect();
  if (!result.yoloDetected) return null;

  return [
    '',
    '╔══════════════════════════════════════════════════════════════╗',
    '║  CONTENT SHIELD — Auto-Approve / YOLO Mode Detected        ║',
    '╠══════════════════════════════════════════════════════════════╣',
    `║  Severity: ${result.severity.toUpperCase().padEnd(48)}║`,
    `║  Indicators: ${result.indicators.length.toString().padEnd(46)}║`,
    '║                                                            ║',
    '║  Malicious routers specifically target autonomous sessions. ║',
    '║  Shield sensitivity has been automatically elevated.        ║',
    '╚══════════════════════════════════════════════════════════════╝',
    '',
  ].join('\n');
}

/**
 * Reset (for testing).
 */
function reset() {
  _approvalTimings = [];
}

module.exports = {
  detect,
  getSensitivityModifier,
  getWarningBanner,
  recordApprovalTiming,
  // Individual checks (for testing)
  checkEnvironment,
  checkSettings,
  checkBehavioralYolo,
  reset,
};
