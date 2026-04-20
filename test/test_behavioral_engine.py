"""Behavioral Markov engine — Python test suite."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class TestBehavioralEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SHIELD_DATA_DIR"] = self.tmp.name
        import core.behavioral_engine as be

        be._reset_model_cache()
        be._reset_current_session()
        self.be = be

    def tearDown(self) -> None:
        os.environ.pop("SHIELD_DATA_DIR", None)
        self.tmp.cleanup()

    # ── Tool abstraction ────────────────────────────────────────

    def test_abstract_tool_known(self) -> None:
        self.assertEqual(self.be.abstract_tool("Read"), "READ")
        self.assertEqual(self.be.abstract_tool("Bash"), "EXEC")
        self.assertEqual(self.be.abstract_tool("WebFetch"), "FETCH")

    def test_abstract_tool_memory_heuristic(self) -> None:
        self.assertEqual(self.be.abstract_tool("mempalace_save"), "MEMORY")
        self.assertEqual(self.be.abstract_tool("knowledge_add"), "MEMORY")

    def test_abstract_tool_unknown_falls_to_other(self) -> None:
        self.assertEqual(self.be.abstract_tool("ZzzTool"), "OTHER")
        self.assertEqual(self.be.abstract_tool(None), "OTHER")

    # ── Sensitivity classification ──────────────────────────────

    def test_classify_high_sensitivity_paths(self) -> None:
        self.assertEqual(
            self.be.classify_sensitivity({"file_path": ".env"}), "high"
        )
        self.assertEqual(
            self.be.classify_sensitivity({"file_path": "/home/x/.ssh/id_rsa"}),
            "high",
        )
        self.assertEqual(
            self.be.classify_sensitivity({"command": "cat /etc/secrets"}),
            "high",
        )

    def test_classify_medium_sensitivity_paths(self) -> None:
        self.assertEqual(
            self.be.classify_sensitivity({"file_path": "settings/foo.yaml"}),
            "medium",
        )

    def test_classify_low_sensitivity_default(self) -> None:
        self.assertEqual(
            self.be.classify_sensitivity({"file_path": "src/index.ts"}),
            "low",
        )
        self.assertEqual(self.be.classify_sensitivity({}), "low")
        self.assertEqual(self.be.classify_sensitivity(None), "low")

    # ── State encoding ──────────────────────────────────────────

    def test_encode_state_empty(self) -> None:
        self.assertEqual(self.be.encode_state(None), "__START__")
        self.assertEqual(self.be.encode_state([]), "__START__")

    def test_encode_state_windowed(self) -> None:
        history = [
            {"category": "READ", "sensitivity": "low"},
            {"category": "FETCH", "sensitivity": "low"},
            {"category": "WRITE", "sensitivity": "high"},
        ]
        self.assertEqual(
            self.be.encode_state(history), "READ:low->FETCH:low->WRITE:high"
        )

    # ── Learning + scoring ──────────────────────────────────────

    def test_learn_builds_transitions(self) -> None:
        sessions = [
            {
                "actions": [
                    {"category": "READ", "sensitivity": "low"},
                    {"category": "FETCH", "sensitivity": "low"},
                ]
            }
        ]
        model = self.be.learn(sessions)
        self.assertIn("__START__", model["transitions"])
        self.assertEqual(model["totalSessions"], 1)

    def test_score_action_novel_state_is_moderate(self) -> None:
        s = self.be.score_action([], "SomeUnknownTool", {})
        self.assertEqual(s, 0.6)

    def test_score_action_known_transition_low_surprise(self) -> None:
        # Train with READ -> FETCH 100 times
        sessions = [
            {
                "actions": [
                    {"category": "READ", "sensitivity": "low"},
                    {"category": "FETCH", "sensitivity": "low"},
                ]
            }
            for _ in range(100)
        ]
        self.be.learn(sessions)
        self.be._reset_model_cache()
        history = [{"category": "READ", "sensitivity": "low"}]
        # FETCH after READ is the dominant transition → low surprise
        s = self.be.score_action(history, "WebFetch", {})
        self.assertLess(s, 0.8)

    def test_calibrate_threshold_floor(self) -> None:
        sessions = [
            {
                "actions": [
                    {"category": "READ", "sensitivity": "low", "tool": "Read"}
                    for _ in range(10)
                ]
            }
        ]
        t = self.be.calibrate_threshold(sessions)
        self.assertGreaterEqual(t, 0.5)

    # ── Session management ─────────────────────────────────────

    def test_get_or_create_session_reuses_within_window(self) -> None:
        s1 = self.be.get_or_create_session()
        s2 = self.be.get_or_create_session()
        self.assertEqual(s1["id"], s2["id"])

    def test_append_action_persists(self) -> None:
        s = self.be.get_or_create_session()
        self.be.append_action(s["id"], {"tool": "Read", "input": {"file_path": "a.txt"}})
        log = Path(self.tmp.name) / "sessions.jsonl"
        self.assertTrue(log.exists())
        line = log.read_text().strip().split("\n")[-1]
        obj = json.loads(line)
        self.assertEqual(obj["tool"], "Read")
        self.assertEqual(obj["category"], "READ")
        self.assertEqual(obj["sensitivity"], "low")

    # ── Session risk ───────────────────────────────────────────

    def test_session_risk_empty_is_zero(self) -> None:
        self.assertEqual(self.be.compute_session_risk({"actions": []}), 0.0)

    def test_session_risk_fetch_then_write_raises(self) -> None:
        session = {
            "actions": [
                {"category": "FETCH", "sensitivity": "low"},
                {"category": "WRITE", "sensitivity": "low"},
            ]
        }
        r = self.be.compute_session_risk(session)
        self.assertGreaterEqual(r, 0.3)

    def test_session_risk_exec_then_high_write_raises(self) -> None:
        session = {
            "actions": [
                {"category": "EXEC", "sensitivity": "low"},
                {"category": "WRITE", "sensitivity": "high"},
            ]
        }
        r = self.be.compute_session_risk(session)
        # Expect EXEC->WRITE(high) path bonus (0.4) + 1 high sensitivity (0.15)
        self.assertGreaterEqual(r, 0.4)

    # ── Integration ────────────────────────────────────────────

    def test_behavioral_guard_returns_all_keys(self) -> None:
        r = self.be.behavioral_guard("Read", {"file_path": "a.txt"})
        self.assertIn("anomalous", r)
        self.assertIn("surprise", r)
        self.assertIn("explanation", r)
        self.assertIn("sessionRisk", r)


if __name__ == "__main__":
    unittest.main()
