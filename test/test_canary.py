"""Canary token system — behavioral test suite."""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class TestCanaryIsolated(unittest.TestCase):
    """Each test runs with a temp canary dir via ``SHIELD_CANARY_DIR``
    so real canaries on the developer's machine are never touched."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SHIELD_CANARY_DIR"] = self.tmp.name
        # Prefer refresh over reimport — reimport across sys.modules is
        # fragile on Windows when the module cache holds references the
        # test can't easily invalidate. _refresh re-reads env and
        # re-persists deterministically.
        import core.canary as canary

        canary._refresh()
        self.canary_mod = canary

    def tearDown(self) -> None:
        os.environ.pop("SHIELD_CANARY_DIR", None)
        self.tmp.cleanup()

    # ── Identity ────────────────────────────────────────────────

    def test_id_is_128_bits_hex(self) -> None:
        cid = self.canary_mod.CANARY_ID
        self.assertEqual(len(cid), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in cid))

    def test_phrase_contains_id(self) -> None:
        self.assertIn(self.canary_mod.CANARY_ID, self.canary_mod.get_canary_phrase())

    def test_canary_file_is_persisted(self) -> None:
        canary_file = Path(self.tmp.name) / "canary.json"
        self.assertTrue(canary_file.exists())
        data = json.loads(canary_file.read_text())
        self.assertEqual(data["id"], self.canary_mod.CANARY_ID)
        self.assertIsNone(data["previousId"])

    # ── Detection ───────────────────────────────────────────────

    def test_check_detects_current_canary(self) -> None:
        phrase = self.canary_mod.get_canary_phrase()
        text = (
            "Some long prose that mentions the tripwire "
            + phrase
            + " embedded in the middle of the document."
        )
        r = self.canary_mod.check_for_canary(text)
        self.assertTrue(r["detected"])
        self.assertEqual(r["canaryId"], "[REDACTED]")
        self.assertEqual(r["severity"], 10)

    def test_check_ignores_short_text(self) -> None:
        r = self.canary_mod.check_for_canary("short")
        self.assertFalse(r["detected"])

    def test_check_ignores_empty_text(self) -> None:
        self.assertFalse(self.canary_mod.check_for_canary("")["detected"])

    def test_check_misses_similar_hex(self) -> None:
        # A bare 32-char hex (commit hash / UUID without dashes) must
        # NOT trigger the canary — only the structured phrase.
        r = self.canary_mod.check_for_canary("sha=" + "a" * 32 + " is a commit.")
        self.assertFalse(r["detected"])

    # ── Rotation ────────────────────────────────────────────────

    def test_rotation_creates_new_id_and_keeps_previous(self) -> None:
        canary_file = Path(self.tmp.name) / "canary.json"
        original_id = self.canary_mod.CANARY_ID

        # Age out the persisted canary
        data = json.loads(canary_file.read_text())
        data["createdAt"] = 0
        canary_file.write_text(json.dumps(data))

        # Trigger a fresh resolve against the aged file
        self.canary_mod._refresh()

        self.assertNotEqual(self.canary_mod.CANARY_ID, original_id)
        persisted = json.loads(canary_file.read_text())
        self.assertEqual(persisted["previousId"], original_id)

    def test_previous_canary_still_matches_during_overlap(self) -> None:
        canary_file = Path(self.tmp.name) / "canary.json"
        original_phrase = self.canary_mod.get_canary_phrase()

        # Force rotation
        data = json.loads(canary_file.read_text())
        data["createdAt"] = 0
        canary_file.write_text(json.dumps(data))
        self.canary_mod._refresh()

        text = (
            "Content carrying the previous canary because the attacker "
            "exfiltrated it before rotation: " + original_phrase
        )
        r = self.canary_mod.check_for_canary(text)
        self.assertTrue(
            r["detected"], "previous canary should still match during overlap"
        )


if __name__ == "__main__":
    unittest.main()
