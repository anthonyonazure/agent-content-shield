"""
Shared-lexicon drift test (Python side).

Mirror of test/shared-lexicon.test.js — asserts that the Python ports
(core/semantic_detector.py, core/nli_classifier.py) load byte-for-byte
the same data as the shared JSON files, and that nothing has drifted
back into inline copies.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.semantic_detector import INJECTION_SEEDS, THREAT_IDF  # noqa: E402
from core.nli_classifier import NLI_SYSTEM_PROMPT, THREAT_INTENTS  # noqa: E402


def _load(filename: str) -> dict:
    return json.loads((ROOT / "core" / filename).read_text(encoding="utf-8"))


class TestSemanticLexiconDrift(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lex = _load("semantic-lexicon.json")

    def test_seed_count(self) -> None:
        self.assertEqual(
            len(INJECTION_SEEDS),
            len(self.lex["injection_seeds"]),
            "seed array lengths diverge",
        )

    def test_seed_content(self) -> None:
        self.assertEqual(INJECTION_SEEDS, self.lex["injection_seeds"])

    def test_idf_term_count(self) -> None:
        self.assertEqual(len(THREAT_IDF), len(self.lex["threat_idf"]))

    def test_idf_weights(self) -> None:
        self.assertEqual(THREAT_IDF, self.lex["threat_idf"])


class TestNliIntentDrift(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.intents = _load("nli-intents.json")

    def test_intent_count(self) -> None:
        self.assertEqual(len(THREAT_INTENTS), len(self.intents["intents"]))

    def test_intent_ids(self) -> None:
        self.assertEqual(
            sorted(t["id"] for t in THREAT_INTENTS),
            sorted(t["id"] for t in self.intents["intents"]),
        )

    def test_intent_full_content(self) -> None:
        self.assertEqual(THREAT_INTENTS, self.intents["intents"])

    def test_system_prompt(self) -> None:
        self.assertEqual(NLI_SYSTEM_PROMPT, self.intents["system_prompt"])


class TestCrossLanguageParity(unittest.TestCase):
    """Belt-and-suspenders: confirm JS + Python see the SAME JSON files.
    If someone accidentally duplicates a JSON (or points the two
    languages at different files) this catches it."""

    def test_semantic_lexicon_single_source(self) -> None:
        p = ROOT / "core" / "semantic-lexicon.json"
        self.assertTrue(p.exists(), f"shared lexicon missing: {p}")
        self.assertFalse(
            (ROOT / "core" / "semantic_lexicon.json").exists(),
            "accidental underscore-variant JSON exists — both languages "
            "must read from the hyphenated file",
        )

    def test_nli_intents_single_source(self) -> None:
        p = ROOT / "core" / "nli-intents.json"
        self.assertTrue(p.exists(), f"shared intents missing: {p}")
        self.assertFalse((ROOT / "core" / "nli_intents.json").exists())


if __name__ == "__main__":
    unittest.main()
