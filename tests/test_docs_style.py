"""Test the plain-language policy and Markdown sentence checker."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "docs_style", ROOT / "tools" / "check_docs_style.py"
)
style = importlib.util.module_from_spec(spec)
spec.loader.exec_module(style)

NEW_OR_REVISED = [
    "README.md",
    "CONTRIBUTING.md",
    "AGENTS.md",
    "PROMPT.md",
    "web_prompt.md",
    "review_setup_prompt.md",
    "docs/writing-standard.md",
    "docs/artex-research.md",
    "docs/intelligence-operations.md",
]


class DocsStyleTests(unittest.TestCase):
    def test_public_entry_docs_use_short_sentences(self):
        for name in NEW_OR_REVISED:
            with self.subTest(document=name):
                errors = style.checks(ROOT / name)
                self.assertEqual([], errors[:8],
                                 "Review long sentences in " + name)

    def test_detects_long_prose_but_ignores_fenced_code(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.md"
            long_text = " ".join(["word"] * 30)
            path.write_text(
                "# Test\n\n" + long_text + ".\n\n" +
                chr(96) * 3 + "bash\n" + long_text + "\n" +
                chr(96) * 3 + "\n",
                encoding="utf-8",
            )
            result = style.checks(path)
            self.assertEqual(1, len(result))
            self.assertEqual("LONG_SENTENCE", result[0]["rule"])


if __name__ == "__main__":
    unittest.main()
