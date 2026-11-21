"""Regression checks for curated public malware detection references."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "intel" / "campaigns" / "developer-supply-chain-2026.json"
spec = importlib.util.spec_from_file_location(
    "validate_campaign", ROOT / "tools" / "validate_campaign.py"
)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class CampaignReferenceTests(unittest.TestCase):
    def test_public_catalog_schema(self):
        result = validator.validate(CATALOG)
        self.assertEqual(result["source_count"], 2)
        self.assertEqual(result["controls"], 9)
        self.assertEqual(result["releases"], 12)

    def test_bad_source_and_duplicate_release_hold(self):
        original = json.loads(CATALOG.read_text("utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "catalog.json"
            bad = json.loads(json.dumps(original))
            bad["sources"][0]["url"] = "https://evil.example/feed"
            target.write_text(json.dumps(bad))
            with self.assertRaisesRegex(ValueError, "public source"):
                validator.validate(target)
            bad = json.loads(json.dumps(original))
            bad["npm_exact_releases"].append(bad["npm_exact_releases"][0])
            target.write_text(json.dumps(bad))
            with self.assertRaisesRegex(ValueError, "duplicate npm"):
                validator.validate(target)

    def test_untrusted_patterns_cannot_add_tools(self):
        obj = json.loads(CATALOG.read_text("utf-8"))
        self.assertNotIn("commands", obj)
        self.assertNotIn("tools", obj)
        self.assertTrue(all("regex" not in c for c in obj["behavioral_checks"]))


if __name__ == "__main__":
    unittest.main()
