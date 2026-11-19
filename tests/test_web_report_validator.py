"""Contract tests for the deterministic WEB-01 report validator and manifest."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

web = load("web_baseline")
validator = load("validate_web_report")

class ReportContractTests(unittest.TestCase):
    def sample(self):
        t = web.parse_target("https://staging.example.org")
        headers = {"status": 200,
                   "tls": {"status": "VERIFIED", "version": "TLSv1.3",
                           "certificate_not_after": ""},
                   "headers": [("content-security-policy", "default-src 'self'"),
                               ("x-content-type-options", "nosniff")],
                   "redirects_followed": 0}
        with mock.patch.object(web, "pinned_addresses", return_value=["8.8.8.8"]), \
             mock.patch.object(web, "one_request", return_value=headers):
            return web.perform(t)
    def test_valid_single_request(self):
        obj = self.sample()
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp) / "report.json"
            f.write_text(json.dumps(obj), encoding="utf-8")
            self.assertEqual(validator.validate_report(f)["request_count"], 1)
    def test_refuse_fabricated_verification_or_overbudget(self):
        obj = self.sample()
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp) / "report.json"
            for patch in ({"request_count": 2}, {"redirects_followed": 1},
                          {"evidence_class": "LIVE_VERIFIED"}, {"authorized": False}):
                candidate = dict(obj)
                candidate.update(patch)
                f.write_text(json.dumps(candidate), encoding="utf-8")
                with self.subTest(patch=patch), self.assertRaises(ValueError):
                    validator.validate_report(f)
            obj["findings"][0]["control_id"] = "WEB-04.02"
            f.write_text(json.dumps(obj), encoding="utf-8")
            with self.assertRaises(ValueError):
                validator.validate_report(f)
    def test_unearned_assurance_and_fabricated_coverage_are_rejected(self):
        obj = self.sample()
        self.assertEqual(obj["assurance"], "NOT_A_VAPT")
        self.assertGreaterEqual(len(obj["coverage"]["high_impact_unknown"]), 6)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.json"
            for patch in (
                    {"assurance": "ASVS_L1_PASSED"},
                    {"coverage": {"executed_controls": 999, "high_impact_unknown": []}},
                    {"coverage": {"executed_controls": len(obj["findings"]),
                                  "high_impact_unknown": []}}):
                candidate = dict(obj)
                candidate.update(patch)
                path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.subTest(patch=patch), self.assertRaises(ValueError):
                    validator.validate_report(path)

    def test_report_manifest_hashes_match_file(self):
        report = self.sample()
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "private-out"
            with mock.patch.object(web, "perform", return_value=report):
                code = web.main(["--target", "https://staging.example.org",
                                 "--authorized", "--output", str(out)])
            self.assertEqual(code, 0)
            evidence = (out / "report.json").read_bytes()
            manifest = json.loads((out / "manifest.json").read_text("utf-8"))
            self.assertEqual(manifest["report_sha256"], hashlib.sha256(evidence).hexdigest())
            self.assertIsNotNone(manifest["web_prompt_sha256"])
            self.assertIsNotNone(manifest["checklist_sha256"])
            self.assertEqual(validator.validate_report(out / "report.json")["state"], "OBSERVED")

if __name__ == "__main__":
    unittest.main()
