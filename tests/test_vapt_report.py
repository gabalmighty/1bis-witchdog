"""Evidence assembly tests: no fabricated complete-VAPT claim or raw data release."""
import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

vapt = load("vapt")
reporter = load("vapt_report")

def sample_scope():
    return {
        "schema_version": 1,
        "engagement": {
            "id": "WD-REPORT-01", "approval_ref": "SEC-REPORT-01",
            "owner_contact": "owner@example.invalid", "authorized": True,
            "expires_utc": (dt.datetime.now(dt.timezone.utc) +
                            dt.timedelta(days=1)).isoformat(),
        },
        "target": "https://vapt-staging.example.invalid",
        "environment": "staging", "synthetic_data_only": True,
        "egress_allowlist_enforced": True, "mode": "active",
        "active_testing_approved": True,
        "snapshot_restore_verified": True, "safe_stateful_routes_approved": True,
        "full_origin_scope_approved": False,
        "allowed_prefixes": ["/test/"], "forbidden_prefixes": [],
        "seed_paths": ["/test/health"], "limits": {"max_duration_minutes": 6,
                                                "delay_ms": 1500},
        "role_token_env": {}, "authz_cases": [],
    }

class ReportTests(unittest.TestCase):
    def test_no_tool_run_cannot_claim_vapt_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps(sample_scope()))
            out = Path(tmp) / "output"
            vapt.create_plan(path, out)
            result = reporter.produce(path, out)
            self.assertEqual(result["assurance"], "SCOPED_VAPT_PARTIAL")
            self.assertEqual(result["stages"]["zap"], "NOT_RUN")
            self.assertEqual(result["stages"]["manual_vapt"], "NOT_ATTESTED")
            self.assertGreaterEqual(len(result["untested_high_impact"]), 6)
            self.assertIn("SCOPED_VAPT_PARTIAL", (out / "vapt-assessment.md").read_text())
    def test_sanitized_alerts_and_status_mismatch_are_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.json"
            scope.write_text(json.dumps(sample_scope()))
            out = Path(tmp) / "out"
            manifest = vapt.create_plan(scope, out)
            digest = vapt.load_scope(scope)[2]
            zap = {"source_digest": digest, "alerts": [
                {"plugin_id": "40012", "name": "Potential Cross Site Scripting",
                 "risk": "High", "confidence": "Medium", "instances": [
                     {"evidence": "SECRET_BODY_THAT_MUST_NOT_LEAK"}]}
            ]}
            (out / "zap-sanitized.json").write_text(json.dumps(zap))
            auth = {"source_scope_sha256": digest,
                    "status": "REVIEW", "results": [
                        {"case_id": "synthetic-self", "verdict": "REVIEW_UNEXPECTED_RESPONSE",
                         "raw_cookie": "PRIVATE_SESSION_DO_NOT_LEAK"}]}
            (out / "authz-status-matrix.json").write_text(json.dumps(auth))
            result = reporter.produce(scope, out)
            text = (out / "vapt-assessment.md").read_text()
            self.assertEqual(result["stages"]["zap"], "EXTERNAL_UNVERIFIED")
            self.assertEqual(result["zap_execution_attribution"], "EXTERNAL_UNVERIFIED")
            self.assertEqual(result["dynamic_scanner_candidates"], 1)
            self.assertEqual(result["synthetic_authz_unexpected_statuses"], 1)
            self.assertIn("Potential Cross Site Scripting", text)
            self.assertNotIn("SECRET_BODY_THAT_MUST_NOT_LEAK", text)
            self.assertNotIn("PRIVATE_SESSION_DO_NOT_LEAK", text)
            self.assertEqual(result["findings"][0]["status"],
                             "CANDIDATE_NEEDS_INDEPENDENT_VALIDATION")
    def test_runner_recorded_warning_is_not_a_clean_vapt_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            scope_file = folder / 'scope.json'
            scope_file.write_text(json.dumps(sample_scope()))
            out = folder / 'out'
            manifest = vapt.create_plan(scope_file, out)
            raw = {'site': [{'@name': 'https://vapt-staging.example.invalid',
                             'alerts': []}]}
            report_file = out / 'zap-raw-private.json'
            report_file.write_text(json.dumps(raw), encoding='utf-8')
            manifest['execution_state'] = 'COMPLETE_WITH_WARNINGS'
            manifest['execution_path'] = 'WITCHDOG_RUNNER'
            manifest['exit_code'] = 2
            manifest['precheck_exit_code'] = 0
            vapt.write_private(out, 'manifest.json', json.dumps(manifest) + '\n')
            receipt = {
                'schema_version': 1, 'execution_path': 'WITCHDOG_RUNNER',
                'engagement_id': manifest['engagement_id'],
                'scope_sha256': manifest['scope_sha256'],
                'plan_sha256': manifest['plan_sha256'],
                'report_sha256': vapt.sha256(report_file.read_bytes()),
                'precheck_exit_code': 0, 'autorun_exit_code': 2,
            }
            vapt.write_private(out, 'runner-receipt.json', json.dumps(receipt))
            normalized = vapt.normalize_zap(scope_file, out)
            self.assertEqual(normalized['execution_attribution'], 'RUNNER_RECORDED')
            result = reporter.produce(scope_file, out)
            self.assertEqual(result['stages']['zap'], 'EXECUTED_WITH_WARNINGS')
            self.assertEqual(result['assurance'], 'SCOPED_VAPT_PARTIAL')
    def test_wrong_baseline_origin_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps(sample_scope()))
            out = Path(tmp) / "out"
            vapt.create_plan(path, out)
            (out / "report.json").write_text(json.dumps({
                "origin": "https://different-client.example.invalid",
                "state": "OBSERVED"
            }))
            with self.assertRaises(ValueError):
                reporter.produce(path, out)

    def test_wrong_scope_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps(sample_scope()))
            out = Path(tmp) / "out"
            vapt.create_plan(path, out)
            (out / "zap-sanitized.json").write_text(
                json.dumps({"source_digest": "wrong", "alerts": []}))
            with self.assertRaises(ValueError):
                reporter.produce(path, out)

if __name__ == "__main__":
    unittest.main()
