"""Offline tests for the plan and coverage ledger."""
import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("agent_plan", TOOLS / "agent_plan.py")
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


def scope(mode="passive"):
    return {
        "schema_version": 1,
        "engagement": {
            "id": "WD-TEST-001", "authorized": True,
            "approval_ref": "SEC-TEST-001", "owner_contact": "a@example.invalid",
            "expires_utc": (
                dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
            ).isoformat(),
        },
        "target": "https://test.example.invalid",
        "environment": "lab",
        "synthetic_data_only": True,
        "egress_allowlist_enforced": True,
        "mode": mode,
        "active_testing_approved": mode == "active",
        "snapshot_restore_verified": mode == "active",
        "safe_stateful_routes_approved": mode == "active",
        "full_origin_scope_approved": False,
        "allowed_prefixes": ["/wd-test/"],
        "forbidden_prefixes": ["/wd-test/delete"],
        "seed_paths": ["/wd-test/health"],
        "limits": {"max_duration_minutes": 6, "delay_ms": 1500},
        "role_token_env": {}, "authz_cases": [],
    }


class PlanTests(unittest.TestCase):
    def test_plan_is_not_a_scan_and_has_held_stages(self):
        with tempfile.TemporaryDirectory() as folder:
            conf = Path(folder) / "scope.json"
            conf.write_text(json.dumps(scope()), encoding="utf-8")
            out = Path(folder) / "out"
            plan = planner.init(conf, out)
            self.assertEqual(plan["assurance"], "PLAN_NOT_EXECUTION")
            self.assertEqual(plan["budgets"]["requests_executed"], 0)
            self.assertEqual(
                {task["id"]: task["status"] for task in plan["intents"]}["test-authz"],
                "HOLD",
            )
            self.assertEqual(
                {task["id"]: task["status"] for task in plan["intents"]}["check-injection"],
                "HOLD",
            )
            self.assertEqual(len(json.loads((out / "coverage.json").read_text())[
                "untested_areas"]), 7)
            with self.assertRaises(ValueError):
                planner.init(conf, out)

    def test_active_scope_only_makes_plan_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            conf = Path(folder) / "scope.json"
            conf.write_text(json.dumps(scope("active")), encoding="utf-8")
            out = Path(folder) / "out"
            plan = planner.init(conf, out)
            task = next(t for t in plan["intents"] if t["id"] == "check-injection")
            self.assertEqual(task["status"], "READY")
            self.assertEqual(plan["budgets"]["requests_executed"], 0)

    def test_finding_and_negative_result_require_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            conf = Path(folder) / "scope.json"
            conf.write_text(json.dumps(scope()), encoding="utf-8")
            out = Path(folder) / "out"
            planner.init(conf, out)
            with self.assertRaises(ValueError):
                planner.record(out, "/wd-test/health", "injection",
                               "NO_ISSUE_FOUND", evidence_path=None)
            with self.assertRaises(ValueError):
                planner.record(out, "/wd-test/delete", "injection",
                               "NEEDS_FOLLOWUP", evidence_path=None)
            proof = Path(folder) / "synthetic.txt"
            proof.write_text("approved synthetic case", encoding="utf-8")
            result = planner.record(
                out, "/wd-test/health", "injection", "NO_ISSUE_FOUND",
                evidence_path=proof,
            )
            self.assertEqual(result["outcome"], "NO_ISSUE_FOUND")
            data = json.loads((out / "coverage.json").read_text("utf-8"))
            self.assertNotIn("injection", data["untested_areas"])
            self.assertIn("authorization", data["untested_areas"])
            self.assertEqual(result["verification"],
                             "EVIDENCE_RECORDED_NOT_INDEPENDENTLY_VERIFIED")

    def test_outcome_without_reason_is_not_allowed(self):
        with tempfile.TemporaryDirectory() as folder:
            conf = Path(folder) / "scope.json"
            conf.write_text(json.dumps(scope()), encoding="utf-8")
            out = Path(folder) / "out"
            planner.init(conf, out)
            with self.assertRaises(ValueError):
                planner.record(out, "/wd-test/health", "transport",
                               "RULED_OUT", evidence_path=None)


if __name__ == "__main__":
    unittest.main()
