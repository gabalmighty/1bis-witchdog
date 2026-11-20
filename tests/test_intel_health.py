"""Test the schedule watchdog without network requests."""
import datetime as dt
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "intel_health", ROOT / "tools" / "intel_health.py"
)
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
NOW = dt.datetime(2026, 11, 20, 2, 45, tzinfo=dt.timezone.utc)


def run_item(when, status="completed", result="success", event="schedule"):
    return {
        "name": "Witch Dog public threat intelligence",
        "event": event, "status": status, "conclusion": result,
        "created_at": when, "html_url": "https://github.com/gabalmighty/witchdog/actions/runs/123",
    }


class ScheduleHealthTests(unittest.TestCase):
    def test_no_intelligence_schedule_is_hold(self):
        result = health.audit_runs({"workflow_runs": [
            {"name": "Witch Dog quality", "event": "push"}
        ]}, NOW)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "NO_SCHEDULE_RUNS")

    def test_recent_success(self):
        result = health.audit_runs({
            "workflow_runs": [run_item("2026-11-20T00:23:00Z")]
        }, NOW)
        self.assertEqual(result["status"], "OK")
        self.assertAlmostEqual(result["age_hours"], 2.37, delta=0.03)

    def test_stale_success_is_hold(self):
        result = health.audit_runs({
            "workflow_runs": [run_item("2026-11-19T00:23:00Z")]
        }, NOW)
        self.assertEqual(result["reason"], "SCHEDULE_SUCCESS_STALE")

    def test_latest_failed_run_is_hold_even_if_older_one_passed(self):
        result = health.audit_runs({
            "workflow_runs": [
                run_item("2026-11-20T00:23:00Z", result="failure"),
                run_item("2026-11-19T12:23:00Z"),
            ]
        }, NOW)
        self.assertEqual(result["reason"], "LATEST_SCHEDULE_RUN_FAILED")

    def test_only_manual_success_is_not_schedule_success(self):
        result = health.audit_runs({
            "workflow_runs": [
                run_item("2026-11-20T00:23:00Z", event="workflow_dispatch")
            ]
        }, NOW)
        self.assertEqual(result["reason"], "NO_SCHEDULE_RUNS")


if __name__ == "__main__":
    unittest.main()
