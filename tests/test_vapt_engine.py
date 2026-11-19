"""Witch Dog VAPT engagement, active scan plan, and synthetic auth tests."""
import datetime as dt
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

vapt = load("vapt")
authz = load("vapt_authz")

def scope(mode="passive"):
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)).isoformat()
    return {
        "schema_version": 1,
        "engagement": {
            "id": "WD-TEST-001", "authorized": True,
            "approval_ref": "SEC-TEST-001",
            "owner_contact": "owner@example.invalid", "expires_utc": expires,
        },
        "target": "https://staging.example.invalid",
        "environment": "staging", "synthetic_data_only": True,
        "egress_allowlist_enforced": True,
        "mode": mode, "active_testing_approved": mode == "active",
        "snapshot_restore_verified": mode == "active",
        "safe_stateful_routes_approved": mode == "active",
        "full_origin_scope_approved": False,
        "allowed_prefixes": ["/__witchdog_test__/"],
        "forbidden_prefixes": ["/__witchdog_test__/delete"],
        "seed_paths": ["/__witchdog_test__/health"],
        "limits": {"max_duration_minutes": 6, "delay_ms": 1500},
        "role_token_env": {}, "authz_cases": [],
    }

class ScopeTest(unittest.TestCase):
    def test_passive_plan_has_no_active_payloads(self):
        normalized = vapt.validate_scope(scope())
        plan = vapt.plan_yaml(normalized)
        self.assertIn("type: requestor", plan)
        self.assertIn("type: passiveScan-wait", plan)
        self.assertIn("traditional-json", plan)
        self.assertNotIn("type: activeScan", plan)
        self.assertNotIn("type: spider", plan)
        self.assertIn("delete", plan)  # excluded path retained

    def test_active_is_real_zap_but_low_impact_bounded(self):
        norm = vapt.validate_scope(scope("active"))
        plan = vapt.plan_yaml(norm)
        self.assertIn("type: activeScan", plan)
        self.assertIn("type: spider", plan)
        self.assertIn("maxScanDurationInMins: 6", plan)
        self.assertIn("threadPerHost: 1", plan)
        self.assertIn("delayInMs: 1500", plan)
        self.assertIn("defaultStrength: Low", plan)
        self.assertIn("maxDepth: 2", plan)

    def test_unapproved_active_plan_rejected(self):
        value = scope("active")
        for key in ("active_testing_approved", "snapshot_restore_verified",
                    "safe_stateful_routes_approved", "egress_allowlist_enforced",
                    "synthetic_data_only"):
            altered = dict(value)
            altered[key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                vapt.validate_scope(altered)

    def test_prod_and_unapproved_engagement_rejected(self):
        for key, val in (("environment", "production"),
                         ("target", "http://evil.example.invalid"),
                         ("target", "https://staging.example.invalid/unsafe"),
                         ("target", "https://user:pass@staging.example.invalid"),
                         ("full_origin_scope_approved", False)):
            bad = scope()
            bad[key] = val
            if key == "full_origin_scope_approved":
                bad["allowed_prefixes"] = ["/"]
            with self.subTest(key=key), self.assertRaises(ValueError):
                vapt.validate_scope(bad)
        bad = scope()
        bad["engagement"]["authorized"] = False
        with self.assertRaises(ValueError):
            vapt.validate_scope(bad)

    def test_http_requires_lab_not_just_a_toggle(self):
        value = scope()
        value["target"] = "http://staging.example.invalid"
        value["lab_http"] = True
        with self.assertRaises(ValueError):
            vapt.validate_scope(value)

    def test_path_limits_and_forbidden_seeds(self):
        for path in ("//api/", "/..%2fadmin", "/api/../payroll", "/path?do=delete",
                     "/a\\b", "relative"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                vapt.path_check(path)
        bad = scope()
        bad["seed_paths"] = ["/__witchdog_test__/delete"]
        with self.assertRaises(ValueError):
            vapt.validate_scope(bad)

    def test_token_names_and_fixture_scope(self):
        value = scope()
        value["role_token_env"] = {"employee": "MY_OTHER_TOKEN"}
        with self.assertRaises(ValueError):
            vapt.validate_scope(value)
        value["role_token_env"] = {"employee": "WITCHDOG_EMPLOYEE_TOKEN"}
        value["authz_cases"] = [{
            "id": "employee-own-record", "path": "/admin/payroll",
            "method": "GET", "synthetic_fixture": True,
            "expected": {"employee": [403]},
        }]
        with self.assertRaises(ValueError):
            vapt.validate_scope(value)

    def test_scopes_and_plan_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            config = folder / "scope.json"
            config.write_text(json.dumps(scope()), encoding="utf-8")
            out = folder / "results"
            manifest = vapt.create_plan(config, out)
            self.assertEqual(manifest["execution_state"], "NOT_RUN")
            s, read = vapt.validate_generated(config, out)
            self.assertEqual(s["mode"], "passive")
            with self.assertRaises(ValueError):
                vapt.create_plan(config, out)
            (out / "zap-plan.yaml").write_text("unreviewed change")
            with self.assertRaises(ValueError):
                vapt.validate_generated(config, out)

    def test_expiration_and_approval_are_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            doc = scope()
            doc["engagement"]["expires_utc"] = (
                dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
            path = folder / "expired.json"
            path.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                vapt.load_scope(path, for_execution=True)
            doc["engagement"]["expires_utc"] = (
                dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).isoformat()
            path.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                vapt.load_scope(path, for_execution=True)

    def test_draft_only_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "draft"
            with mock.patch.object(vapt.subprocess, "run") as run:
                draft = vapt.draft_scope("https://staging.example.invalid", out)
                run.assert_not_called()
            self.assertFalse(draft["engagement"]["authorized"])
            self.assertFalse(draft["egress_allowlist_enforced"])
            with self.assertRaises(ValueError):
                vapt.load_scope(out / "engagement.json")
            with self.assertRaises(ValueError):
                vapt.draft_scope("https://staging.example.invalid", out)

    def test_execute_requires_matching_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            path = folder / "config.json"
            path.write_text(json.dumps(scope()))
            out = folder / "run"
            vapt.create_plan(path, out)
            with self.assertRaises(ValueError):
                vapt.execute(path, out, "WRONG-REF", "zap.sh", False)
            with mock.patch.object(vapt.shutil, "which", return_value="/bin/echo"), \
                 mock.patch.object(vapt.subprocess, "run") as proc:
                proc.return_value.returncode = 0
                result = vapt.execute(path, out, "SEC-TEST-001", "zap.sh", False)
            self.assertEqual(result, 0)
            self.assertEqual(proc.call_count, 2)
            autocheck = proc.call_args_list[0].args[0]
            cmd = proc.call_args_list[1].args[0]
            self.assertEqual(autocheck[1:3], ["-cmd", "-autocheck"])
            self.assertEqual(cmd[1:3], ["-cmd", "-autorun"])
            self.assertFalse(proc.call_args.kwargs["shell"])
            with self.assertRaises(ValueError):
                vapt.validate_generated(path, out)

    def test_normalize_zap_excludes_raw_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps(scope()))
            out = Path(tmp) / "run"
            vapt.create_plan(path, out)
            report = {
                "site": [
                    {"@name": "https://staging.example.invalid",
                     "alerts": [
                         {"pluginid": "40012", "alert": "Reflected XSS",
                          "riskdesc": "High", "confidence": "Medium",
                          "cweid": "79",
                          "instances": [{"uri": "https://staging.example.invalid/token=FAKE_SECRET",
                                         "evidence": "FAKE_SECRET",
                                         "attack": "FAKE_SECRET"}]}
                     ]}
                ]
            }
            (out / "zap-raw-private.json").write_text(json.dumps(report))
            normalized = vapt.normalize_zap(path, out)
            output = json.dumps(normalized)
            self.assertIn("Reflected XSS", output)
            self.assertNotIn("FAKE_SECRET", output)
            self.assertEqual(normalized["alerts"][0]["status"],
                             "CANDIDATE_NEEDS_INDEPENDENT_VALIDATION")
            report["site"][0]["@name"] = "https://unowned.example.invalid"
            (out / "zap-raw-private.json").write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                vapt.normalize_zap(path, out)


class AuthzFixtureTest(unittest.TestCase):
    def test_synthetic_role_matrix_status_only(self):
        hits = []
        class App(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                if self.path != "/__witchdog_test__/my-record":
                    self.send_response(404)
                elif self.headers.get("Authorization") == "Bearer SYNTHETIC_TOKEN":
                    self.send_response(200)
                else:
                    self.send_response(403)
                self.end_headers()
                self.wfile.write(b"PRIVATE_SYNTHETIC_FIXTURE_BODY_NOT_FOR_REPORT")
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), App)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            data = scope()
            data.update({"target": f"http://127.0.0.1:{server.server_port}",
                         "environment": "lab", "lab_http": True,
                         "lab_private_network_approved": True,
                         "role_token_env": {"testemployee": "WITCHDOG_TESTEMPLOYEE_TOKEN"},
                         "authz_cases": [
                             {"id": "my-record-access",
                              "path": "/__witchdog_test__/my-record",
                              "method": "GET", "synthetic_fixture": True,
                              "expected": {"anonymous": [403], "testemployee": [200]}}
                         ]})
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "engagement.json"
                path.write_text(json.dumps(data))
                with mock.patch.dict(os.environ, {"WITCHDOG_TESTEMPLOYEE_TOKEN": "SYNTHETIC_TOKEN"}):
                    result = authz.authz_matrix(path, Path(tmp) / "out", "SEC-TEST-001", True)
                raw = json.dumps(result)
                self.assertEqual(result["total_attempted"], 2)
                self.assertEqual(result["status"], "COMPLETED_WITH_EXPECTED_STATUSES")
                self.assertNotIn("SYNTHETIC_TOKEN", raw)
                self.assertNotIn("PRIVATE_SYNTHETIC_FIXTURE_BODY_NOT_FOR_REPORT", raw)
                self.assertEqual(hits, ["/__witchdog_test__/my-record"] * 2)
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
