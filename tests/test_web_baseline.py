"""Deterministic safety and evidence tests for Witch Dog WEB-01."""
import importlib.util
import json
import socket
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("web_baseline", ROOT / "tools" / "web_baseline.py")
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)


class TargetScopeTests(unittest.TestCase):
    def test_valid_https_origin_only(self):
        t = web.parse_target("https://example.com/")
        self.assertEqual(t["origin"], "https://example.com")
        self.assertEqual(t["port"], 443)
    def test_block_dangerous_url_forms(self):
        for url in ("ftp://example.com", "https://user:password@example.com",
                    "https://example.com/delete", "https://example.com/?token=secret",
                    "https://example.com/#fragment", "https://example.com\n",
                    "https://exa%mple.com", "example.com"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                web.parse_target(url)
    def test_plain_http_requires_separate_optin(self):
        with self.assertRaises(ValueError):
            web.parse_target("http://example.com")
        self.assertEqual(web.parse_target("http://example.com", allow_http=True)["port"], 80)
    def test_private_dns_is_rejected_by_default(self):
        result = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with mock.patch.object(web.socket, "getaddrinfo", return_value=result):
            t = web.parse_target("https://example.com")
            with self.assertRaises(ValueError):
                web.pinned_addresses(t)
            t["allow_private"] = True
            self.assertEqual(web.pinned_addresses(t), ["127.0.0.1"])
    def test_mixed_global_private_dns_fails_closed(self):
        result = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                  (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with mock.patch.object(web.socket, "getaddrinfo", return_value=result):
            with self.assertRaises(ValueError):
                web.pinned_addresses(web.parse_target("https://example.com"))
    def test_no_authorization_blocks_before_network(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(web, "perform") as perform:
                with self.assertRaises(SystemExit) as exc:
                    web.main(["--target", "https://example.com", "--output", folder])
                self.assertEqual(exc.exception.code, 2)
                perform.assert_not_called()


class EvidenceTests(unittest.TestCase):
    def test_no_cookie_value_in_report(self):
        t = web.parse_target("https://example.com")
        observed = {"status": 200, "tls": {"status": "VERIFIED", "version": "TLSv1.3",
                                           "certificate_not_after": ""},
                    "headers": [("set-cookie", "session=TOP_SECRET_SESSION_VALUE; SameSite=None"),
                                ("x-content-type-options", "nosniff")],
                    "redirects_followed": 0}
        with mock.patch.object(web, "pinned_addresses", return_value=["8.8.8.8"]), \
             mock.patch.object(web, "one_request", return_value=observed):
            report = web.perform(t)
            rendered = json.dumps(report) + web.format_md(report)
            self.assertNotIn("TOP_SECRET_SESSION_VALUE", rendered)
            self.assertNotIn("set-cookie", rendered.lower())
            self.assertEqual(report["request_count"], 1)
            self.assertEqual(report["state"], "OBSERVED")
            self.assertTrue(any(f["control_id"] == "WEB-05.01" and
                                f["verdict"] == "WARN" for f in report["findings"]))
    def test_hsts_and_frame_policy_are_narrowly_verified(self):
        t = web.parse_target("https://example.org")
        obs = {"status": 200, "tls": {"status": "VERIFIED"},
               "headers": [("strict-transport-security", "max-age=31536000; includeSubDomains"),
                           ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
                           ("x-content-type-options", "nosniff"),
                           ("referrer-policy", "strict-origin-when-cross-origin")]}
        findings = {f["control_id"]: f for f in web.check_headers(t, obs)}
        self.assertEqual(findings["WEB-02.03"]["verdict"], "PASS")
        self.assertEqual(findings["WEB-02.06"]["verdict"], "PASS")
        self.assertEqual(findings["WEB-02.07"]["verdict"], "PASS")
    def test_tls_failure_not_bypassed(self):
        t = web.parse_target("https://example.com")
        with mock.patch.object(web, "pinned_addresses", return_value=["8.8.8.8"]), \
             mock.patch.object(web, "one_request", side_effect=ssl.SSLCertVerificationError("bad cert")):
            report = web.perform(t)
        self.assertEqual(report["state"], "BLOCKED")
        self.assertEqual(report["request_count"], 0)
        self.assertEqual(report["findings"][0]["control_id"], "WEB-02.01")
    def test_cross_origin_redirect_never_followed_on_local_lab(self):
        hits = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "https://outside.example/private?secret=x")
                self.send_header("Set-Cookie", "sid=PRIVATE_TOKEN; SameSite=Lax")
                self.end_headers()
            def log_message(self, format, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = web.parse_target(
                "http://127.0.0.1:" + str(server.server_port),
                allow_private=True, allow_http=True,
            )
            with tempfile.TemporaryDirectory() as temp:
                with mock.patch.object(web, "pinned_addresses", return_value=["127.0.0.1"]):
                    report = web.perform(target)
                self.assertEqual(report["request_count"], 1)
                self.assertEqual(report["status_code"], 302)
                self.assertEqual(hits, ["/"])
                self.assertEqual(report["redirects_followed"], 0)
                self.assertNotIn("PRIVATE_TOKEN", json.dumps(report))
                self.assertNotIn("outside.example", json.dumps(report))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)



class SecurityPolicyValueTests(unittest.TestCase):
    """Prevent false PASS for headers with permissive or obsolete values."""

    def evaluate(self, headers, status=200):
        target = web.parse_target("https://example.com")
        observed = {"status": status,
                    "tls": {"status": "VERIFIED", "version": "TLSv1.3"},
                    "headers": headers, "redirects_followed": 0}
        return {row["control_id"]: row for row in web.check_headers(target, observed)}

    def test_csp_present_but_scripts_unrestricted_is_warn(self):
        for policy in ("img-src 'self'; object-src 'none'",
                       "default-src *", "script-src 'unsafe-inline'",
                       "default-src 'self'; script-src https:",
                       "script-src data:"):
            with self.subTest(policy=policy):
                result = self.evaluate([("content-security-policy", policy)])
                self.assertEqual(result["WEB-02.04"]["verdict"], "WARN")
        result = self.evaluate([("content-security-policy-report-only", "script-src 'self'")])
        self.assertEqual(result["WEB-02.04"]["verdict"], "WARN")

    def test_csp_script_restriction_pass_is_narrow(self):
        result = self.evaluate([("content-security-policy",
                                 "default-src 'self'; script-src 'self'; frame-ancestors 'none'")])
        self.assertEqual(result["WEB-02.04"]["verdict"], "PASS")
        self.assertIn("NOT verified", result["WEB-02.04"]["evidence"].lower().replace("not verified", "NOT verified"))
        self.assertEqual(result["WEB-02.06"]["verdict"], "PASS")

    def test_xframe_options_obsolete_not_passed(self):
        bad = self.evaluate([("x-frame-options", "ALLOW-FROM https://example.com")])
        self.assertEqual(bad["WEB-02.06"]["verdict"], "WARN")
        weak = self.evaluate([("content-security-policy",
                                "script-src 'self'; frame-ancestors *")])
        self.assertEqual(weak["WEB-02.06"]["verdict"], "WARN")
        good = self.evaluate([("x-frame-options", "DENY")])
        self.assertEqual(good["WEB-02.06"]["verdict"], "PASS")

    def test_mime_referrer_permissions_must_mean_something(self):
        weak = self.evaluate([
            ("x-content-type-options", "notnosniff"),
            ("referrer-policy", "unsafe-url"),
            ("permissions-policy", "camera=*, microphone=*")])
        for control in ("WEB-02.05", "WEB-02.07", "WEB-02.08"):
            self.assertEqual(weak[control]["verdict"], "WARN")
        strong = self.evaluate([
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("permissions-policy", "camera=(), microphone=()")])
        for control in ("WEB-02.05", "WEB-02.07", "WEB-02.08"):
            self.assertEqual(strong[control]["verdict"], "PASS")

    def test_http_auth_or_challenge_is_not_security_pass(self):
        for status in (401, 403, 429, 503):
            with self.subTest(status=status):
                result = self.evaluate([], status=status)
                self.assertEqual(result["WEB-01.03"]["verdict"], "WARN")

    def test_hsts_zero_is_warn_not_pass(self):
        result = self.evaluate([("strict-transport-security", "max-age=0")])
        self.assertEqual(result["WEB-02.03"]["verdict"], "WARN")


if __name__ == "__main__":
    unittest.main()
