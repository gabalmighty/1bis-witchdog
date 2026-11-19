import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(module):
    spec = importlib.util.spec_from_file_location(module, ROOT / "tools" / (module + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

witchdog = load("witchdog")
intel = load("intel_sync")
validator = load("validate_intel")
RSS = b"""<?xml version="1.0"?><rss><channel><item><title>Vulnerability note</title>
<link>https://radar.cloudflare.com/security/zero-wire/test</link>
<guid>test-one</guid><pubDate>Thu, 19 Nov 2026 00:00:00 GMT</pubDate>
<description>Safe text</description></item></channel></rss>"""
KEV = json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-12345",
 "dateAdded": "2026-11-19", "vulnerabilityName": "Test CVE",
 "shortDescription": "test description"}]}).encode()

class ScannerTests(unittest.TestCase):
    def test_host_disclosure(self):
        h = witchdog.host()
        self.assertIn("system", h)
        self.assertEqual(h["running_services"], "NOT_INSPECTED")
        self.assertNotIn("hostname", h)
    def test_root_and_multi_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            for name in ("one", "two"):
                (root / name / ".git").mkdir(parents=True)
            repos, gaps = witchdog.discover(root)
            self.assertEqual({p.name for p in repos}, {"one", "two"})
            self.assertEqual(gaps, [])
            with self.assertRaises(ValueError):
                witchdog.discover(Path(root.anchor))
    @unittest.skipUnless(shutil.which("git"), "git required")
    def test_findings_do_not_include_secret_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "work"
            repo = root / "app"
            repo.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
            (repo / ".env").write_text("FAKE_TEST_KEY=not-a-real-secret\n")
            (repo / "package.json").write_text(json.dumps({"scripts":{
                "dev":"vite --host 0.0.0.0", "postinstall":"echo safe"}}))
            (repo / "Dockerfile").write_text("FROM nginx:1.27-alpine\n")
            subprocess.run(["git", "-C", str(repo), "add", ".env", "package.json", "Dockerfile"],
                           capture_output=True, check=True)
            r = witchdog.inspect(repo, root)
            statuses = {(x["control"], x["status"]) for x in r["findings"]}
            self.assertIn(("E01", "FAIL"), statuses)
            self.assertIn(("A06", "WARN"), statuses)
            self.assertIn(("F02", "WARN"), statuses)
            self.assertIn(("F06", "WARN"), statuses)
            self.assertIn(("A03", "UNKNOWN"), statuses)
            self.assertNotIn("not-a-real-secret", json.dumps(r))
    def test_feed_parsing(self):
        self.assertEqual(len(intel.parse_zero_wire(RSS)), 1)
        self.assertEqual(intel.parse_kev(KEV)[0]["cve"], "CVE-2026-12345")
        with self.assertRaises(ValueError):
            intel.parse_zero_wire(b"<!DOCTYPE a><rss/>")
    def test_feed_validation(self):
        obj = intel.build(RSS, KEV)
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "data.json"
            f.write_text(json.dumps(obj))
            self.assertEqual(validator.validate(f), 2)
            obj["advisories"][0]["url"] = "http://127.0.0.1/private"
            f.write_text(json.dumps(obj))
            with self.assertRaises(ValueError):
                validator.validate(f)

if __name__ == "__main__":
    unittest.main()
