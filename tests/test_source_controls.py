"""Offline source-scanner tests for Docker digest and secret-coverage semantics."""
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("witchdog", ROOT / "tools" / "witchdog.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(shutil.which("git"), "Git CLI required for source tests")
class SourceControlTests(unittest.TestCase):
    def test_dockerfile_checks_every_from_image_without_running_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            repo = root / "example-app"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
            docker = "\n".join([
                "FROM --platform=$BUILDPLATFORM golang:1.24 AS build",
                "FROM alpine@sha256:" + "a" * 64 + " AS runtime",
                "FROM $BASE_IMAGE AS final",
                "FROM scratch",
                "FROM busybox@sha256:shortvalue",
                "# FROM nginx:latest",
                "",
            ])
            (repo / "Dockerfile").write_text(docker, encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "Dockerfile"],
                           check=True, capture_output=True)
            result = mod.inspect(repo, root)
            f06 = [x for x in result["findings"] if x["control"] == "F06"]
            self.assertEqual([x["status"] for x in f06],
                             ["WARN", "PASS", "UNKNOWN", "N/A", "WARN"])
            self.assertEqual([x["evidence"] for x in f06],
                             ["Dockerfile:" + str(i) for i in (1, 2, 3, 4, 5)])
            self.assertTrue(all(x["evidence_class"] == "SOURCE_DECLARED" for x in f06))
            self.assertTrue(all("running image UNKNOWN" in x["reason"] for x in f06))

    def test_no_sensitive_filenames_is_unknown_not_full_secret_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            repo = root / "clean-app"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
            (repo / "README.md").write_text("# Synthetic clean repo\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "README.md"],
                           check=True, capture_output=True)
            result = mod.inspect(repo, root)
            e01 = [x for x in result["findings"] if x["control"] == "E01"]
            self.assertEqual(len(e01), 1)
            self.assertEqual(e01[0]["status"], "UNKNOWN")
            self.assertIn("history", e01[0]["reason"])
            self.assertNotIn("PASS", [x["status"] for x in e01])

    def test_tracked_sensitive_file_is_flagged_without_reading_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            repo = root / "config-app"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
            (repo / ".env").write_text("NOT_A_SECRET=DO_NOT_STORE_12345\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", ".env"], check=True, capture_output=True)
            result = mod.inspect(repo, root)
            e01 = [x for x in result["findings"] if x["control"] == "E01"]
            self.assertEqual(len(e01), 1)
            self.assertEqual(e01[0]["status"], "FAIL")
            self.assertNotIn("DO_NOT_STORE_12345", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
