"""Offline, inert fixtures for developer loader and Git compromise detection."""
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def load(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load("developer_guard")
scanner = load("witchdog")


def create_repo(base: Path, malicious=True):
    root = base / "synthetic-app"
    root.mkdir()
    (root / ".vscode").mkdir()
    (root / "public" / "fonts").mkdir(parents=True)
    (root / ".env").write_text("REAL_SECRET_MUST_NOT_BE_READ_987654\n", encoding="utf-8")
    (root / "package.json").write_text(json.dumps({
        "scripts": {"dev": "node init && vite" if malicious else "vite",
                    "lint": "eslint ."}
    }), encoding="utf-8")
    (root / ".vscode" / "tasks.json").write_text(json.dumps({
        "version": "2.0.0",
        "tasks": [{
            "label": "test fixture",
            "type": "shell",
            "command": "node ./public/fonts/fixture.woff2" if malicious else "echo safe",
            "hide": malicious,
            "presentation": {"reveal": "never" if malicious else "always"},
            "runOptions": {"runOn": "folderOpen" if malicious else "default"}
        }]
    }), encoding="utf-8")
    (root / ".vscode" / "settings.json").write_text(json.dumps({
        "task.allowAutomaticTasks": malicious
    }), encoding="utf-8")
    (root / "public" / "fonts" / "fixture.woff2").write_bytes(
        b"const x = require('fs'); /* inert test string, never run */"
        if malicious else b"wOF2" + b"\x00" * 20
    )
    (root / "eslint.config.js").write_text(
        "const inert = atob(process.env.AUTH_API_KEY); eval(inert);"
        if malicious else "export default [];",
        encoding="utf-8",
    )
    (root / ".gitignore").write_text(
        ".env\n!.env\n" if malicious else ".env\n!.env.example\n",
        encoding="utf-8",
    )
    (root / "package-lock.json").write_text(json.dumps({
        "name": "fixture", "lockfileVersion": 3,
        "packages": {
            "": {"name": "fixture"},
            "node_modules/cdeops": {"version": "13.5.31" if malicious else "13.5.30"},
        }
    }), encoding="utf-8")
    if malicious:
        (root / "init").write_text("const x = require('path');", encoding="utf-8")
        (root / "temp_auto_push.bat").write_text("echo inert fixture only\n", encoding="utf-8")
    return root


class DeveloperGuardTests(unittest.TestCase):
    def test_catalog_exact_versions_and_references(self):
        versions = guard.catalog_versions()
        self.assertEqual(len(versions), 12)
        self.assertIn(("cdeops", "13.5.31"), versions)
        self.assertNotIn(("cdeops", "13.5.30"), versions)

    def test_repository_patterns_detect_but_never_execute(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = create_repo(Path(folder))
            entries = [str(x.relative_to(repo)).replace("\\", "/")
                       for x in repo.rglob("*") if x.is_file()]
            with mock.patch.object(subprocess, "run", side_effect=AssertionError("NO SUBPROCESS")):
                result = guard.scan_repo(repo, entries)
            controls = {x["control"] for x in result["findings"]}
            for expected in ("M01", "M02", "M03", "M04", "M05", "M08", "M09"):
                self.assertIn(expected, controls)
            self.assertEqual(result["status"], "SUSPECTED")
            self.assertEqual(result["network_requests"], 0)
            self.assertFalse(result["target_code_executed"])
            report_text = json.dumps(result)
            self.assertNotIn("REAL_SECRET_MUST_NOT_BE_READ_987654", report_text)
            self.assertNotIn("const x = require", report_text)
            self.assertNotIn("atob(process.env", report_text)

    def test_safe_fixture_does_not_claim_clean_host(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = create_repo(Path(folder), malicious=False)
            entries = [str(x.relative_to(repo)).replace("\\", "/")
                       for x in repo.rglob("*") if x.is_file()]
            result = guard.scan_repo(repo, entries)
            self.assertEqual(result["status"], "NO_INDICATOR_IN_CHECKED_PATHS")
            self.assertEqual(result["findings"], [])
            self.assertTrue(any("Remote Git branches" in x
                                for x in result["coverage_gaps"]))
            self.assertTrue(any("persistence" in x
                                for x in result["coverage_gaps"]))

    def test_home_artifacts_names_only(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            staging = root / ".node_modules"
            staging.mkdir()
            (staging / ".npm-ws-runner.js").write_text(
                "SENSITIVE_POTENTIAL_SOURCE_MUST_NOT_LEAK", encoding="utf-8")
            result = guard.scan_home(root)
            self.assertEqual(result["status"], "SUSPECTED")
            self.assertIn(".npm-ws-runner.js", result["artifact_names"])
            self.assertNotIn("SENSITIVE_POTENTIAL", json.dumps(result))
            (staging / ".npm-ws-runner.js").unlink()
            self.assertEqual(guard.scan_home(root)["status"],
                             "NOT_DETECTED_IN_CHECKED_PATHS")

    def test_untracked_known_artifact_can_be_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = create_repo(Path(folder), malicious=True)
            result = guard.scan_repo(repo, [])
            controls = {x["control"] for x in result["findings"]}
            self.assertIn("M01", controls)
            self.assertIn("M09", controls)
            self.assertNotIn("M08", controls)  # Lockfile not known through index.

    def test_missing_catalog_is_unknown_not_negative(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = create_repo(Path(folder), malicious=False)
            with mock.patch.object(guard, "CATALOG", Path(folder) / "absent.json"):
                result = guard.scan_repo(repo, ["package-lock.json"])
            self.assertTrue(any("M08 UNKNOWN" in x for x in result["coverage_gaps"]))

    @unittest.skipUnless(shutil.which("git"), "Git CLI required")
    def test_default_witchdog_scan_includes_inert_malware_candidates(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            repo = create_repo(root)
            subprocess.run(["git", "init", "-q", str(repo)],
                           check=True, capture_output=True)
            subprocess.run(["git", "-C", str(repo), "add", "-A"],
                           check=True, capture_output=True)
            result = scanner.inspect(repo, root)
            controls = {x["control"] for x in result["findings"]}
            self.assertIn("M02", controls)
            self.assertIn("M04", controls)
            self.assertIn("M08", controls)
            self.assertEqual(result["developer_guard"]["scope"],
                             "LOCAL_WORKTREE_AND_TRACKED_NAMES_ONLY")
            self.assertNotIn("REAL_SECRET_MUST_NOT_BE_READ_987654",
                             json.dumps(result))
            report = scanner.report_md({
                "timestamp_utc": "2026-11-21T10:00:00Z",
                "host": {"system": "Windows", "release": "test",
                         "developer_loader_artifacts": guard.scan_home(root)},
                "repos": [result], "coverage_gaps": []
            })
            self.assertIn("M08", report)
            self.assertIn("NOT INSPECTED", report)


if __name__ == "__main__":
    unittest.main()
