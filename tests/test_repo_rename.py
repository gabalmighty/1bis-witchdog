"""Check repository rename and intelligence trigger configuration."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OLD_PREFIX = "1" + "bis-"


class RenameAndScheduleTests(unittest.TestCase):
    def test_no_old_repo_prefix_in_tracked_project_files(self):
        skip = {".git", ".witchdog", "__pycache__", ".venv", "node_modules"}
        extensions = {".md", ".py", ".json", ".jsonc", ".yml", ".yaml", ".sh", ".ps1"}
        problems = []
        for item in ROOT.rglob("*"):
            if any(component in skip for component in item.relative_to(ROOT).parts):
                continue
            if item.is_symlink() or not item.is_file() or item.suffix not in extensions:
                continue
            if item.stat().st_size > 300000:
                continue
            if OLD_PREFIX in item.read_text(encoding="utf-8"):
                problems.append(str(item.relative_to(ROOT)))
        self.assertEqual([], problems)

    def test_public_feed_and_action_use_current_repo(self):
        policy = (ROOT / "tools" / "pr_policy.py").read_text(encoding="utf-8")
        self.assertIn("gabalmighty/witchdog", policy)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("## Feed the Witch Dog", readme)
        self.assertIn("CONTRIBUTING.md", readme)
        workflow = (
            ROOT / ".github" / "workflows" / "intelligence.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('cron: "31 0,12 * * *"', workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("push:", workflow)
        self.assertIn("branches: [main]", workflow)


if __name__ == "__main__":
    unittest.main()
