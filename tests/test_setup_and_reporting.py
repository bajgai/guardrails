"""Setup preview transactions and sanitized CLI reporting."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
PYTHONPATH = str(PROJECT / "src")
POLICY = ".public-repo-policy.json"


class SetupAndReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = dict(
            os.environ,
            PYTHONPATH=PYTHONPATH,
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
            GIT_AUTHOR_NAME="Guard Test",
            GIT_AUTHOR_EMAIL="test@example.invalid",
            GIT_COMMITTER_NAME="Guard Test",
            GIT_COMMITTER_EMAIL="test@example.invalid",
        )
        self.git("init", "-q", "-b", "main")
        self.write("README.md", "Public documentation.\n")
        self.write("LICENSE", "MIT\n")
        self.git("add", "README.md", "LICENSE")

    def git(self, *args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def write(self, name: str, content: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "guardrails", *args],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
        )

    def test_init_writes_preview_without_installing_hooks(self) -> None:
        result = self.run_cli("init", str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)
        preview = self.root / ".scratch" / "guardrails-setup.json"
        self.assertTrue(preview.is_file())
        payload = json.loads(preview.read_text())
        self.assertEqual(payload["version"], 1)
        self.assertIn(POLICY, payload["public_paths"])
        self.assertIn("README.md", payload["public_paths"])
        self.assertIn("LICENSE", payload["public_paths"])
        self.assertNotIn(".scratch/guardrails-setup.json", payload["public_paths"])
        config = subprocess.run(
            ["git", "config", "--get", "core.hooksPath"],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(config.returncode, 0)

    def test_setup_apply_rejects_missing_preview(self) -> None:
        result = self.run_cli("setup", "apply")
        self.assertEqual(result.returncode, 2)
        self.assertIn("preview", result.stderr.lower())

    def test_setup_apply_rejects_stale_preview(self) -> None:
        self.assertEqual(self.run_cli("init", str(self.root)).returncode, 0)
        self.write("NEW.md", "Added after preview.\n")
        self.git("add", "NEW.md")
        result = self.run_cli("setup", "apply")
        self.assertEqual(result.returncode, 2)
        self.assertIn("stale", result.stderr.lower())

    def test_setup_apply_writes_policy_and_installs_hooks(self) -> None:
        self.assertEqual(self.run_cli("init", str(self.root)).returncode, 0)
        result = self.run_cli("setup", "apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = json.loads((self.root / POLICY).read_text())
        self.assertEqual(policy["version"], 1)
        self.assertEqual(self.git("config", "--local", "core.hooksPath"), ".githooks")
        self.assertTrue((self.root / ".githooks" / "pre-commit").is_file())

    def test_check_json_output_is_versioned_and_redacted(self) -> None:
        self.write(
            POLICY,
            json.dumps({"version": 1, "public_paths": [POLICY, "README.md"]}) + "\n",
        )
        self.git("add", POLICY, "README.md")
        credential = "gh" + "p_" + "A" * 36
        self.write("README.md", credential + "\n")
        self.git("add", "README.md")
        result = self.run_cli("check", "--staged", "--format", "json")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(credential, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["status"], "blocked")
        self.assertTrue(payload["findings"])
        for finding in payload["findings"]:
            self.assertNotIn(credential, json.dumps(finding))

    def test_configuration_failure_uses_exit_code_two(self) -> None:
        result = self.run_cli("check", "--staged")
        self.assertEqual(result.returncode, 2)
        self.assertIn("BLOCKED:", result.stderr)

    def test_doctor_reports_version_and_hooks(self) -> None:
        result = self.run_cli("doctor", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["version"], 1)
        self.assertIn("guardrails", payload["tool_version"])
        self.assertIn("hooks_path", payload)


if __name__ == "__main__":
    unittest.main()
