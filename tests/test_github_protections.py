"""GitHub protection planning with a mockable API boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
PYTHONPATH = str(PROJECT / "src")


class GitHubProtectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = dict(os.environ, PYTHONPATH=PYTHONPATH)

    def run_cli(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [os.environ.get("PYTHON", "python3"), "-m", "guardrails", *args],
            cwd=PROJECT,
            env=env or self.env,
            text=True,
            capture_output=True,
        )

    def test_plan_reports_required_protections(self) -> None:
        from guardrails.github_protect import ProtectionState, plan_protections

        current = ProtectionState(
            secret_scanning=False,
            push_protection=False,
            requires_pr=False,
            requires_passing_checks=False,
            includes_admins=False,
            allows_force_pushes=True,
            allows_deletions=True,
            required_checks=(),
        )
        plan = plan_protections(current, required_checks=("Public repository guard",))
        self.assertTrue(plan.changes)
        serialized = json.dumps(plan.to_json_dict())
        self.assertIn("secret_scanning", serialized)
        self.assertIn("push_protection", serialized)
        self.assertIn("requires_pr", serialized)

    def test_apply_preserves_stronger_existing_protections(self) -> None:
        from guardrails.github_protect import ProtectionState, plan_protections

        current = ProtectionState(
            secret_scanning=True,
            push_protection=True,
            requires_pr=True,
            requires_passing_checks=True,
            includes_admins=True,
            allows_force_pushes=False,
            allows_deletions=False,
            required_checks=("Public repository guard", "Secret scan", "Extra stronger check"),
        )
        plan = plan_protections(current, required_checks=("Public repository guard", "Secret scan"))
        self.assertEqual(plan.changes, ())
        self.assertIn("Extra stronger check", plan.resulting.required_checks)

    def test_verify_detects_readback_mismatch(self) -> None:
        from guardrails.github_protect import ProtectionState, verify_protections

        desired = ProtectionState(
            secret_scanning=True,
            push_protection=True,
            requires_pr=True,
            requires_passing_checks=True,
            includes_admins=True,
            allows_force_pushes=False,
            allows_deletions=False,
            required_checks=("Public repository guard",),
        )
        actual = desired
        self.assertTrue(verify_protections(desired, actual))
        mismatched = ProtectionState(
            secret_scanning=True,
            push_protection=False,
            requires_pr=True,
            requires_passing_checks=True,
            includes_admins=True,
            allows_force_pushes=False,
            allows_deletions=False,
            required_checks=("Public repository guard",),
        )
        self.assertFalse(verify_protections(desired, mismatched))

    def test_cli_plan_uses_injected_reader(self) -> None:
        from guardrails import github_protect

        fake = github_protect.ProtectionState(
            secret_scanning=False,
            push_protection=False,
            requires_pr=False,
            requires_passing_checks=False,
            includes_admins=False,
            allows_force_pushes=True,
            allows_deletions=True,
            required_checks=(),
        )
        with mock.patch.object(github_protect, "read_protection_state", return_value=fake):
            code = github_protect.emit_plan(
                Path(PROJECT),
                required_checks=("Public repository guard",),
                output_format="json",
            )
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
