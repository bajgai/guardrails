"""Security scanner adapters fail closed and keep findings sanitized."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
PYTHONPATH = str(PROJECT / "src")
POLICY = ".public-repo-policy.json"


class SecurityScannerTests(unittest.TestCase):
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
        self.write(
            POLICY,
            json.dumps({"version": 1, "public_paths": [POLICY, "README.md"]}) + "\n",
        )
        self.git("add", POLICY, "README.md")
        self.git(
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "Public documentation",
        )

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

    def test_missing_scanner_cannot_unqualified_pass(self) -> None:
        from guardrails.scanners import ScannerStatus
        from guardrails.security import SecurityScanRequest, run_security_scan

        with mock.patch(
            "guardrails.scanners.which",
            return_value=None,
        ):
            result = run_security_scan(SecurityScanRequest(repo=self.root))
        self.assertEqual(result.status, "incomplete")
        self.assertTrue(any(item.status == ScannerStatus.MISSING for item in result.scanners))
        self.assertNotEqual(result.exit_code, 0)

    def test_malformed_scanner_output_fails_closed(self) -> None:
        from guardrails.scanners import GitleaksAdapter, ScannerStatus

        adapter = GitleaksAdapter(executable="/usr/bin/false")
        with mock.patch("guardrails.scanners.run_command") as mocked:
            mocked.return_value = mock.Mock(returncode=0, stdout=b"not-json", stderr=b"")
            outcome = adapter.scan(self.root)
        self.assertEqual(outcome.status, ScannerStatus.ERROR)
        self.assertTrue(outcome.findings or outcome.message)

    def test_high_severity_finding_blocks(self) -> None:
        from guardrails.models import Finding, FindingSeverity
        from guardrails.security import SecurityScanResult, summarize_security

        result = summarize_security(
            SecurityScanResult(
                status="blocked",
                findings=(
                    Finding(
                        path="README.md",
                        category="credential",
                        severity=FindingSeverity.BLOCKER,
                        scanner="gitleaks",
                    ),
                ),
                scanners=(),
                warnings=(),
            )
        )
        self.assertEqual(result.exit_code, 1)

    def test_warning_severity_does_not_block_when_scanners_complete(self) -> None:
        from guardrails.models import Finding, FindingSeverity
        from guardrails.scanners import ScannerOutcome, ScannerStatus
        from guardrails.security import SecurityScanResult, summarize_security

        result = summarize_security(
            SecurityScanResult(
                status="ok",
                findings=(
                    Finding(
                        path="README.md",
                        category="personal-data",
                        severity=FindingSeverity.WARNING,
                        scanner="semgrep",
                    ),
                ),
                scanners=(
                    ScannerOutcome(name="gitleaks", status=ScannerStatus.OK),
                    ScannerOutcome(name="osv-scanner", status=ScannerStatus.OK),
                    ScannerOutcome(name="semgrep", status=ScannerStatus.OK),
                    ScannerOutcome(name="zizmor", status=ScannerStatus.OK),
                ),
                warnings=("personal-data finding reported",),
            )
        )
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.warnings)

    def test_expired_exception_does_not_suppress_finding(self) -> None:
        from datetime import date

        from guardrails.exceptions_policy import ExceptionRecord, is_active_exception
        from guardrails.models import Finding, FindingSeverity

        finding = Finding(
            path="README.md",
            category="credential",
            severity=FindingSeverity.BLOCKER,
            scanner="gitleaks",
        )
        record = ExceptionRecord(
            path="README.md",
            category="credential",
            scanner="gitleaks",
            reason="temporary fixture",
            expires_on=date(2020, 1, 1),
        )
        self.assertFalse(is_active_exception(record, finding, today=date(2026, 9, 6)))

    def test_private_rule_identifiers_are_sanitized(self) -> None:
        from guardrails.private_rules import sanitize_rule_id

        self.assertEqual(
            sanitize_rule_id("/Users/home/secret-rules/acme.yml#rule-9"), "private-rule"
        )
        self.assertNotIn("acme", sanitize_rule_id("/tmp/company-private/rule.yaml"))

    def test_cli_security_reports_incomplete_when_scanners_missing(self) -> None:
        result = self.run_cli("check", "--security", "--format", "json")
        self.assertNotEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["status"], "incomplete")
        self.assertNotIn("unqualified", json.dumps(payload).lower())


if __name__ == "__main__":
    unittest.main()
