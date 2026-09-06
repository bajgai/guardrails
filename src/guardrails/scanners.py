"""External scanner adapters with sanitized, fail-closed outcomes."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from guardrails.errors import GuardError
from guardrails.models import Finding, FindingSeverity
from guardrails.private_rules import sanitize_rule_id
from guardrails.process import run_command
from guardrails.report import sanitize_path

which = shutil.which


class ScannerStatus(StrEnum):
    OK = "ok"
    MISSING = "missing"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class ScannerOutcome:
    name: str
    status: ScannerStatus
    findings: tuple[Finding, ...] = ()
    message: str = ""

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "findings": [
                {
                    "path": finding.path,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "scanner": finding.scanner,
                }
                for finding in self.findings
            ],
            "message": self.message,
        }


class ScannerAdapter:
    name: str
    executable: str

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or self.executable

    def resolve(self) -> str | None:
        return which(self.executable)

    def scan(self, snapshot: Path) -> ScannerOutcome:
        path = self.resolve()
        if path is None:
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.MISSING,
                message=f"{self.name} is unavailable",
            )
        try:
            return self._scan_with(path, snapshot)
        except GuardError as error:
            status = (
                ScannerStatus.TIMEOUT
                if "timed out" in str(error).casefold()
                else ScannerStatus.ERROR
            )
            return ScannerOutcome(name=self.name, status=status, message=str(error))

    def _scan_with(self, executable: str, snapshot: Path) -> ScannerOutcome:
        raise NotImplementedError


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    executable = "gitleaks"

    def _scan_with(self, executable: str, snapshot: Path) -> ScannerOutcome:
        result = run_command(
            [
                executable,
                "dir",
                str(snapshot),
                "--no-banner",
                "--redact=100",
                "-f",
                "json",
                "-r",
                "/dev/stdout",
            ],
            cwd=snapshot,
            check=False,
            timeout=120,
        )
        # gitleaks exits 1 when leaks are found.
        if result.returncode not in {0, 1}:
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="gitleaks failed",
            )
        raw = result.stdout.strip() or b"[]"
        try:
            payload = json.loads(raw.decode())
        except (UnicodeError, ValueError):
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="gitleaks returned malformed output",
                findings=(),
            )
        if not isinstance(payload, list):
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="gitleaks returned unexpected JSON",
            )
        findings = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            path = sanitize_path(str(item.get("File", "unknown")))
            rule = sanitize_rule_id(str(item.get("RuleID", "credential")))
            findings.append(
                Finding(
                    path=path,
                    category=rule if rule != "private-rule" else "credential",
                    severity=FindingSeverity.BLOCKER,
                    scanner=self.name,
                )
            )
        return ScannerOutcome(
            name=self.name,
            status=ScannerStatus.OK,
            findings=tuple(findings),
        )


class OsvScannerAdapter(ScannerAdapter):
    name = "osv-scanner"
    executable = "osv-scanner"

    def _scan_with(self, executable: str, snapshot: Path) -> ScannerOutcome:
        result = run_command(
            [executable, "--format", "json", str(snapshot)],
            cwd=snapshot,
            check=False,
            timeout=180,
        )
        if result.returncode not in {0, 1}:
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="osv-scanner failed or vulnerability data is incomplete",
            )
        raw = result.stdout.strip() or b"{}"
        try:
            payload = json.loads(raw.decode())
        except (UnicodeError, ValueError):
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="osv-scanner returned malformed output",
            )
        findings: list[Finding] = []
        results = payload.get("results") if isinstance(payload, dict) else None
        if results is None and result.returncode == 0:
            return ScannerOutcome(name=self.name, status=ScannerStatus.OK)
        if not isinstance(results, list):
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="osv-scanner returned unexpected JSON",
            )
        for entry in results:
            if not isinstance(entry, dict):
                continue
            packages = entry.get("packages") or []
            if not isinstance(packages, list):
                continue
            for package in packages:
                vulns = (package or {}).get("vulnerabilities") or []
                for vuln in vulns:
                    severity = FindingSeverity.BLOCKER
                    database_specific = (vuln or {}).get("database_specific") or {}
                    sev = str(database_specific.get("severity", "")).casefold()
                    if sev in {"low", "medium", "moderate"}:
                        severity = FindingSeverity.WARNING
                    findings.append(
                        Finding(
                            path=sanitize_path(str(entry.get("source", {}).get("path", "deps"))),
                            category="vulnerability",
                            severity=severity,
                            scanner=self.name,
                        )
                    )
        return ScannerOutcome(name=self.name, status=ScannerStatus.OK, findings=tuple(findings))


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    executable = "semgrep"

    def _scan_with(self, executable: str, snapshot: Path) -> ScannerOutcome:
        result = run_command(
            [
                executable,
                "scan",
                "--config",
                "p/default",
                "--json",
                "--quiet",
                str(snapshot),
            ],
            cwd=snapshot,
            check=False,
            timeout=300,
        )
        if result.returncode not in {0, 1}:
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="semgrep failed",
            )
        try:
            payload = json.loads(result.stdout.decode() or "{}")
        except (UnicodeError, ValueError):
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="semgrep returned malformed output",
            )
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list):
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="semgrep returned unexpected JSON",
            )
        findings: list[Finding] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            extra = item.get("extra") or {}
            severity_raw = str(extra.get("severity", "ERROR")).casefold()
            severity = (
                FindingSeverity.BLOCKER
                if severity_raw in {"error", "high", "critical"}
                else FindingSeverity.WARNING
            )
            check_id = sanitize_rule_id(str(item.get("check_id", "rule")))
            findings.append(
                Finding(
                    path=sanitize_path(str(item.get("path", "unknown"))),
                    category=check_id if check_id != "private-rule" else "semgrep-finding",
                    severity=severity,
                    scanner=self.name,
                )
            )
        return ScannerOutcome(name=self.name, status=ScannerStatus.OK, findings=tuple(findings))


class ZizmorAdapter(ScannerAdapter):
    name = "zizmor"
    executable = "zizmor"

    def _scan_with(self, executable: str, snapshot: Path) -> ScannerOutcome:
        workflows = snapshot / ".github" / "workflows"
        if not workflows.is_dir():
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.OK,
                message="no GitHub workflows to scan",
            )
        result = run_command(
            [executable, "--format=json", str(snapshot)],
            cwd=snapshot,
            check=False,
            timeout=180,
        )
        if result.returncode not in {0, 1}:
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="zizmor failed",
            )
        raw = result.stdout.strip() or b"[]"
        try:
            payload = json.loads(raw.decode())
        except (UnicodeError, ValueError):
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="zizmor returned malformed output",
            )
        if not isinstance(payload, list):
            return ScannerOutcome(
                name=self.name,
                status=ScannerStatus.ERROR,
                message="zizmor returned unexpected JSON",
            )
        findings: list[Finding] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            severity_raw = str(item.get("determinations", {}).get("severity", "Unknown")).casefold()
            severity = (
                FindingSeverity.BLOCKER
                if severity_raw in {"high", "critical"}
                else FindingSeverity.WARNING
            )
            findings.append(
                Finding(
                    path=sanitize_path(str(item.get("location", {}).get("file", "workflow"))),
                    category="actions-" + sanitize_rule_id(str(item.get("ident", "finding"))),
                    severity=severity,
                    scanner=self.name,
                )
            )
        return ScannerOutcome(name=self.name, status=ScannerStatus.OK, findings=tuple(findings))


DEFAULT_ADAPTERS: tuple[ScannerAdapter, ...] = (
    GitleaksAdapter(),
    OsvScannerAdapter(),
    SemgrepAdapter(),
    ZizmorAdapter(),
)
