"""Security scanning against isolated Git snapshots."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import tempfile

from guardrails.errors import EXIT_BLOCKED, EXIT_ERROR, EXIT_OK
from guardrails.gitops import git
from guardrails.models import Finding, FindingSeverity
from guardrails.scanners import DEFAULT_ADAPTERS, ScannerAdapter, ScannerOutcome, ScannerStatus


@dataclass(frozen=True)
class SecurityScanRequest:
    repo: Path
    adapters: tuple[ScannerAdapter, ...] = DEFAULT_ADAPTERS


@dataclass(frozen=True)
class SecurityScanResult:
    status: str
    findings: tuple[Finding, ...]
    scanners: tuple[ScannerOutcome, ...]
    warnings: tuple[str, ...]
    exit_code: int = EXIT_OK

    def to_json_dict(self) -> dict[str, object]:
        return {
            "version": 1,
            "status": self.status,
            "findings": [
                {
                    "path": finding.path,
                    "category": finding.category,
                    "severity": finding.severity.value,
                    "scanner": finding.scanner,
                }
                for finding in self.findings
            ],
            "scanners": [outcome.to_json_dict() for outcome in self.scanners],
            "warnings": list(self.warnings),
            "public_rules_only": True,
        }


def create_commit_snapshot(repo: Path) -> Path:
    """Materialize HEAD into a temporary directory without executing project code."""
    temp = Path(tempfile.mkdtemp(prefix="guardrails-snap-"))
    archive = git(repo, "archive", "--format=tar", "HEAD")
    # Use Python tarfile via subprocess tar for deterministic extraction.
    from guardrails.process import run_command

    run_command(["tar", "-xf", "-"], cwd=temp, input_bytes=archive, check=True)
    return temp


def summarize_security(result: SecurityScanResult) -> SecurityScanResult:
    blockers = tuple(
        finding for finding in result.findings if finding.severity == FindingSeverity.BLOCKER
    )
    warnings = list(result.warnings)
    for finding in result.findings:
        if finding.severity == FindingSeverity.WARNING:
            warnings.append(f"{finding.scanner}:{finding.category}")
    incomplete = any(
        outcome.status
        in {ScannerStatus.MISSING, ScannerStatus.ERROR, ScannerStatus.TIMEOUT, ScannerStatus.UNSUPPORTED}
        for outcome in result.scanners
    )
    if blockers:
        status = "blocked"
        code = EXIT_BLOCKED
    elif incomplete:
        status = "incomplete"
        code = EXIT_ERROR
    else:
        status = "ok"
        code = EXIT_OK
    return SecurityScanResult(
        status=status,
        findings=result.findings,
        scanners=result.scanners,
        warnings=tuple(dict.fromkeys(warnings)),
        exit_code=code,
    )


def run_security_scan(request: SecurityScanRequest) -> SecurityScanResult:
    snapshot: Path | None = None
    try:
        snapshot = create_commit_snapshot(request.repo)
        outcomes: list[ScannerOutcome] = []
        findings: list[Finding] = []
        for adapter in request.adapters:
            outcome = adapter.scan(snapshot)
            outcomes.append(outcome)
            findings.extend(outcome.findings)
        result = SecurityScanResult(
            status="ok",
            findings=tuple(findings),
            scanners=tuple(outcomes),
            warnings=(),
        )
        return summarize_security(result)
    finally:
        if snapshot is not None:
            shutil.rmtree(snapshot, ignore_errors=True)


def emit_security_scan(repo: Path, *, output_format: str = "text") -> int:
    result = run_security_scan(SecurityScanRequest(repo=repo))
    if output_format == "json":
        print(json.dumps(result.to_json_dict(), indent=2, sort_keys=True))
    else:
        print(f"Security scan status: {result.status}")
        for outcome in result.scanners:
            print(f"- {outcome.name}: {outcome.status.value}")
            if outcome.message:
                print(f"  {outcome.message}")
        for finding in result.findings:
            print(f"FINDING {finding.scanner} {finding.path}: {finding.category} ({finding.severity.value})")
        for warning in result.warnings:
            print(f"WARNING {warning}")
        if result.status == "incomplete":
            print("Security scan incomplete; unavailable or failed scanners prevent an unqualified pass.")
    return result.exit_code
