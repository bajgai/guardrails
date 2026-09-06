"""Typed models for policies, findings, and setup plans."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    BLOCKER = "blocker"
    WARNING = "warning"


@dataclass(frozen=True)
class Finding:
    path: str
    category: str
    severity: FindingSeverity = FindingSeverity.BLOCKER
    scanner: str = "publication"


@dataclass(frozen=True)
class ScanResult:
    status: str
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "status": self.status,
            "findings": [asdict(finding) for finding in self.findings],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class SetupPreview:
    version: int
    kind: str
    repo_fingerprint: str
    public_paths: tuple[str, ...]
    install_hooks: bool = True

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "kind": self.kind,
            "repo_fingerprint": self.repo_fingerprint,
            "public_paths": list(self.public_paths),
            "install_hooks": self.install_hooks,
        }


@dataclass
class DoctorReport:
    tool_version: str
    hooks_path: str | None = None
    policy_present: bool = False
    scanners: dict[str, str] = field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "tool_version": self.tool_version,
            "hooks_path": self.hooks_path,
            "policy_present": self.policy_present,
            "scanners": self.scanners,
        }
