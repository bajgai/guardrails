"""Environment and protection diagnostics."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
import sys

from guardrails import __version__
from guardrails.errors import EXIT_OK, GuardError
from guardrails.gitops import git
from guardrails.models import DoctorReport
from guardrails.policy import POLICY_PATH


def _hooks_path(repo: Path) -> str | None:
    try:
        return git(repo, "config", "--get", "core.hooksPath").decode().strip()
    except GuardError:
        return None


def collect_doctor(repo: Path | None) -> DoctorReport:
    scanners = {
        name: ("available" if shutil.which(name) else "missing")
        for name in ("gitleaks", "osv-scanner", "semgrep", "zizmor")
    }
    if repo is None:
        return DoctorReport(tool_version=f"guardrails {__version__}", scanners=scanners)
    return DoctorReport(
        tool_version=f"guardrails {__version__}",
        hooks_path=_hooks_path(repo),
        policy_present=(repo / POLICY_PATH).is_file(),
        scanners=scanners,
    )


def emit_doctor(repo: Path | None, *, output_format: str = "text") -> int:
    report = collect_doctor(repo)
    if output_format == "json":
        print(json.dumps(report.to_json_dict(), indent=2, sort_keys=True))
        return EXIT_OK
    print(f"guardrails {report.tool_version}")
    print(f"hooks_path: {report.hooks_path or '(default)'}")
    print(f"policy_present: {report.policy_present}")
    for name, status in sorted(report.scanners.items()):
        print(f"scanner {name}: {status}", file=sys.stderr if status == "missing" else sys.stdout)
    return EXIT_OK
