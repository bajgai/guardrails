"""Sanitized reporting for publication and security findings."""

from __future__ import annotations

import hashlib
import json
import sys

from guardrails.content import content_categories
from guardrails.errors import EXIT_BLOCKED, EXIT_OK
from guardrails.models import Finding, FindingSeverity, ScanResult


def sanitize_path(path: str) -> str:
    encoded_path = path.encode("utf-8", errors="surrogateescape")
    if content_categories(encoded_path):
        return "<redacted-path-" + hashlib.sha256(encoded_path).hexdigest()[:12] + ">"
    return path


def findings_from_pairs(pairs: set[tuple[str, str]]) -> tuple[Finding, ...]:
    return tuple(
        Finding(
            path=sanitize_path(path),
            category=category,
            severity=FindingSeverity.BLOCKER,
            scanner="publication",
        )
        for path, category in sorted(pairs)
    )


def report_findings(
    findings: set[tuple[str, str]],
    *,
    output_format: str = "text",
) -> int:
    models = findings_from_pairs(findings)
    result = ScanResult(
        status="blocked" if models else "ok",
        findings=models,
    )
    if output_format == "json":
        print(json.dumps(result.to_json_dict(), ensure_ascii=True, indent=2, sort_keys=True))
        return EXIT_BLOCKED if models else EXIT_OK
    for finding in models:
        print(
            f"BLOCKED {json.dumps(finding.path, ensure_ascii=True)}: {finding.category}",
            file=sys.stderr,
        )
    if models:
        print("Public repository guard failed. No secret values are printed.", file=sys.stderr)
        return EXIT_BLOCKED
    print("Public repository guard passed.")
    return EXIT_OK
