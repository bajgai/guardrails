"""Sanitized reporting for publication and security findings."""

from __future__ import annotations

import hashlib
import json
import sys

from guardrails.content import content_categories
from guardrails.errors import EXIT_BLOCKED, EXIT_OK


def report_findings(findings: set[tuple[str, str]]) -> int:
    for path, category in sorted(findings):
        encoded_path = path.encode("utf-8", errors="surrogateescape")
        shown_path = (
            "<redacted-path-" + hashlib.sha256(encoded_path).hexdigest()[:12] + ">"
            if content_categories(encoded_path)
            else path
        )
        print(f"BLOCKED {json.dumps(shown_path, ensure_ascii=True)}: {category}", file=sys.stderr)
    if findings:
        print("Public repository guard failed. No secret values are printed.", file=sys.stderr)
        return EXIT_BLOCKED
    print("Public repository guard passed.")
    return EXIT_OK
