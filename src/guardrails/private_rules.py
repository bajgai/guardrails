"""Private rule path sanitization."""

from __future__ import annotations


def sanitize_rule_id(rule_id: str) -> str:
    """Never emit private filesystem paths or rule pack names."""
    if not rule_id:
        return "private-rule"
    lowered = rule_id.casefold()
    if "private" in lowered or rule_id.startswith(("/", "~", ".")) or "\\" in rule_id:
        return "private-rule"
    if "/" in rule_id or "\\" in rule_id:
        return "private-rule"
    return "rule"
