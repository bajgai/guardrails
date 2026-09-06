"""Time-bounded finding exceptions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from guardrails.models import Finding


@dataclass(frozen=True)
class ExceptionRecord:
    path: str
    category: str
    scanner: str
    reason: str
    expires_on: date


def is_active_exception(
    record: ExceptionRecord,
    finding: Finding,
    *,
    today: date | None = None,
) -> bool:
    if not record.reason.strip():
        return False
    current = today or date.today()
    if record.expires_on < current:
        return False
    return (
        record.path == finding.path
        and record.category == finding.category
        and record.scanner == finding.scanner
    )
