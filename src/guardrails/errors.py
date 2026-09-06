"""Shared error types and exit codes."""

from __future__ import annotations

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2


class GuardError(Exception):
    """Configuration or execution failure that must fail closed."""
