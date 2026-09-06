"""Shared subprocess runner with sanitized failures."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Mapping, Sequence

from guardrails.errors import GuardError

DEFAULT_TIMEOUT_SECONDS = 120
MAX_CAPTURE_BYTES = 1024 * 1024


def run_command(
    args: Sequence[str],
    *,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    input_bytes: bytes | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    """Run a command without a shell, bounding captured output."""
    if not args:
        raise GuardError("Command argument list is empty")
    if any(not isinstance(arg, str) for arg in args):
        raise GuardError("Command arguments must be strings")

    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)

    try:
        result = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd is not None else None,
            env=merged_env,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError as error:
        raise GuardError(f"Required executable is unavailable: {args[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise GuardError(f"Command timed out: {args[0]}") from error
    except OSError as error:
        raise GuardError(f"Unable to execute command: {args[0]}") from error

    if len(result.stdout) > MAX_CAPTURE_BYTES or len(result.stderr) > MAX_CAPTURE_BYTES:
        raise GuardError(f"Command produced oversized output: {args[0]}")
    if check and result.returncode != 0:
        raise GuardError(f"Command failed: {args[0]}")
    return result
