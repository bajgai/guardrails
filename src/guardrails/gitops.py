"""Git object helpers that never execute repository-supplied commands."""

from __future__ import annotations

import os
from pathlib import Path

from guardrails.errors import GuardError
from guardrails.process import run_command

GIT_SAFE_ENV = {
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
}


def git(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    """Run git in ``repo`` with argument arrays and sanitized failures."""
    env = dict(os.environ)
    env.update(GIT_SAFE_ENV)
    result = run_command(
        ["git", "-C", str(repo), *args],
        cwd=repo,
        env=env,
        input_bytes=input_bytes,
        check=False,
    )
    if result.returncode:
        # Git errors can contain a secret supplied as a ref or filename.
        raise GuardError("Git operation failed; inspect repository state locally")
    return result.stdout


def repository_root(start: Path | None = None) -> Path:
    path = start or Path.cwd()
    raw = git(path if path.is_dir() else path.parent, "rev-parse", "--show-toplevel")
    return Path(raw.decode().strip())
