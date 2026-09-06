"""Local Git hook installation that preserves custom hook configuration."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from guardrails.errors import EXIT_ERROR, EXIT_OK, GuardError
from guardrails.gitops import git

PRE_COMMIT = """#!/bin/sh
set -eu
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
exec {python} -m guardrails check --staged
"""

PRE_PUSH = """#!/bin/sh
set -eu
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"
exec {python} -m guardrails hook pre-push
"""


def _existing_hooks_path(repo: Path) -> str:
    try:
        return git(repo, "config", "--get", "core.hooksPath").decode().strip()
    except GuardError:
        return ""


def install_hooks(repo: Path, *, python_executable: str | None = None) -> int:
    """Install repository-local hooks without replacing custom hook paths."""
    python = python_executable or "python3"
    existing = _existing_hooks_path(repo)
    hooks_dir = repo / ".githooks"
    allowed = {"", ".githooks", str(hooks_dir)}
    if existing not in allowed:
        print("Refusing to replace an existing custom core.hooksPath.", file=sys.stderr)
        return EXIT_ERROR
    if existing == "":
        default_hooks = Path(git(repo, "rev-parse", "--git-path", "hooks").decode().strip())
        if not default_hooks.is_absolute():
            default_hooks = repo / default_hooks
        for hook in default_hooks.iterdir() if default_hooks.is_dir() else []:
            if hook.name.endswith(".sample"):
                continue
            mode = hook.stat().st_mode
            if hook.is_file() and (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                print(
                    "Refusing to disable existing executable default Git hooks.",
                    file=sys.stderr,
                )
                return EXIT_ERROR

    hooks_dir.mkdir(parents=True, exist_ok=True)
    mapping = {
        "pre-commit": PRE_COMMIT.format(python=python),
        "pre-push": PRE_PUSH.format(python=python),
    }
    for name, body in mapping.items():
        path = hooks_dir / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Tests/dev can point hooks at an unpacked src tree without packaging.
    dev_src = os.environ.get("GUARDRAILS_DEV_SRC", "").strip()
    if dev_src and Path(dev_src, "guardrails").is_dir():
        for name in mapping:
            path = hooks_dir / name
            text = path.read_text()
            export = f'export PYTHONPATH="{dev_src}${{PYTHONPATH:+:$PYTHONPATH}}"\n'
            if "PYTHONPATH=" not in text:
                path.write_text(text.replace("set -eu\n", "set -eu\n" + export, 1))

    git(repo, "config", "--local", "core.hooksPath", ".githooks")
    print("Enabled local pre-commit and pre-push public repository guards.")
    return EXIT_OK
