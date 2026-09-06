"""Setup preview creation and application."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

from guardrails.content import DENIED_DIRS, DENIED_SUFFIXES, path_categories
from guardrails.errors import EXIT_OK, GuardError
from guardrails.gitops import git
from guardrails.models import SetupPreview
from guardrails.policy import POLICY_PATH
from guardrails.setup_hooks import install_hooks

PREVIEW_RELATIVE = Path(".scratch") / "guardrails-setup.json"


def _fingerprint(repo: Path) -> str:
    records: list[str] = []
    for record in git(repo, "ls-files", "-z").split(b"\0"):
        if not record:
            continue
        path = record.decode("utf-8", errors="surrogateescape")
        try:
            oid = git(repo, "ls-files", "-s", "--", path).decode().split()[1]
        except (GuardError, IndexError):
            oid = "missing"
        records.append(f"{oid}:{path}")
    digest = hashlib.sha256("\n".join(sorted(records)).encode()).hexdigest()
    return digest


def _candidate_paths(repo: Path) -> list[str]:
    paths: list[str] = []
    for record in git(repo, "ls-files", "-z").split(b"\0"):
        if not record:
            continue
        path = record.decode("utf-8", errors="surrogateescape")
        if path.startswith(".scratch/") or path == str(PREVIEW_RELATIVE):
            continue
        categories = path_categories(path, "100644", {path, POLICY_PATH})
        # Candidate generation ignores approval; keep denied shapes out.
        denied = categories - {"path-not-approved"}
        if denied:
            continue
        pure_parts = Path(path).parts
        if any(part.casefold() in DENIED_DIRS for part in pure_parts[:-1]):
            continue
        name = Path(path).name.casefold()
        if any(name.endswith(suffix) for suffix in DENIED_SUFFIXES):
            continue
        paths.append(path)
    if POLICY_PATH not in paths:
        paths.append(POLICY_PATH)
    return sorted(set(paths))


def create_preview(repo: Path) -> SetupPreview:
    preview = SetupPreview(
        version=1,
        kind="setup-preview",
        repo_fingerprint=_fingerprint(repo),
        public_paths=tuple(_candidate_paths(repo)),
        install_hooks=True,
    )
    path = repo / PREVIEW_RELATIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(preview.to_json_dict(), indent=2, sort_keys=True) + "\n")
    print(f"Wrote setup preview to {PREVIEW_RELATIVE}")
    print(f"Candidate public paths: {len(preview.public_paths)}")
    return preview


def load_preview(repo: Path) -> SetupPreview:
    path = repo / PREVIEW_RELATIVE
    if not path.is_file():
        raise GuardError("Setup preview is missing; run guardrails init first")
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError, UnicodeError) as error:
        raise GuardError("Setup preview is not valid JSON") from error
    if (
        not isinstance(payload, dict)
        or payload.get("version") != 1
        or payload.get("kind") != "setup-preview"
        or not isinstance(payload.get("repo_fingerprint"), str)
        or not isinstance(payload.get("public_paths"), list)
        or not all(isinstance(item, str) and item for item in payload["public_paths"])
    ):
        raise GuardError("Setup preview is malformed")
    return SetupPreview(
        version=1,
        kind="setup-preview",
        repo_fingerprint=payload["repo_fingerprint"],
        public_paths=tuple(payload["public_paths"]),
        install_hooks=bool(payload.get("install_hooks", True)),
    )


def apply_preview(repo: Path, *, hooks_only: bool = False) -> int:
    if hooks_only:
        return install_hooks(repo)
    preview = load_preview(repo)
    current = _fingerprint(repo)
    if preview.repo_fingerprint != current:
        raise GuardError("Setup preview is stale; regenerate it with guardrails init")
    paths = list(preview.public_paths)
    if POLICY_PATH not in paths:
        paths.append(POLICY_PATH)
    # Validate candidates through the same policy loader constraints.
    from guardrails.policy import load_policy

    raw = json.dumps({"version": 1, "public_paths": sorted(set(paths))}, indent=2) + "\n"
    load_policy(raw.encode())
    (repo / POLICY_PATH).write_text(raw)
    if preview.install_hooks:
        code = install_hooks(repo)
        if code != EXIT_OK:
            return code
    print(f"Applied setup preview with {len(set(paths))} public paths.", file=sys.stderr)
    return EXIT_OK
