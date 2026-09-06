"""Publication scanning over staged objects and Git history."""

from __future__ import annotations

import re
import sys
from pathlib import Path, PurePosixPath

from guardrails.content import MAX_BYTES, content_categories, path_categories
from guardrails.errors import GuardError
from guardrails.gitops import git, repository_root
from guardrails.policy import POLICY_PATH, load_policy
from guardrails.report import report_findings

OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class PublicationGuard:
    def __init__(self, repo: Path, allowed: set[str]) -> None:
        self.repo = repo
        self.allowed = allowed
        self.findings: set[tuple[str, str]] = set()
        self.blobs: dict[tuple[str, str], set[str]] = {}

    def check_content(self, path: str, raw: bytes) -> None:
        for category in content_categories(raw, path):
            self.findings.add((path, category))

    def check_entry(self, path: str, mode: str, oid: str) -> None:
        for category in path_categories(path, mode, self.allowed):
            self.findings.add((path, category))
        if mode not in {"100644", "100755"}:
            return
        cache_key = (oid, PurePosixPath(path).name)
        if cache_key not in self.blobs:
            size = int(git(self.repo, "cat-file", "-s", oid))
            self.blobs[cache_key] = (
                {"oversized-file"}
                if size > MAX_BYTES
                else content_categories(git(self.repo, "cat-file", "blob", oid), path)
            )
        for category in self.blobs[cache_key]:
            self.findings.add((path, category))

    def check_tree(self, tree: str) -> None:
        for record in git(self.repo, "ls-tree", "-rz", "--full-tree", tree).split(b"\0"):
            if record:
                metadata, name = record.split(b"\t", 1)
                mode, _, oid = metadata.decode("ascii").split()
                path = name.decode("utf-8", errors="surrogateescape")
                self.check_entry(path, mode, oid)

    def history(self, refs: list[str] | None) -> None:
        if git(self.repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
            raise GuardError("History scan requires a complete clone (fetch-depth: 0)")
        if not refs:
            refs = git(self.repo, "for-each-ref", "--format=%(refname)").decode().splitlines()
            try:
                refs.append(git(self.repo, "rev-parse", "--verify", "HEAD").decode().strip())
            except GuardError:
                pass  # An unborn repository has no HEAD.
        policies: dict[frozenset[str], list[str]] = {}
        tags: set[str] = set()
        for ref in refs:
            if not ref or ref.startswith("-"):
                raise GuardError("Invalid history reference")
            if content_categories(ref.encode()):
                raise GuardError("Credential detected in history reference name")
            oid = git(self.repo, "rev-parse", "--verify", "--end-of-options", ref).decode().strip()
            if not OID.fullmatch(oid):
                raise GuardError("Invalid resolved object identifier")
            while True:
                kind = git(self.repo, "cat-file", "-t", oid).strip()
                if kind == b"commit":
                    record = git(self.repo, "ls-tree", "-z", oid, "--", POLICY_PATH).rstrip(b"\0")
                    if not record:
                        raise GuardError("Every published tip must contain a public policy")
                    metadata, _ = record.split(b"\t", 1)
                    mode, kind_name, policy_oid = metadata.decode("ascii").split()
                    if mode != "100644" or kind_name != "blob":
                        raise GuardError("Published tip policy must be a regular file")
                    if int(git(self.repo, "cat-file", "-s", policy_oid)) > MAX_BYTES:
                        raise GuardError("Public policy exceeds size limit")
                    allowed = frozenset(load_policy(git(self.repo, "cat-file", "blob", policy_oid)))
                    policies.setdefault(allowed, []).append(oid)
                    break
                if kind != b"tag":
                    raise GuardError(
                        "Public refs must resolve to commits, not standalone trees or blobs"
                    )
                if oid in tags:
                    break
                tags.add(oid)
                raw = git(self.repo, "cat-file", "tag", oid)
                headers, _, _ = raw.partition(b"\n\n")
                self.check_content("<tag-metadata-and-message>", raw)
                oid = headers.splitlines()[0].removeprefix(b"object ").decode("ascii")
                if not OID.fullmatch(oid):
                    raise GuardError("Invalid annotated tag target")
        for allowed, commits in policies.items():
            self.allowed = set(allowed)
            trees: set[str] = set()
            for commit in git(self.repo, "rev-list", *sorted(set(commits)), "--").splitlines():
                raw = git(self.repo, "cat-file", "commit", commit.decode())
                headers, _, _ = raw.partition(b"\n\n")
                self.check_content("<commit-metadata-and-message>", raw)
                tree = headers.splitlines()[0].removeprefix(b"tree ").decode("ascii")
                if not OID.fullmatch(tree):
                    raise GuardError("Invalid commit tree")
                if tree not in trees:
                    trees.add(tree)
                    self.check_tree(tree)

    def report(self, *, output_format: str = "text") -> int:
        return report_findings(self.findings, output_format=output_format)


def scan_staged(repo: Path, *, output_format: str = "text") -> int:
    entries: list[tuple[str, str, str]] = []
    policy_oid: str | None = None
    for record in git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if record:
            metadata, name = record.split(b"\t", 1)
            mode, oid, stage = metadata.decode("ascii").split()
            if stage != "0":
                raise GuardError("Unmerged index entries must be resolved before publication")
            path = name.decode("utf-8", errors="surrogateescape")
            entries.append((path, mode, oid))
            if path == POLICY_PATH and mode == "100644":
                policy_oid = oid
    if policy_oid is None:
        raise GuardError("Stage a regular public policy file before committing")
    if int(git(repo, "cat-file", "-s", policy_oid)) > MAX_BYTES:
        raise GuardError("Public policy exceeds size limit")
    guard = PublicationGuard(repo, load_policy(git(repo, "cat-file", "blob", policy_oid)))
    for entry in entries:
        guard.check_entry(*entry)
    return guard.report(output_format=output_format)


def scan_history(repo: Path, refs: list[str] | None, *, output_format: str = "text") -> int:
    guard = PublicationGuard(repo, set())
    guard.history(refs)
    return guard.report(output_format=output_format)


def parse_pre_push_refs(stdin_text: str | None = None) -> list[str]:
    refs: list[str] = []
    stream = stdin_text if stdin_text is not None else sys.stdin.read()
    for line in stream.splitlines():
        fields = line.split()
        if len(fields) != 4:
            raise GuardError("Malformed pre-push input")
        local_ref, local_oid, remote_ref, remote_oid = fields
        if content_categories(local_ref.encode()) or content_categories(remote_ref.encode()):
            raise GuardError("Credential detected in outgoing reference name")
        if (
            not OID.fullmatch(local_oid)
            or not OID.fullmatch(remote_oid)
            or len(local_oid) != len(remote_oid)
            or not remote_ref.startswith("refs/")
            or local_ref.startswith("-")
        ):
            raise GuardError("Invalid pre-push reference input")
        if set(local_oid) != {"0"}:
            refs.append(local_oid)
    return refs


def scan_pre_push(
    repo: Path,
    stdin_text: str | None = None,
    *,
    output_format: str = "text",
) -> int:
    refs = parse_pre_push_refs(stdin_text)
    guard = PublicationGuard(repo, set())
    if not refs:
        return guard.report(output_format=output_format)  # Deletions or no-op push.
    guard.history(refs)
    return guard.report(output_format=output_format)


def resolve_repo() -> Path:
    return repository_root()
