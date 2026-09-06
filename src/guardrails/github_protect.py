"""GitHub repository protection planning and verification."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any, Callable

from guardrails.errors import EXIT_BLOCKED, EXIT_OK, GuardError
from guardrails.process import run_command

DEFAULT_REQUIRED_CHECKS = (
    "Public repository guard",
    "Secret scan",
)


@dataclass(frozen=True)
class ProtectionState:
    secret_scanning: bool
    push_protection: bool
    requires_pr: bool
    requires_passing_checks: bool
    includes_admins: bool
    allows_force_pushes: bool
    allows_deletions: bool
    required_checks: tuple[str, ...]

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "secret_scanning": self.secret_scanning,
            "push_protection": self.push_protection,
            "requires_pr": self.requires_pr,
            "requires_passing_checks": self.requires_passing_checks,
            "includes_admins": self.includes_admins,
            "allows_force_pushes": self.allows_force_pushes,
            "allows_deletions": self.allows_deletions,
            "required_checks": list(self.required_checks),
        }


@dataclass(frozen=True)
class ProtectionPlan:
    current: ProtectionState
    resulting: ProtectionState
    changes: tuple[str, ...]

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "current": self.current.to_json_dict(),
            "resulting": self.resulting.to_json_dict(),
            "changes": list(self.changes),
        }


def desired_state(
    current: ProtectionState,
    *,
    required_checks: tuple[str, ...] = DEFAULT_REQUIRED_CHECKS,
) -> ProtectionState:
    merged_checks = tuple(sorted(set(current.required_checks) | set(required_checks)))
    return ProtectionState(
        secret_scanning=True,
        push_protection=True,
        requires_pr=True,
        requires_passing_checks=True,
        includes_admins=True,
        allows_force_pushes=False,
        allows_deletions=False,
        required_checks=merged_checks,
    )


def plan_protections(
    current: ProtectionState,
    *,
    required_checks: tuple[str, ...] = DEFAULT_REQUIRED_CHECKS,
) -> ProtectionPlan:
    resulting = desired_state(current, required_checks=required_checks)
    changes: list[str] = []
    for field_name in (
        "secret_scanning",
        "push_protection",
        "requires_pr",
        "requires_passing_checks",
        "includes_admins",
        "allows_force_pushes",
        "allows_deletions",
    ):
        if getattr(current, field_name) != getattr(resulting, field_name):
            changes.append(field_name)
    if set(current.required_checks) != set(resulting.required_checks):
        changes.append("required_checks")
    return ProtectionPlan(current=current, resulting=resulting, changes=tuple(changes))


def verify_protections(desired: ProtectionState, actual: ProtectionState) -> bool:
    if (
        not actual.secret_scanning
        or not actual.push_protection
        or not actual.requires_pr
        or not actual.requires_passing_checks
        or not actual.includes_admins
        or actual.allows_force_pushes
        or actual.allows_deletions
    ):
        return False
    return set(desired.required_checks).issubset(set(actual.required_checks))


def _gh_api(repo: Path, endpoint: str) -> dict[str, Any]:
    result = run_command(["gh", "api", endpoint], cwd=repo, check=False)
    if result.returncode != 0:
        raise GuardError(
            "GitHub API request failed; inspect credentials and repository access locally"
        )
    try:
        payload = json.loads(result.stdout.decode())
    except (UnicodeError, ValueError) as error:
        raise GuardError("GitHub API returned malformed JSON") from error
    if not isinstance(payload, dict):
        raise GuardError("GitHub API returned an unexpected payload")
    return payload


def read_protection_state(repo: Path) -> ProtectionState:
    """Read current protection state through the GitHub CLI API."""
    remote = run_command(
        ["gh", "repo", "view", "--json", "nameWithOwner,defaultBranchRef"],
        cwd=repo,
        check=False,
    )
    if remote.returncode != 0:
        raise GuardError("Unable to resolve the GitHub repository with gh")
    try:
        meta = json.loads(remote.stdout.decode())
        full_name = meta["nameWithOwner"]
        branch = meta["defaultBranchRef"]["name"]
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise GuardError("Unable to parse GitHub repository metadata") from error

    security = _gh_api(repo, f"repos/{full_name}")
    secret_scanning = bool(
        ((security.get("security_and_analysis") or {}).get("secret_scanning") or {}).get("status")
        == "enabled"
    )
    push_protection = bool(
        (
            (security.get("security_and_analysis") or {}).get("secret_scanning_push_protection")
            or {}
        ).get("status")
        == "enabled"
    )
    try:
        rules = _gh_api(repo, f"repos/{full_name}/branches/{branch}/protection")
    except GuardError:
        # Unprotected branches fail closed into the weak baseline so plan shows needed changes.
        return ProtectionState(
            secret_scanning=secret_scanning,
            push_protection=push_protection,
            requires_pr=False,
            requires_passing_checks=False,
            includes_admins=False,
            allows_force_pushes=True,
            allows_deletions=True,
            required_checks=(),
        )
    required = rules.get("required_status_checks") or {}
    contexts = tuple(required.get("contexts") or ())
    enforce_admins = bool((rules.get("enforce_admins") or {}).get("enabled"))
    allow_force = bool((rules.get("allow_force_pushes") or {}).get("enabled"))
    allow_delete = bool((rules.get("allow_deletions") or {}).get("enabled"))
    pr_reviews = rules.get("required_pull_request_reviews")
    return ProtectionState(
        secret_scanning=secret_scanning,
        push_protection=push_protection,
        requires_pr=pr_reviews is not None,
        requires_passing_checks=bool(contexts) or bool(required.get("strict")),
        includes_admins=enforce_admins,
        allows_force_pushes=allow_force,
        allows_deletions=allow_delete,
        required_checks=contexts,
    )


def emit_plan(
    repo: Path,
    *,
    required_checks: tuple[str, ...] = DEFAULT_REQUIRED_CHECKS,
    output_format: str = "text",
    reader: Callable[[Path], ProtectionState] | None = None,
) -> int:
    read = reader or read_protection_state
    current = read(repo)
    plan = plan_protections(current, required_checks=required_checks)
    if output_format == "json":
        print(json.dumps(plan.to_json_dict(), indent=2, sort_keys=True))
    elif not plan.changes:
        print("GitHub protections already satisfy the required baseline.")
    else:
        print("Planned GitHub protection changes:")
        for change in plan.changes:
            print(f"- {change}")
    return EXIT_OK


def emit_verify(
    repo: Path,
    *,
    required_checks: tuple[str, ...] = DEFAULT_REQUIRED_CHECKS,
    output_format: str = "text",
    reader: Callable[[Path], ProtectionState] | None = None,
) -> int:
    read = reader or read_protection_state
    current = read(repo)
    desired = desired_state(current, required_checks=required_checks)
    ok = verify_protections(desired, current)
    payload = {
        "version": 1,
        "status": "ok" if ok else "mismatch",
        "actual": current.to_json_dict(),
        "desired": desired.to_json_dict(),
    }
    if output_format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif ok:
        print("GitHub protections match the required baseline.")
    else:
        print("GitHub protections do not match the required baseline.", file=sys.stderr)
    return EXIT_OK if ok else EXIT_BLOCKED


def emit_apply(
    repo: Path,
    *,
    required_checks: tuple[str, ...] = DEFAULT_REQUIRED_CHECKS,
    reader: Callable[[Path], ProtectionState] | None = None,
    applier: Callable[[Path, ProtectionState], None] | None = None,
) -> int:
    read = reader or read_protection_state
    current = read(repo)
    plan = plan_protections(current, required_checks=required_checks)
    if not plan.changes:
        print("No GitHub protection changes required.")
        return EXIT_OK
    if applier is None:
        raise GuardError(
            "GitHub apply requires an explicit applier; refusing to mutate repository "
            "settings without a reviewed apply path"
        )
    applier(repo, plan.resulting)
    print(f"Applied {len(plan.changes)} GitHub protection changes.")
    return EXIT_OK
