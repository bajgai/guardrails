"""Thin argparse CLI for guardrails."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from guardrails import __version__
from guardrails.doctor import emit_doctor
from guardrails.errors import EXIT_ERROR, GuardError
from guardrails.github_protect import emit_apply, emit_plan, emit_verify
from guardrails.publication import resolve_repo, scan_history, scan_pre_push, scan_staged
from guardrails.setup import apply_preview, create_preview


def _add_format(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="sanitized text or versioned JSON output",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrails",
        description="Fail-closed publication and security checks for public Git repositories.",
    )
    parser.add_argument("--version", action="version", version=f"guardrails {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="prepare setup preview and candidate public-file list")
    init.add_argument("path", type=Path, help="repository path to initialize")

    check = sub.add_parser("check", help="Scan staged objects, history, or security surfaces")
    _add_format(check)
    modes = check.add_mutually_exclusive_group(required=True)
    modes.add_argument("--staged", action="store_true", help="scan the entire Git index")
    modes.add_argument(
        "--history",
        nargs="*",
        metavar="REF",
        help="scan complete histories; default all refs and HEAD",
    )
    modes.add_argument("--security", action="store_true", help="run security scanners")

    hook = sub.add_parser("hook", help="Git hook entry points")
    hook_sub = hook.add_subparsers(dest="hook_command", required=True)
    hook_sub.add_parser("pre-push", help="inspect outgoing refs from pre-push hook input")

    setup = sub.add_parser("setup", help="Apply reviewed local setup")
    setup_sub = setup.add_subparsers(dest="setup_command", required=True)
    apply = setup_sub.add_parser("apply", help="apply reviewed setup")
    apply.add_argument(
        "--hooks-only",
        action="store_true",
        help="install local Git hooks without a setup preview",
    )

    format_parent = argparse.ArgumentParser(add_help=False)
    _add_format(format_parent)

    github = sub.add_parser("github", help="preview, apply, and verify GitHub protections")
    github_sub = github.add_subparsers(dest="github_command", required=True)
    github_sub.add_parser(
        "plan",
        parents=[format_parent],
        help="preview exact GitHub protection changes",
    )
    github_sub.add_parser("apply", help="apply reviewed GitHub protection changes")
    github_sub.add_parser(
        "verify",
        parents=[format_parent],
        help="read back GitHub protection state",
    )

    doctor = sub.add_parser("doctor", help="report versions, coverage, hooks, and protection state")
    _add_format(doctor)

    sub.add_parser("update", help="preview explicit integration and version upgrades")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            target = args.path.resolve()
            if not (target / ".git").exists() and not (target / ".git").is_file():
                # Allow worktrees where .git is a file.
                raise GuardError("init requires an existing Git repository")
            create_preview(target)
            return 0
        if args.command == "doctor":
            repo: Path | None
            try:
                repo = resolve_repo()
            except GuardError:
                repo = None
            return emit_doctor(repo, output_format=args.output_format)
        if args.command == "update":
            print("No integration updates are available in this development build.")
            return 0
        if args.command == "github":
            repo = resolve_repo()
            output_format = getattr(args, "output_format", "text")
            if args.github_command == "plan":
                return emit_plan(repo, output_format=output_format)
            if args.github_command == "verify":
                return emit_verify(repo, output_format=output_format)
            if args.github_command == "apply":
                return emit_apply(repo)
            raise GuardError(f"Unhandled github command: {args.github_command}")
        repo = resolve_repo()
        output_format = getattr(args, "output_format", "text")
        if args.command == "check":
            if args.staged:
                return scan_staged(repo, output_format=output_format)
            if args.history is not None:
                return scan_history(repo, args.history, output_format=output_format)
            if args.security:
                raise GuardError("Security scanning is not implemented yet")
        if args.command == "hook" and args.hook_command == "pre-push":
            return scan_pre_push(repo, output_format=output_format)
        if args.command == "setup" and args.setup_command == "apply":
            return apply_preview(repo, hooks_only=args.hooks_only)
        raise GuardError(f"Unhandled command: {args.command}")
    except (GuardError, OSError, ValueError, UnicodeError) as error:
        message = (
            str(error)
            if isinstance(error, GuardError)
            else "Unable to complete the public repository scan"
        )
        print(f"BLOCKED: {message}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
