"""Thin argparse CLI for guardrails."""

from __future__ import annotations

import argparse
import sys

from guardrails import __version__
from guardrails.errors import EXIT_ERROR, GuardError
from guardrails.publication import resolve_repo, scan_history, scan_pre_push, scan_staged
from guardrails.setup_hooks import install_hooks


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrails",
        description="Fail-closed publication and security checks for public Git repositories.",
    )
    parser.add_argument("--version", action="version", version=f"guardrails {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Scan staged objects, history, or security surfaces")
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

    sub.add_parser("doctor", help="report versions, coverage, hooks, and protection state")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            print(f"guardrails {__version__}")
            return 0
        repo = resolve_repo()
        if args.command == "check":
            if args.staged:
                return scan_staged(repo)
            if args.history is not None:
                return scan_history(repo, args.history)
            if args.security:
                raise GuardError("Security scanning is not implemented yet")
        if args.command == "hook" and args.hook_command == "pre-push":
            return scan_pre_push(repo)
        if args.command == "setup" and args.setup_command == "apply":
            if not args.hooks_only:
                raise GuardError("Full setup apply requires a reviewed preview; use --hooks-only for hooks")
            return install_hooks(repo)
        raise GuardError(f"Unhandled command: {args.command}")
    except (GuardError, OSError, ValueError, UnicodeError) as error:
        message = (
            str(error)
            if isinstance(error, GuardError)
            else "Unable to complete the public repository scan"
        )
        print(f"BLOCKED: {message}", file=sys.stderr)
        # Publication findings use exit 1 via report_findings; configuration
        # and execution failures use exit 2.
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
