# guardrails

Reusable Python CLI that fails closed before publishing files or history to a
public Git repository. Public release target: `bajgai/guardrails` (MIT).

## Commands

```sh
python3 -m unittest discover -s tests
python3 -m ruff check src tests
python3 -m ruff format --check src tests
python3 -m mypy src
python3 -m guardrails doctor
python3 -m guardrails check --staged
python3 -m guardrails check --history
```

Prefer the installed `guardrails` entry point after packaging.

## Boundaries

- Never emit matched secret values or source excerpts.
- Never automatically approve existing files, baseline old leaks, or rewrite history.
- Private custom rules stay outside the repository and supplement public rules.
- CI must report that it ran public rules only.
- Scan isolated Git snapshots; do not execute project code, lifecycle scripts,
  Git filters, or repository-supplied commands.
- Do not use `shell=True`, swallow broad exceptions, mutate the process cwd
  globally, or invent success-shaped fallback results.
- Keep machine-specific handoff, Cursor state, and operational records out of
  publication. Synthetic fixtures only.

## Coding standards

- Python 3.11+, `src` layout, thin `argparse` CLI.
- Separate Git traversal, policy decisions, scanners, setup/GitHub, and reporting.
- Typed dataclasses/enums for policies, findings, outcomes, and setup plans.
- Shared subprocess runner: argument arrays, explicit cwd, timeouts, bounded
  output, sanitized errors.
- Prefer small cohesive modules. No plugin framework, rule language, daemon,
  dashboard, or LLM classifier.
- Tests use `unittest`, temporary Git repositories, and runtime-generated
  synthetic credentials. Mock only GitHub/scanner boundaries.

## Product contract

See `docs/product-specification.md` for commands, exit codes, publication
rules, scanner policy, and acceptance expectations.
