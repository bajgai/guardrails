# Product specification

Reusable public-repository publication and security guardrails.

## Purpose

Provide a shared Python CLI that fails closed before publishing files or history
to a public Git repository, without weakening protections already proven in
consuming projects.

## Architecture

Python 3.11+, standard `src` package layout, thin `argparse` CLI. Separate:

- Git object traversal and snapshot creation
- Policy parsing and publication decisions
- Scanner execution and result normalization
- Setup and GitHub reconciliation
- Sanitized reporting

Use typed dataclasses/enums for policies, findings, scan outcomes, and setup
plans. Keep policy decisions pure where practical; isolate filesystem,
subprocess, and network effects.

Provide one shared subprocess runner with argument arrays, explicit working
directories, timeouts, bounded captured output, and sanitized errors. Do not
use `shell=True`, broad exception swallowing, global directory changes, or
success-shaped fallback results.

Prefer small cohesive modules and straightforward composition. Do not build a
plugin framework, rule language, daemon, dashboard, or LLM-based classifier.
Share behavior between local and CI entry points.

## Public interface

| Command | Contract |
|---|---|
| `guardrails init PATH` | Prepare setup preview and candidate public-file list |
| `guardrails setup apply` | Apply reviewed setup; reject stale previews and preserve custom hooks |
| `guardrails check --staged` | Scan the entire Git index using the staged policy |
| `guardrails check --history [REF...]` | Scan complete reachable histories |
| `guardrails check --security` | Run security scanners against a Git snapshot |
| `guardrails hook pre-push` | Inspect every outgoing ref from Git hook input |
| `guardrails github plan\|apply\|verify` | Preview, apply, and verify protections |
| `guardrails doctor` | Report versions, coverage, hooks, and protection state |
| `guardrails update` | Preview explicit integration and version upgrades |

Provide sanitized text and versioned JSON output.

Exit codes:

- `0` completed without blockers
- `1` blocking findings
- `2` configuration or execution failure

## Publication policy

Preserve version-1 policy compatibility, exact public-file approval,
staged-object inspection, deleted historical content, merges, commit/tag
metadata, and ref-name checks.

Reject incomplete histories, credential material, authenticated state, unsafe
paths, unreviewed binaries, symlinks, submodules, and sensitive exports.

Separate generic rules from business-specific restrictions. Consumers may keep
stricter local behavior during migration.

Permit legitimate assets and synthetic fixtures only through exact-path,
SHA-256-bound review records. Changed and historical content require matching
approvals. Credential findings remain blocking.

## Security scanning

- Gitleaks for credentials
- OSV-Scanner for dependencies
- Semgrep with bundled versioned rules
- Zizmor for GitHub Actions

Run publication and credential gates on commit/push. Run full security checks
explicitly locally and on CI pull requests, pushes, and weekly schedules.

Block high/critical security findings. Report lower-severity and ambiguous
personal-data findings as warnings. Exceptions require a specific finding,
reason, and expiration.

Report unsupported inputs and unavailable scanners. Missing, stale, or
incomplete vulnerability data cannot produce an unqualified pass.

Never automatically approve existing files, baseline old leaks, or rewrite
history.

Keep private custom rules outside repositories. They supplement public rules
and remain local. CI must report that it ran public rules only.

Never emit matched values or source excerpts. Sanitize paths and private-rule
identifiers; upload no raw scanner reports. Scan isolated snapshots without
executing project code, lifecycle scripts, Git filters, or repository-supplied
commands.

## GitHub protections

Setup must preview exact changes, apply explicitly, and read back:

- Secret scanning and push protection
- Pull requests and current passing checks
- Administrator enforcement
- Disabled force-pushes and branch deletion
- Preservation of stronger existing protections

Use read-only workflows, full-commit Action pins, no persisted checkout
credentials, and no privileged execution of pull-request code. For
single-maintainer repositories, require a pull request without requiring
another person's approval.

## Limits

Local hooks remain bypassable; CI executes after upload. Automated scans do not
replace human review of proprietary information before publication.
