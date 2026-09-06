# guardrails

Fail-closed publication and security checks for public Git repositories.

`guardrails` inspects staged Git objects and reachable history, enforces an
exact-path public policy, runs credential and security scanners against isolated
snapshots, and helps configure local hooks and GitHub repository protections.

## Status

Early development. The first public release will be published to
[`bajgai/guardrails`](https://github.com/bajgai/guardrails) under the MIT
license.

## Requirements

- Python 3.11+
- Git
- Optional scanners: Gitleaks, OSV-Scanner, Semgrep, Zizmor

## Documentation

- Product behavior: [`docs/product-specification.md`](docs/product-specification.md)
- Contributing and review expectations: coming with the first packaged release

## License

MIT. See [`LICENSE`](LICENSE).
