# Contributing to Plumbum

Thank you for your interest in improving Plumbum. This document covers how to propose changes, the development workflow, and what we expect from contributions.

## Getting Started

```sh
git clone https://github.com/copyleftdev/plumbum.git
cd plumbum
cargo build
cargo test --workspace
```

All 7 crates must build with **zero warnings** before submitting a PR.

## Development Workflow

1. **Fork** the repository and create a feature branch from `main`.
2. **Write tests** for any new functionality or bug fix.
3. **Keep commits small** and focused — one logical change per commit.
4. **Run the full check** before pushing:

```sh
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

5. **Open a pull request** against `main` with a clear description.

## What We Accept

- Bug fixes with regression tests
- New input format parsers (e.g., JSON Zeek logs, EVE JSON)
- Scoring model improvements backed by data
- Export format additions (STIX, MISP, etc.)
- TUI enhancements
- MCP server tool/resource additions
- Documentation improvements

## What We Don't Accept

- External parsing dependencies (we parse DNS wire format by hand)
- Logging frameworks (use `eprintln!` for diagnostics)
- Regex in hot parsing paths
- Changes that break deterministic scoring
- Large refactors without prior discussion

## Code Style

- Follow existing patterns in each crate.
- No comments that restate what the code does — comments explain *why*.
- All public functions need doc comments.
- Prefer explicit error handling over `.unwrap()` in library code.

## Crate Ownership

Each crate has a clear boundary. PRs should stay within a single crate when possible:

| Crate | Scope |
| --- | --- |
| `plumbum-core` | DNS types, parsers, feature extraction |
| `plumbum-score` | Weights, normalization, composite scoring, explain |
| `plumbum-store` | SQLite schema, ingest, queries, artifacts |
| `plumbum-config` | HCL parser, config types, defaults |
| `plumbum-cli` | CLI commands and argument handling |
| `plumbum-tui` | Terminal UI widgets and views |
| `plumbum-mcp` | MCP server protocol and handlers |

## Reporting Issues

Use [GitHub Issues](https://github.com/copyleftdev/plumbum/issues) with the provided templates. Include:

- Steps to reproduce
- Expected vs. actual behavior
- Input file format (PCAP, pcapng, Zeek)
- Plumbum version (`plumbum version`)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
