# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-28

### Added

- **plumbum-core**: DNS record types, PCAP/pcapng parser, Zeek dns.log parser, feature extraction (Shannon entropy, beacon detection, subdomain diversity)
- **plumbum-score**: Composite scoring engine with three weight presets (default, optimized, regularized), corpus normalization, full score decomposition and explanation
- **plumbum-store**: SQLite persistence with WAL mode, batch ingest, prepared queries, JSON/CSV/Sigma export
- **plumbum-config**: HCL-style configuration parser with analysis weights and threshold defaults
- **plumbum-cli**: Full CLI with commands: `init`, `validate`, `plan`, `apply`, `show`, `explain`, `export`, `dashboard`, `version`
- **plumbum-tui**: Interactive terminal dashboard with sparkline, score gauge, and severity badge widgets
- **plumbum-mcp**: MCP server over stdio JSON-RPC with resource listing and tool calls
- Linux SLL (link type 113) support for cooked captures
- Sigma rule export format for SIEM integration

[0.1.0]: https://github.com/copyleftdev/plumbum/releases/tag/v0.1.0
