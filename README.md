<div align="center">

# Plumbum

**Deterministic DNS TXT tunnel detection.**

It does not guess. It computes.\
It does not alert. It explains.

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#install)
[![Crates](https://img.shields.io/badge/crates-7-8B5CF6)](#architecture)

</div>

---

Plumbum computes composite anomaly scores from PCAP and Zeek dns.log files, persists results in SQLite, and produces fully decomposable explanations for every finding. No machine learning. No black boxes. Every score is a deterministic function of six inspectable features.

## Install

```sh
cargo build --release
```

Two binaries are produced in `target/release/`:

| Binary | Purpose |
|---|---|
| `plumbum` | CLI for analysis, scoring, and export |
| `plumbum-mcp` | MCP server over stdio JSON-RPC |

## Quick Start

```sh
plumbum init                                    # create .plumbum/ working directory
plumbum validate capture.pcap                   # check file structure
plumbum plan capture.pcap                       # dry-run: preview scope
plumbum apply capture.pcap --c2-domains evil.tk # full analysis
plumbum show evil.tk                            # inspect a domain
plumbum explain evil.tk                         # score decomposition
plumbum export --format json                    # export findings
plumbum dashboard                               # interactive TUI
```

<details>
<summary><strong>Example output</strong></summary>

```console
Plumbum Findings:

CRITICAL   94.4  evil.tk

Artifacts written to .plumbum/plumbum.db (run #1)

Summary: 1 domains scored, 1 CRITICAL, 0 HIGH, 0 MEDIUM
```

```console
Domain: evil.tk
Score:  94.4 (CRITICAL)

Components:
  entropy                norm=0.000  w=0.1500  contrib=0.000  ( 0.0%)
  periodicity            norm=1.000  w=0.1000  contrib=0.100  ( 3.7%)
  volume                 norm=1.000  w=0.2500  contrib=0.250  ( 9.3%)
  length                 norm=1.000  w=0.1000  contrib=0.100  ( 3.7%)
  client_rarity          norm=1.000  w=1.8000  contrib=1.800  (66.7%)
  subdomain_diversity    norm=1.000  w=0.3000  contrib=0.300  (11.1%)
```

</details>

## Commands

| Command | Description |
|---|---|
| `init` | Create `.plumbum/` directory with config and database |
| `validate` | Parse inputs and report record counts |
| `plan` | Dry-run showing what will be analyzed |
| `apply` | Full analysis: parse, extract, score, persist |
| `show` | Display a domain's score and raw features |
| `explain` | Detailed score decomposition with per-feature contributions |
| `export` | Export as JSON, CSV, or Sigma rule |
| `dashboard` | Interactive TUI dashboard |
| `version` | Print version |

## Scoring Model

Plumbum uses a weighted linear model over **six normalized features**:

| Feature | Signal | Range |
|---|---|---|
| **Entropy** | Shannon entropy of TXT content | 0 = low, 1 = high |
| **Periodicity** | Regularity of query timing | 0 = irregular, 1 = clockwork |
| **Volume** | Query count per parent domain | 0 = quiet, 1 = loudest in corpus |
| **Length** | Mean TXT response length | 0 = short, 1 = longest in corpus |
| **Client Rarity** | Inverse of unique source IPs | 1 = single host (most suspicious) |
| **Subdomain Diversity** | Unique subdomains per parent | 0 = few, 1 = most in corpus |

### Weight Presets

| Preset | Description |
|---|---|
| `default` | Balanced equal-ish weights |
| `optimized` | Tuned via simulated annealing on labeled data |
| `regularized` | SA-informed with enforced feature diversity **(default)** |

### Severity Thresholds

| Severity | Score |
|---|---|
| **CRITICAL** | &ge; 80 |
| **HIGH** | &ge; 60 |
| **MEDIUM** | &ge; 40 |
| **LOW** | &lt; 40 |

## Supported Formats

| Format | Details |
|---|---|
| **PCAP** | Classic libpcap &mdash; both endianness, micro/nanosecond timestamps |
| **pcapng** | SHB / IDB / EPB blocks |
| **Zeek dns.log** | Tab-separated with standard `#fields` headers |
| **Link layers** | Ethernet (type 1), Linux SLL (type 113) |

## Configuration

`plumbum init` writes `.plumbum/config.hcl`:

```hcl
analysis {
  weight_preset              = "regularized"
  entropy_weight             = 0.15
  periodicity_weight         = 0.10
  volume_weight              = 0.25
  length_weight              = 0.10
  client_rarity_weight       = 1.80
  subdomain_diversity_weight = 0.30
}

thresholds {
  critical = 80
  high     = 60
  medium   = 40
}
```

## MCP Server

Plumbum exposes analysis results via the [Model Context Protocol](https://modelcontextprotocol.io) over stdio JSON-RPC:

```sh
plumbum-mcp
```

| Type | Endpoint | Description |
|---|---|---|
| Resource | `plumbum://domains` | Scored domains from the latest run |
| Resource | `plumbum://status` | Analysis state and run summary |
| Tool | `plumbum_explain` | Score decomposition for a domain |
| Tool | `plumbum_query` | Query scored domains with filters |

## Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                      plumbum-cli                        │
│              init validate plan apply                   │
│            show explain export dashboard                │
├────────────┬────────────┬───────────────┬───────────────┤
│plumbum-tui │plumbum-mcp │ plumbum-config│               │
│  ratatui   │ stdio rpc  │  HCL parser   │               │
├────────────┴────────────┴───────────────┤               │
│            plumbum-store                │ plumbum-score  │
│    SQLite · WAL · batch ingest          │  weights       │
│    schema · queries · artifacts         │  normalize     │
│                                         │  composite     │
│                                         │  explain       │
├─────────────────────────────────────────┴───────────────┤
│                     plumbum-core                        │
│          dns types · features · pcap · zeek             │
└─────────────────────────────────────────────────────────┘
```

| Crate | Role |
|---|---|
| [`plumbum-core`](plumbum-core/) | DNS types, PCAP/pcapng + Zeek parsers, feature extraction |
| [`plumbum-score`](plumbum-score/) | Composite scoring, weight presets, normalization, explain |
| [`plumbum-store`](plumbum-store/) | SQLite schema, batch ingest, prepared queries, export artifacts |
| [`plumbum-config`](plumbum-config/) | HCL config parser, types, defaults |
| [`plumbum-cli`](plumbum-cli/) | CLI binary (`plumbum`) |
| [`plumbum-tui`](plumbum-tui/) | Interactive dashboard with ratatui |
| [`plumbum-mcp`](plumbum-mcp/) | MCP server binary (`plumbum-mcp`) |

## License

This project is licensed under the [MIT License](LICENSE).
