# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ Current |

## Reporting a Vulnerability

If you discover a security vulnerability in Plumbum, **do not open a public issue.**

Instead, please report it privately:

1. Use [GitHub Security Advisories](https://github.com/copyleftdev/plumbum/security/advisories/new) to report the vulnerability directly.
2. Alternatively, email the maintainer with details.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix or mitigation**: within 30 days for confirmed vulnerabilities

### Scope

Plumbum processes untrusted network data (PCAP files, Zeek logs). The following are in scope:

- Memory safety issues in the PCAP/DNS wire-format parser
- SQLite injection via crafted DNS records
- Denial of service via malformed input
- Path traversal in export or init commands

### Out of Scope

- Vulnerabilities in upstream dependencies (report those upstream)
- Issues requiring physical access to the machine
- Social engineering

## Security Design Principles

- **No `unsafe` blocks** in application code
- **No external parsing dependencies** — all wire-format parsing is hand-written with bounds checking
- **SQLite parameterized queries** throughout — no string interpolation in SQL
- **Input validation** before persistence
- **WAL mode** with foreign key enforcement
