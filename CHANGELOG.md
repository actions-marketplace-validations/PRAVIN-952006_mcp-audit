# Changelog

All notable changes to `mcp-audit` are documented in this file.

## [0.5.0] - 2026-11-25
### Added
- **Cross-server Toxic Flow / Lethal Trifecta detection (`TOOL009`):** Flags MCP sessions combining untrusted external-content readers, private local/data access, and outbound messaging/network sinks (bringing the rule engine to **21 built-in rules**).
- **GitHub Step Summary / PR Comment Markdown reporter (`--format markdown`):** Generates ready-to-post Markdown summary tables with Grade, Risk Score, and per-finding remediations.
- **Rule suppression flag (`--ignore <rule1,rule2>`):** Allows intentional CI exceptions with automatic grade/risk-score recalculation.
- **Upgraded terminal hero visual (`assets/demo.svg`), 3-engine architecture diagram (`assets/architecture.svg`), GitHub Issue/PR templates, and expanded 20-repo empirical ecosystem benchmark (`docs/ECOSYSTEM_AUDIT.md`).**

## [0.4.0] - 2026-11-25
### Added
- **Auto-hardening (`mcp-audit fix <file> [--write]`):** Dry-run preview and in-place remediation for hardcoded secrets, `NODE_TLS_REJECT_UNAUTHORIZED=0`, wildcard `autoApprove`, and invisible Unicode Tag steganography.
- **Zero-install CLI support (`npx github:PRAVIN-952006/mcp-audit`):** Added `#!/usr/bin/env node` shebang and `prepare` build hook so anyone can run `mcp-audit` without cloning first.
- **README badges & comparison matrix** highlighting zero-dependency offline execution, Unicode Tag decoding, and GitHub Code Scanning SARIF 2.1.0 output.

## [0.3.0] - 2026-11-23
### Added
- **Live Streamable-HTTP / SSE probing (`probeHttpServer`):** Supports remote MCP servers via JSON-RPC 2.0 `initialize` -> `Mcp-Session-Id` -> `tools/list`, parsing both `application/json` and `text/event-stream` SSE frames.
- **Reusable GitHub Action (`action.yml`):** Composite action supporting `path`, `probe`, `lockfile`, `fail-on`, and `sarif-file` inputs for GitHub Code Scanning.
- **Visual terminal demo (`assets/demo.svg`)** embedded in `README.md`.
- **Hardened reference config (`examples/hardened-mcp.json`)** and `CONTRIBUTING.md`.

## [0.2.0] - 2026-11-23
### Added
- **Live stdio JSON-RPC 2.0 probing (`mcp-audit probe` / `--probe`):** Spawns local stdio MCP servers with a strict timeout, fetches live `tools/list` definitions, and audits them for poisoning, steganography, and rug-pull drift.
- End-to-end live stdio mock MCP server test.

## [0.1.0] - 2026-11-23
### Added
- Zero-dependency TypeScript CLI and library (`"dependencies": {}`).
- 20 security rules: `MCP001`–`MCP008` (static config), `TOOL001`–`TOOL008` (tool poisoning, Unicode Tag steganography decoding, shadowing, schema checks), and `RUG001`–`RUG004` (SHA-256 canonical-JSON rug-pull lockfile).
- Auto-discovery for Claude Desktop, Cursor, VS Code, Claude Code, and Windsurf.
- Text, JSON, and SARIF 2.1.0 reporters.
