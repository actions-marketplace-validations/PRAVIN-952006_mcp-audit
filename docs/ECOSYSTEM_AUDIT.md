# Ecosystem Audit: Top Public MCP Server Install Configs (Nov 2026)

To benchmark `mcp-audit` on real-world defaults, we queried the top 140 most-starred public GitHub repositories matching `mcp server` / `mcp-server` (non-archived) via the GitHub API on **2026-11-25**, extracted every parseable `mcpServers` / `servers` JSON installation snippet from their primary `README.md`, and audited each with `mcp-audit scan --format json`.

> **Note:** This study audits only publicly published `README.md` quick-start configuration snippets (not live servers). Flagging `MCP001` or `MCP002` does not mean a repository is malicious—it highlights that copy-pasting unpinned `npx -y` / `uvx` snippets or placeholder credential patterns leaves users exposed to upstream package takeovers, credential leakage, or silent tool-schema rug-pulls on next restart.

### Key Findings (20 Top-Starred Public Repositories, >= 3,500 Stars)
- **20** top-starred repositories exposed parseable `mcpServers` / `servers` JSON install blocks in their primary `README.md`.
- **16 of 20 (80.0%)** triggered **`MCP001` (Unpinned ephemeral package runner)** — recommending `npx -y` or `uvx` without an exact immutable version pin.
- **1 of 20 (5.0%)** additionally triggered **`MCP002` (Credential/token pattern in config snippet)**.
- **4 of 20 (20.0%)** scored **Grade A (0 findings)** by using HTTPS endpoints, containers, or pinned/local executables.

### Per-Repository Breakdown (Snapshot: 2026-11-25)

| Repository | Stars | Grade | Risk Score | Rules Triggered |
| :--- | ---: | :---: | ---: | :--- |
| [ChromeDevTools/chrome-devtools-mcp](https://github.com/ChromeDevTools/chrome-devtools-mcp) | 59,312 | B | 15 | `MCP001` |
| [DayuanJiang/next-ai-draw-io](https://github.com/DayuanJiang/next-ai-draw-io) | 37,176 | B | 15 | `MCP001` |
| [github/github-mcp-server](https://github.com/github/github-mcp-server) | 34,743 | A | 0 | None |
| [googleapis/mcp-toolbox](https://github.com/googleapis/mcp-toolbox) | 16,948 | B | 15 | `MCP001` |
| [GLips/Figma-Context-MCP](https://github.com/GLips/Figma-Context-MCP) | 16,311 | B | 15 | `MCP001` |
| [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | 12,039 | B | 15 | `MCP001` |
| [wonderwhy-er/DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP) | 10,414 | B | 15 | `MCP001` |
| [awslabs/mcp](https://github.com/awslabs/mcp) | 9,950 | B | 15 | `MCP001` |
| [idosal/git-mcp](https://github.com/idosal/git-mcp) | 8,535 | A | 0 | None |
| [irinabuht12-oss/google-ads-meta-ads-mcp](https://github.com/irinabuht12-oss/google-ads-meta-ads-mcp) | 8,329 | A | 0 | None |
| [AgentDeskAI/browser-tools-mcp](https://github.com/AgentDeskAI/browser-tools-mcp) | 7,344 | B | 15 | `MCP001` |
| [sooperset/mcp-atlassian](https://github.com/sooperset/mcp-atlassian) | 6,157 | B | 15 | `MCP001` |
| [makenotion/notion-mcp-server](https://github.com/makenotion/notion-mcp-server) | 4,724 | B | 15 | `MCP001` |
| [MarkusPfundstein/mcp-obsidian](https://github.com/MarkusPfundstein/mcp-obsidian) | 4,551 | A | 0 | None |
| [antvis/mcp-server-chart](https://github.com/antvis/mcp-server-chart) | 4,423 | B | 15 | `MCP001` |
| [stickerdaniel/linkedin-mcp-server](https://github.com/stickerdaniel/linkedin-mcp-server) | 4,307 | B | 15 | `MCP001` |
| [Pimzino/spec-workflow-mcp](https://github.com/Pimzino/spec-workflow-mcp) | 4,303 | B | 15 | `MCP001` |
| [bostrot/wslmanager](https://github.com/bostrot/wslmanager) | 4,072 | D | 45 | `MCP002`, `MCP001` |
| [grafana/mcp-grafana](https://github.com/grafana/mcp-grafana) | 3,699 | B | 15 | `MCP001` |
| [aws/agent-toolkit-for-aws](https://github.com/aws/agent-toolkit-for-aws) | 3,569 | B | 15 | `MCP001` |

### Recommended Hardening
1. **Pin exact versions** in `npx`/`uvx` commands (e.g., `@scope/pkg@1.2.3` or `pkg==1.2.3`).
2. **Keep credentials out of JSON configs** using environment references (`${ENV_VAR}`), or run `mcp-audit fix <file> --write` to auto-harden local configs.
3. **Lock live tool schemas** with `mcp-audit pin .cursor/mcp.json --probe` and run `mcp-audit verify --probe` in CI so any silent post-install description mutation (`RUG001`) fails the build.
