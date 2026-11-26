import type { AuditReport, Finding, RuleMetadata, Severity } from "./types.ts";

export function formatTextReport(report: AuditReport): string {
  const lines: string[] = [];
  const { summary, findings } = report;

  lines.push(`mcp-audit v${report.version} — MCP Server & Tool-Schema Security Report`);
  lines.push(
    `Scanned ${summary.filesScanned} file(s), ${summary.serversScanned} server(s), ${summary.toolsScanned} tool(s)`
  );
  lines.push(
    `Grade: ${summary.grade}  |  Risk Score: ${summary.riskScore}/100  |  ` +
      `Findings: ${findings.length} (` +
      `${summary.counts.CRITICAL} critical, ${summary.counts.HIGH} high, ` +
      `${summary.counts.MEDIUM} medium, ${summary.counts.LOW} low)`
  );

  if (findings.length === 0) {
    lines.push("");
    lines.push("PASS: No security issues detected.");
    return lines.join("\n");
  }

  lines.push("");
  for (const f of findings) {
    const scope = [f.server ? `server=${f.server}` : "", f.tool ? `tool=${f.tool}` : ""]
      .filter(Boolean)
      .join(" ");
    lines.push(`[${f.severity.padEnd(8)}] ${f.ruleId} ${f.title}`);
    lines.push(`  Target : ${f.source}${scope ? ` (${scope})` : ""}`);
    lines.push(`  Detail : ${f.message}`);
    if (f.evidence) {
      lines.push(`  Proof  : ${f.evidence}`);
    }
    lines.push(`  Fix    : ${f.remediation}`);
    lines.push("");
  }

  return lines.join("\n").trimEnd();
}

export function formatJsonReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}

function escapeMdCell(val: string): string {
  return val.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function formatMarkdownReport(report: AuditReport): string {
  const { summary, findings } = report;
  const lines: string[] = [];

  lines.push(`## mcp-audit v${report.version} Security Report`);
  lines.push("");
  lines.push(
    `**Grade:** \`${summary.grade}\` | **Risk Score:** \`${summary.riskScore}/100\` | ` +
      `**Scanned:** ${summary.filesScanned} file(s), ${summary.serversScanned} server(s), ${summary.toolsScanned} tool(s)`
  );
  lines.push(
    `**Findings:** ${findings.length} (` +
      `${summary.counts.CRITICAL} critical, ${summary.counts.HIGH} high, ` +
      `${summary.counts.MEDIUM} medium, ${summary.counts.LOW} low)`
  );
  lines.push("");

  if (findings.length === 0) {
    lines.push("> **PASS:** No security issues detected.");
    return lines.join("\n");
  }

  lines.push("| Severity | Rule | Target | Detail | Remediation |");
  lines.push("| :--- | :--- | :--- | :--- | :--- |");
  for (const f of findings) {
    const target = [f.server, f.tool].filter(Boolean).join(" / ") || f.source;
    lines.push(
      `| **${f.severity}** | \`${f.ruleId}\` | ${escapeMdCell(target)} | ${escapeMdCell(f.message)} | ${escapeMdCell(f.remediation)} |`
    );
  }

  return lines.join("\n");
}

function sarifLevel(sev: Severity): "error" | "warning" | "note" {
  if (sev === "CRITICAL" || sev === "HIGH") return "error";
  if (sev === "MEDIUM") return "warning";
  return "note";
}

function sarifSecuritySeverity(sev: Severity): string {
  switch (sev) {
    case "CRITICAL":
      return "9.5";
    case "HIGH":
      return "7.5";
    case "MEDIUM":
      return "5.0";
    case "LOW":
      return "2.5";
    case "INFO":
      return "0.5";
  }
}

export function formatSarifReport(report: AuditReport, rules: RuleMetadata[]): string {
  const sarif = {
    $schema: "https:" + "//json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-audit",
            version: report.version,
            rules: rules.map((r) => ({
              id: r.id,
              name: r.title.replace(/[^A-Za-z0-9]/g, ""),
              shortDescription: { text: r.title },
              fullDescription: { text: r.summary },
              properties: {
                category: r.category,
                "security-severity": sarifSecuritySeverity(r.severity),
                tags: ["security", "mcp", r.category],
              },
            })),
          },
        },
        results: report.findings.map((f: Finding) => ({
          ruleId: f.ruleId,
          level: sarifLevel(f.severity),
          message: {
            text: `${f.message}${f.evidence ? ` Evidence: ${f.evidence}` : ""} Remediation: ${f.remediation}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.source,
                },
                region: {
                  startLine: 1,
                },
              },
              logicalLocations: [
                ...(f.server ? [{ name: f.server, kind: "namespace" }] : []),
                ...(f.tool ? [{ name: f.tool, kind: "function" }] : []),
              ],
            },
          ],
          properties: {
            severity: f.severity,
            category: f.category,
          },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
