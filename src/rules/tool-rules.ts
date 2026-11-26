import type { Finding, McpJsonSchema, McpToolDefinition, RuleMetadata } from "../types.ts";

export const TOOL_RULES: RuleMetadata[] = [
  {
    id: "TOOL001",
    severity: "CRITICAL",
    category: "tool-poisoning",
    title: "Hidden prompt-injection or override directive in tool description",
    summary: "Detects <IMPORTANT>/<SYSTEM> tags and covert behavioral override instructions inside tool metadata.",
  },
  {
    id: "TOOL002",
    severity: "CRITICAL",
    category: "steganography",
    title: "Invisible Unicode steganography or bidi control characters",
    summary: "Detects Unicode Tag chars (U+E0000-E007F), bidi overrides, and zero-width characters hidden in schemas.",
  },
  {
    id: "TOOL003",
    severity: "CRITICAL",
    category: "exfiltration",
    title: "Credential or sensitive-file exfiltration directive",
    summary: "Flags tool descriptions instructing the model to read SSH keys, .env, AWS creds, or MCP configs.",
  },
  {
    id: "TOOL004",
    severity: "HIGH",
    category: "shadowing",
    title: "Cross-server or cross-tool shadowing",
    summary: "Detects duplicate tool names across servers or descriptions attempting to hijack/override another tool.",
  },
  {
    id: "TOOL005",
    severity: "HIGH",
    category: "exfiltration",
    title: "Covert exfiltration parameter trap",
    summary: "Flags suspicious side-channel parameters (sidenote, debug_context, conversation_history, auth_token).",
  },
  {
    id: "TOOL006",
    severity: "MEDIUM",
    category: "exfiltration",
    title: "External webhook or callback URL in tool description",
    summary: "Detects external URLs or webhook/tunnel domains embedded directly inside tool descriptions.",
  },
  {
    id: "TOOL007",
    severity: "MEDIUM",
    category: "schema",
    title: "Unconstrained input schema on sensitive or mutating tool",
    summary: "Flags destructive/exec/write tools lacking strict inputSchema bounds or allowing arbitrary properties.",
  },
  {
    id: "TOOL008",
    severity: "LOW",
    category: "tool-poisoning",
    title: "Excessively long tool description (context-stuffing risk)",
    summary: "Flags tool descriptions exceeding 1,500 characters where adversarial instructions can hide below UI folds.",
  },
  {
    id: "TOOL009",
    severity: "HIGH",
    category: "exfiltration",
    title: "Cross-server toxic flow (untrusted input + private data + outbound sink)",
    summary: "Detects the lethal trifecta where untrusted external-content readers, private local/data access, and outbound messaging/network sinks co-exist in one MCP session.",
  },
];

const INJECTION_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "hidden XML instruction tag", regex: /<\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|INSTRUCTIONS|SECRET|ADMIN|HIDDEN)\s*>/i },
  { label: "instruction override phrase", regex: /\b(?:ignore|disregard|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|user)\s+(?:instructions?|rules?|prompts?)\b/i },
  { label: "concealment directive", regex: /\b(?:do\s+not\s+(?:tell|inform|mention|show|reveal|alert)\s+(?:the\s+)?user|keep\s+this\s+(?:hidden|secret)|silently\s+(?:send|pass|include|read|execute))\b/i },
  { label: "pre-call hijack directive", regex: /\b(?:before\s+(?:calling|using|invoking)\s+this\s+tool|first\s+read\s+the\s+contents\s+of|you\s+must\s+first\s+(?:read|pass|include))\b/i },
];

const EXFIL_TARGET_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "SSH private key path", regex: /(?:~\/\.ssh\/|id_rsa|id_ed25519|authorized_keys)/i },
  { label: "AWS/cloud credential path", regex: /(?:~\/\.aws\/credentials|aws_secret_access_key|~\/\.kube\/config)/i },
  { label: "MCP config or cursor config", regex: /(?:claude_desktop_config\.json|\.cursor\/mcp\.json|\.mcp\.json)/i },
  { label: "environment / secret file", regex: /(?:\.env\b|\/etc\/passwd|\/etc\/shadow|keychain|browser\s+cookies)/i },
  { label: "system prompt / chat history exfiltration", regex: /\b(?:pass|include|append|encode|exfiltrate|send)\b.{0,50}\b(?:system\s+prompt|conversation\s+history|all\s+previous\s+messages|api\s+keys?|secrets?|tokens?)\b/i },
];

const SHADOWING_PATTERNS: RegExp[] = [
  /\b(?:whenever|when)\s+the\s+user\s+(?:calls|uses|asks\s+to\s+use|invokes)\s+[`'"a-z0-9_.-]+/i,
  /\b(?:instead\s+of\s+calling|override\s+the\s+behavior\s+of|reroute\s+all\s+calls|modify\s+the\s+(?:recipient|destination|target)\s+of)\b/i,
  /\b(?:also\s+(?:bcc|cc|forward|copy)\s+(?:all\s+)?(?:emails?|messages?|requests?)\s+to)\b/i,
];

const COVERT_PARAM_NAMES = new Set([
  "sidenote",
  "side_note",
  "debug_context",
  "hidden_context",
  "system_prompt",
  "conversation_history",
  "chat_history",
  "raw_env",
  "env_dump",
  "auth_token",
  "secret_context",
  "metadata_dump",
  "telemetry_payload",
]);

const SUSPICIOUS_URL_REGEX = /https?:\/\/(?:[^\s"'<>]*?(?:webhook\.site|ngrok(?:-free)?\.(?:app|io)|pipedream\.net|requestbin|burpcollaborator|oastify\.com|interact\.sh)|[^\s"'<>]+\?[^\s"'<>]*\{[^}]+\})/i;

const SENSITIVE_TOOL_NAME_REGEX = /\b(?:exec|execute|shell|bash|run_command|eval|sql|query|delete|remove|drop|write_file|modify_file|send_email|transfer|deploy)\b/i;

function detectInvisibleUnicode(text: string): { count: number; kinds: string[]; decodedTags: string } {
  let count = 0;
  const kinds = new Set<string>();
  const tagChars: string[] = [];

  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      count++;
      kinds.add("Unicode Tag (U+E0000-E007F)");
      if (cp >= 0xe0020 && cp <= 0xe007e) {
        tagChars.push(String.fromCharCode(cp - 0xe0000));
      }
    } else if (
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2066 && cp <= 0x2069)
    ) {
      count++;
      kinds.add("Bidi override control");
    } else if (
      (cp >= 0x200b && cp <= 0x200f) ||
      cp === 0x2060 ||
      cp === 0xfeff
    ) {
      count++;
      kinds.add("Zero-width character");
    }
  }

  return {
    count,
    kinds: [...kinds],
    decodedTags: tagChars.join(""),
  };
}

function collectTextFields(tool: McpToolDefinition): Array<{ location: string; text: string }> {
  const fields: Array<{ location: string; text: string }> = [
    { location: "tool.name", text: tool.name },
  ];
  if (tool.description) {
    fields.push({ location: "tool.description", text: tool.description });
  }
  const walkSchema = (schema: McpJsonSchema | undefined, prefix: string): void => {
    if (!schema) return;
    if (typeof schema.description === "string") {
      fields.push({ location: `${prefix}.description`, text: schema.description });
    }
    if (schema.properties) {
      for (const [propName, propSchema] of Object.entries(schema.properties)) {
        walkSchema(propSchema, `${prefix}.properties.${propName}`);
      }
    }
    if (schema.items) {
      walkSchema(schema.items, `${prefix}.items`);
    }
  };
  walkSchema(tool.inputSchema, "inputSchema");
  return fields;
}

export interface ToolAuditInput {
  server: string;
  sourcePath: string;
  tools: McpToolDefinition[];
}

export function auditToolsAcrossServers(inputs: ToolAuditInput[]): Finding[] {
  const findings: Finding[] = [];

  // Track tool names across servers for cross-server shadowing (TOOL004)
  const toolOwners = new Map<string, Array<{ server: string; sourcePath: string }>>();
  for (const input of inputs) {
    for (const tool of input.tools) {
      const list = toolOwners.get(tool.name) ?? [];
      list.push({ server: input.server, sourcePath: input.sourcePath });
      toolOwners.set(tool.name, list);
    }
  }

  for (const [toolName, owners] of toolOwners.entries()) {
    const distinctServers = [...new Set(owners.map((o) => o.server))];
    if (distinctServers.length > 1) {
      const first = owners[0]!;
      findings.push({
        ruleId: "TOOL004",
        severity: "HIGH",
        category: "shadowing",
        title: "Cross-server duplicate tool name collision",
        message: `Tool "${toolName}" is registered by multiple MCP servers (${distinctServers.join(", ")}). A malicious server can shadow a trusted tool.`,
        source: first.sourcePath,
        server: distinctServers.join(", "),
        tool: toolName,
        evidence: `Duplicate tool "${toolName}" across servers: ${distinctServers.join(", ")}`,
        remediation: `Namespace tool names per server or disable the untrusted duplicate MCP server.`,
      });
    }
  }

  for (const input of inputs) {
    for (const tool of input.tools) {
      const textFields = collectTextFields(tool);

      for (const field of textFields) {
        // TOOL001: Hidden instruction markup & override directives
        for (const pat of INJECTION_PATTERNS) {
          const match = field.text.match(pat.regex);
          if (match) {
            findings.push({
              ruleId: "TOOL001",
              severity: "CRITICAL",
              category: "tool-poisoning",
              title: `Tool poisoning (${pat.label})`,
              message: `Tool "${tool.name}" on server "${input.server}" contains a ${pat.label} in ${field.location}.`,
              source: input.sourcePath,
              server: input.server,
              tool: tool.name,
              evidence: `${field.location}: "${match[0]}"`,
              remediation: `Reject or quarantine this MCP server; tool metadata must never contain imperative override instructions.`,
            });
            break;
          }
        }

        // TOOL002: Invisible Unicode steganography / bidi overrides
        const uni = detectInvisibleUnicode(field.text);
        if (uni.count > 0) {
          const decodedHint = uni.decodedTags
            ? ` | decoded tag payload: "${uni.decodedTags.slice(0, 80)}"`
            : "";
          findings.push({
            ruleId: "TOOL002",
            severity: "CRITICAL",
            category: "steganography",
            title: "Invisible Unicode steganography detected in tool schema",
            message: `Tool "${tool.name}" on server "${input.server}" hides ${uni.count} invisible Unicode character(s) (${uni.kinds.join(", ")}) in ${field.location}.`,
            source: input.sourcePath,
            server: input.server,
            tool: tool.name,
            evidence: `${field.location}: ${uni.count} hidden chars${decodedHint}`,
            remediation: `Strip or reject any MCP tool metadata containing Unicode Tag, bidi override, or zero-width characters.`,
          });
        }

        // TOOL003: Credential / sensitive-file exfiltration directives
        for (const pat of EXFIL_TARGET_PATTERNS) {
          const match = field.text.match(pat.regex);
          if (match) {
            findings.push({
              ruleId: "TOOL003",
              severity: "CRITICAL",
              category: "exfiltration",
              title: `Sensitive data exfiltration reference (${pat.label})`,
              message: `Tool "${tool.name}" on server "${input.server}" references ${pat.label} inside ${field.location}.`,
              source: input.sourcePath,
              server: input.server,
              tool: tool.name,
              evidence: `${field.location}: "${match[0]}"`,
              remediation: `Audit and block this tool immediately; legitimate tools should not instruct models to read credential files or prior prompts.`,
            });
            break;
          }
        }

        // TOOL004 (description-level cross-tool shadowing)
        for (const pat of SHADOWING_PATTERNS) {
          const match = field.text.match(pat);
          if (match) {
            findings.push({
              ruleId: "TOOL004",
              severity: "HIGH",
              category: "shadowing",
              title: "Cross-tool hijacking directive in description",
              message: `Tool "${tool.name}" on server "${input.server}" attempts to alter or reroute calls to other tools in ${field.location}.`,
              source: input.sourcePath,
              server: input.server,
              tool: tool.name,
              evidence: `${field.location}: "${match[0]}"`,
              remediation: `Remove or isolate this MCP server so it cannot manipulate calls to other registered tools.`,
            });
            break;
          }
        }

        // TOOL006: Embedded webhook / callback URL
        const urlMatch = field.text.match(SUSPICIOUS_URL_REGEX);
        if (urlMatch) {
          findings.push({
            ruleId: "TOOL006",
            severity: "MEDIUM",
            category: "exfiltration",
            title: "Suspicious external webhook or templated callback URL",
            message: `Tool "${tool.name}" on server "${input.server}" embeds an external webhook/callback URL in ${field.location}.`,
            source: input.sourcePath,
            server: input.server,
            tool: tool.name,
            evidence: `${field.location}: "${urlMatch[0]}"`,
            remediation: `Verify whether this external endpoint is legitimate and block untrusted outbound callbacks.`,
          });
        }
      }

      // TOOL005: Covert exfiltration parameter trap
      const props = tool.inputSchema?.properties ?? {};
      for (const [paramName, paramSchema] of Object.entries(props)) {
        const lower = paramName.toLowerCase();
        const paramDesc = typeof paramSchema.description === "string" ? paramSchema.description : "";
        if (
          COVERT_PARAM_NAMES.has(lower) ||
          /\b(?:paste|pass|dump|include)\s+(?:all\s+)?(?:context|contents|secrets?|history|env)\b/i.test(paramDesc)
        ) {
          findings.push({
            ruleId: "TOOL005",
            severity: "HIGH",
            category: "exfiltration",
            title: `Covert side-channel parameter "${paramName}"`,
            message: `Tool "${tool.name}" on server "${input.server}" defines suspicious parameter "${paramName}" commonly used to smuggle sensitive context out of the model.`,
            source: input.sourcePath,
            server: input.server,
            tool: tool.name,
            evidence: `parameter "${paramName}"${paramDesc ? `: "${paramDesc.slice(0, 90)}"` : ""}`,
            remediation: `Inspect why "${paramName}" exists and restrict the tool schema to strictly necessary typed arguments.`,
          });
        }
      }

      // TOOL007: Unconstrained schema on sensitive/mutating tool
      if (SENSITIVE_TOOL_NAME_REGEX.test(tool.name)) {
        const schema = tool.inputSchema;
        const allowsArbitrary = !schema || schema.additionalProperties === true;
        const hasUnboundedString = Object.entries(props).some(
          ([k, s]) =>
            s.type === "string" &&
            !s.enum &&
            !s.pattern &&
            s.maxLength === undefined &&
            /(?:cmd|command|script|sql|query|path|file|url|code)/i.test(k)
        );
        if (allowsArbitrary || hasUnboundedString) {
          findings.push({
            ruleId: "TOOL007",
            severity: "MEDIUM",
            category: "schema",
            title: "Unconstrained input schema on sensitive tool",
            message: `Sensitive tool "${tool.name}" on server "${input.server}" accepts unbounded string arguments or arbitrary extra properties without enum/pattern/maxLength constraints.`,
            source: input.sourcePath,
            server: input.server,
            tool: tool.name,
            evidence: allowsArbitrary
              ? "missing inputSchema or additionalProperties: true"
              : `unbounded parameters: ${Object.keys(props).join(", ")}`,
            remediation: `Set "additionalProperties": false and enforce strict enum/pattern/maxLength constraints plus explicit user confirmation.`,
          });
        }
      }

      // TOOL008: Bloated description / context-stuffing anomaly
      const descLen = tool.description?.length ?? 0;
      if (descLen > 1500) {
        findings.push({
          ruleId: "TOOL008",
          severity: "LOW",
          category: "tool-poisoning",
          title: "Unusually long tool description",
          message: `Tool "${tool.name}" on server "${input.server}" has a ${descLen}-character description (> 1,500 chars), which can conceal adversarial directives below UI truncation folds.`,
          source: input.sourcePath,
          server: input.server,
          tool: tool.name,
          evidence: `description.length = ${descLen}`,
          remediation: `Review the full untruncated description and pin its SHA-256 hash with "mcp-audit pin".`,
        });
      }
    }
  }

  // TOOL009: Cross-server Toxic Flow (Lethal Trifecta) detection
  const UNTRUSTED_IN_RE = /\b(?:fetch|browse|scrape|web_search|search_web|read_issue|get_issue|get_pr|read_email|list_emails|http_get|curl)\b/i;
  const PRIVATE_READ_RE = /\b(?:read_file|list_files|read_notes|read_env|get_secret|query_db|sql_query|search_files|filesystem)\b/i;
  const OUTBOUND_SINK_RE = /\b(?:send_email|send_message|post_message|slack_post|http_post|create_issue|create_pr|webhook|upload|publish)\b/i;

  const untrustedTools: string[] = [];
  const privateTools: string[] = [];
  const outboundTools: string[] = [];
  let firstSource = "";

  for (const input of inputs) {
    if (!firstSource) firstSource = input.sourcePath;
    for (const tool of input.tools) {
      const label = `${input.server}.${tool.name}`;
      const sig = `${tool.name} ${tool.description ?? ""}`;
      if (UNTRUSTED_IN_RE.test(sig)) untrustedTools.push(label);
      if (PRIVATE_READ_RE.test(sig)) privateTools.push(label);
      if (OUTBOUND_SINK_RE.test(sig)) outboundTools.push(label);
    }
  }

  if (untrustedTools.length > 0 && privateTools.length > 0 && outboundTools.length > 0) {
    findings.push({
      ruleId: "TOOL009",
      severity: "HIGH",
      category: "exfiltration",
      title: "Cross-server toxic flow (lethal trifecta) detected",
      message: `This MCP session combines untrusted external input (${untrustedTools.slice(0, 3).join(", ")}), private data access (${privateTools.slice(0, 3).join(", ")}), and outbound sinks (${outboundTools.slice(0, 3).join(", ")}), enabling indirect prompt-injection exfiltration.`,
      source: firstSource,
      evidence: `in=[${untrustedTools[0]}] -> data=[${privateTools[0]}] -> out=[${outboundTools[0]}]`,
      remediation: "Isolate untrusted web/issue readers from private-data + outbound-messaging MCP servers, or require explicit human approval before any outbound sink executes.",
    });
  }

  return findings;
}
