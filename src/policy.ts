import fs from "node:fs";
import { z } from "zod";
import { matchGlob } from "./util/glob.js";

export const Action = z.enum(["allow", "ask", "deny"]);
export type Action = z.infer<typeof Action>;

const RuleSchema = z.strictObject({
  server: z.string().min(1).default("*"),
  tool: z.string().min(1).default("*"),
  action: Action,
  note: z.string().optional(),
});

const SourceSchema = z.strictObject({
  server: z.string().min(1).default("*"),
  tool: z.string().min(1).default("*"),
  label: z.string().min(1).default("untrusted"),
  /** Also remember hosts and file paths the content names. Turn off for private data such as your own files. */
  indicators: z.boolean().default(true),
});

const SinkSchema = z.strictObject({
  server: z.string().min(1).default("*"),
  tool: z.string().min(1),
  action: z.enum(["ask", "deny"]).default("ask"),
  /** Label -> top-level argument names (globs) that must not carry content with that label. */
  checks: z.record(z.string().min(1), z.array(z.string().min(1)).min(1)).default({ untrusted: ["*"] }),
});

const HookSinkSchema = z.strictObject({
  /** Claude Code tool name (glob), as it appears in the hook input's `tool_name`. */
  tool: z.string().min(1),
  action: z.enum(["ask", "deny"]).default("ask"),
  /** Label -> top-level `tool_input` field names (globs) that must not carry content with that label. */
  checks: z.record(z.string().min(1), z.array(z.string().min(1)).min(1)).default({ untrusted: ["*"] }),
});

type HookSink = z.infer<typeof HookSinkSchema>;

/**
 * Claude Code's built-in tools that run, write, or send something, and the input fields that matter.
 * Field names follow the PreToolUse input documented at code.claude.com/docs/en/hooks.
 */
export const DEFAULT_HOOK_SINKS: readonly HookSink[] = [
  { tool: "Bash", action: "ask", checks: { untrusted: ["command"], private: ["command"] } },
  { tool: "PowerShell", action: "ask", checks: { untrusted: ["command"], private: ["command"] } },
  { tool: "Write", action: "ask", checks: { untrusted: ["file_path"] } },
  { tool: "Edit", action: "ask", checks: { untrusted: ["file_path"] } },
  { tool: "NotebookEdit", action: "ask", checks: { untrusted: ["notebook_path"] } },
  { tool: "WebFetch", action: "ask", checks: { untrusted: ["url"] } },
  { tool: "WebFetch", action: "deny", checks: { private: ["url"] } },
  { tool: "WebSearch", action: "deny", checks: { private: ["query"] } },
];

const defaultHookSinks = (): HookSink[] => DEFAULT_HOOK_SINKS.map((s) => ({ ...s, checks: structuredClone(s.checks) }));

export const PolicySchema = z.strictObject({
  $schema: z.string().optional(),
  /** Action for tool calls no rule matches. */
  default: Action.default("allow"),
  /** First matching rule wins. */
  rules: z.array(RuleSchema).default([]),
  pinning: z
    .strictObject({
      enabled: z.boolean().default(true),
      /** `pin`: trust a tool the first time it is seen (like SSH known_hosts). `block`: hide it until approved with `airlock inspect --approve`. */
      onNew: z.enum(["pin", "block"]).default("pin"),
    })
    .default({ enabled: true, onNew: "pin" }),
  hiddenText: z
    .strictObject({
      enabled: z.boolean().default(true),
      /** Tool names, descriptions, and schemas. `block` hides the tool, `strip` removes the characters, `warn` only logs. */
      toolMetadata: z.enum(["block", "strip", "warn"]).default("block"),
      /** Tool results. `strip` removes the characters and adds a note, `block` replaces the result with an error, `warn` only logs. */
      toolResults: z.enum(["strip", "block", "warn"]).default("strip"),
    })
    .default({ enabled: true, toolMetadata: "block", toolResults: "strip" }),
  taint: z
    .strictObject({
      enabled: z.boolean().default(true),
      sources: z.array(SourceSchema).default([]),
      sinks: z.array(SinkSchema).default([]),
      /** Hosts (and their subdomains) that never count as tainted, e.g. the code host your issues live on. */
      ignoreHosts: z.array(z.string().min(1)).default([]),
      /** Shortest run of shared characters that counts as carrying tainted content. */
      minMatch: z.number().int().min(12).max(200).default(20),
      ttlHours: z.number().positive().default(24),
      /** Only the first this-many characters of each result are fingerprinted. */
      maxTextChars: z.number().int().positive().default(65536),
    })
    .default({ enabled: true, sources: [], sinks: [], ignoreHosts: [], minMatch: 20, ttlHours: 24, maxTextChars: 65536 }),
  approvals: z
    .strictObject({
      /** Ask in the MCP client's own UI (MCP elicitation) when the client supports it. */
      elicitation: z.boolean().default(true),
      timeoutSeconds: z.number().int().positive().default(300),
      /** How long an approval from `airlock approve` stays valid. */
      ttlMinutes: z.number().positive().default(15),
    })
    .default({ elicitation: true, timeoutSeconds: 300, ttlMinutes: 15 }),
  /** `airlock hook`: taint checks for Claude Code's built-in tools, which never pass through MCP. */
  hook: z
    .strictObject({
      /** The name the hook's decisions are logged under in the audit log. */
      server: z.string().min(1).default("claude-code"),
      /** Which built-in tools to check, and which input fields. Setting this replaces the defaults. */
      sinks: z.array(HookSinkSchema).default(defaultHookSinks),
    })
    .default(() => ({ server: "claude-code", sinks: defaultHookSinks() })),
});

export type Policy = z.infer<typeof PolicySchema>;
export type Sink = Policy["taint"]["sinks"][number];
export type Source = Policy["taint"]["sources"][number];
export type { HookSink };

export class PolicyError extends Error {}

export function parsePolicy(raw: unknown, origin = "policy"): Policy {
  const parsed = PolicySchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  ${i.path.join(".") || "(root)"}: ${i.message}`).join("\n");
    throw new PolicyError(`${origin} is invalid:\n${issues}`);
  }
  return parsed.data;
}

export function loadPolicy(file: string): Policy {
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    throw new PolicyError(`cannot read policy ${file}: ${(err as Error).message}`);
  }
  return parsePolicy(raw, file);
}

export function defaultPolicy(): Policy {
  return parsePolicy({});
}

export interface RuleDecision {
  action: Action;
  /** Index into `policy.rules`, or undefined when the default applied. */
  rule?: number;
}

export function decideRule(policy: Policy, server: string, tool: string): RuleDecision {
  const index = policy.rules.findIndex((r) => matchGlob(r.server, server) && matchGlob(r.tool, tool));
  if (index === -1) return { action: policy.default };
  return { action: policy.rules[index]!.action, rule: index };
}

export function sourcesFor(policy: Policy, server: string, tool: string): Source[] {
  if (!policy.taint.enabled) return [];
  return policy.taint.sources.filter((s) => matchGlob(s.server, server) && matchGlob(s.tool, tool));
}

export function sinksFor(policy: Policy, server: string, tool: string): Sink[] {
  if (!policy.taint.enabled) return [];
  return policy.taint.sinks.filter((s) => matchGlob(s.server, server) && matchGlob(s.tool, tool));
}

/** Hook sinks for one Claude Code tool. */
export function hookSinksFor(policy: Policy, tool: string): HookSink[] {
  if (!policy.taint.enabled) return [];
  return policy.hook.sinks.filter((s) => matchGlob(s.tool, tool));
}

const SEVERITY: Record<Action, number> = { allow: 0, ask: 1, deny: 2 };

export function strictest(...actions: Action[]): Action {
  return actions.reduce((a, b) => (SEVERITY[b] > SEVERITY[a] ? b : a), "allow" as Action);
}
