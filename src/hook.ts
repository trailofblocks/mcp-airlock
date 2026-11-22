import { AuditLog } from "./audit.js";
import { checkSinks, describeHit, explain } from "./check.js";
import { hookSinksFor, type Policy } from "./policy.js";
import { statePaths } from "./proxy.js";
import { TaintStore } from "./taint.js";
import { isRecord, truncate } from "./util/json.js";

/**
 * `airlock hook`: a Claude Code `PreToolUse` hook.
 *
 * Claude Code's built-in tools (Bash, Write, Edit, WebFetch, ...) never pass through MCP, so Airlock's
 * proxies can't see them. Claude Code runs this hook before each such call, with the call on stdin.
 * It checks the tool input against the taint store the proxies write, and answers `deny` or `ask`
 * with the taint path, or says nothing and leaves the call to Claude Code's own permission rules.
 *
 * Input and output follow https://code.claude.com/docs/en/hooks (PreToolUse).
 */

export class HookInputError extends Error {}

export interface PreToolUseDecision {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "ask" | "deny";
    permissionDecisionReason: string;
  };
}

export interface HookOptions {
  policy: Policy;
  stateDir: string;
  /** Must match the `--session` of the Airlock proxies whose taint this hook should see. */
  session: string;
}

/** Decide on one hook event. Returns undefined when Airlock has no objection (and so no opinion). */
export function runHook(input: unknown, opts: HookOptions): PreToolUseDecision | undefined {
  if (!isRecord(input)) throw new HookInputError("hook input is not a JSON object");
  if (input.hook_event_name !== "PreToolUse") return undefined;
  const tool = input.tool_name;
  if (typeof tool !== "string" || tool.length === 0) throw new HookInputError("PreToolUse input has no tool_name");
  const toolInput = input.tool_input ?? {};

  const { policy } = opts;
  const sinks = hookSinksFor(policy, tool);
  if (sinks.length === 0) return undefined;

  const paths = statePaths(opts.stateDir);
  const t = policy.taint;
  const taint = new TaintStore({
    file: paths.taint,
    session: opts.session,
    minMatch: t.minMatch,
    ttlMs: t.ttlHours * 3_600_000,
    maxTextChars: t.maxTextChars,
  });
  const audit = new AuditLog(paths.audit, { session: opts.session, server: policy.hook.server });
  const verdict = checkSinks(taint, sinks, toolInput, t.ignoreHosts);

  const details: Record<string, unknown> = {
    args: truncate(JSON.stringify(toolInput), 400),
    ...(typeof input.tool_use_id === "string" ? { toolUseId: input.tool_use_id } : {}),
    ...(verdict.hits.length > 0 ? { taint: verdict.hits.map((h) => ({ ...h, explained: describeHit(h) })) } : {}),
  };
  if (verdict.action === "allow") {
    audit.write({ type: "call_allowed", tool, details: { args: details.args } });
    return undefined;
  }

  const why = explain(verdict.reasons, verdict.hits);
  const decision = verdict.action === "deny" ? "deny" : "ask";
  // For `deny`, Claude reads the reason; for `ask`, the user does, in the permission prompt.
  const reason = decision === "deny" ? `Airlock blocked this call to ${tool}.\n${why}` : `Airlock flagged this call to ${tool}.\n${why}`;
  audit.write({ type: decision === "deny" ? "call_denied" : "call_asked", tool, reason: why.split("\n")[0], details });
  return {
    hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: reason },
  };
}
