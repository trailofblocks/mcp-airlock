import fs from "node:fs";
import path from "node:path";

export type AuditType =
  | "start"
  | "tool_pinned"
  | "tool_hidden"
  | "tool_stripped"
  | "call_allowed"
  | "call_denied"
  | "call_approved"
  /** Handed to the user's prompt in the client: an `input_required` form, or Claude Code's permission prompt. */
  | "call_asked"
  | "result_stripped"
  | "result_blocked"
  | "hidden_text_warning"
  | "taint_recorded"
  | "stop";

export interface AuditEvent {
  ts: string;
  session: string;
  server: string;
  type: AuditType;
  tool?: string;
  /** Why Airlock acted, in one line. */
  reason?: string;
  argsHash?: string;
  details?: Record<string, unknown>;
}

/**
 * Append-only JSONL log. Each event is one `appendFileSync` call (O_APPEND), so concurrent Airlock
 * processes don't interleave within a line. Nothing in Airlock rewrites or truncates it.
 */
export class AuditLog {
  constructor(
    readonly file: string,
    private readonly base: { session: string; server: string },
  ) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
  }

  write(event: Omit<AuditEvent, "ts" | "session" | "server">): AuditEvent {
    const full: AuditEvent = { ts: new Date().toISOString(), ...this.base, ...event };
    fs.appendFileSync(this.file, `${JSON.stringify(full)}\n`, "utf8");
    return full;
  }
}

export function readAudit(file: string): AuditEvent[] {
  if (!fs.existsSync(file)) return [];
  const out: AuditEvent[] = [];
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as AuditEvent);
    } catch {
      // skip a torn line
    }
  }
  return out;
}
