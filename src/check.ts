import { scanHiddenJson, summarizeRuns } from "./hidden.js";
import { type Action, strictest } from "./policy.js";
import type { TaintHit, TaintStore } from "./taint.js";

/**
 * The taint check both front ends share: the MCP proxy runs it on sink tool calls, and
 * `airlock hook` runs it on Claude Code's built-in tool calls. Same store, same wording.
 */

export interface SinkCheck {
  action: "ask" | "deny";
  /** Label -> top-level argument names (globs) that must not carry content with that label. */
  checks: Record<string, string[]>;
}

export interface SinkVerdict {
  /** `allow` when nothing matched. */
  action: Action;
  hits: TaintHit[];
  /** One-line reasons, e.g. "arguments carry untrusted content". */
  reasons: string[];
}

function clock(ts: number): string {
  return new Date(ts).toISOString().slice(11, 19);
}

/** One line explaining where a tainted argument came from. */
export function describeHit(hit: TaintHit): string {
  const src = `${hit.source.server}/${hit.source.tool} (${hit.label}, ${clock(hit.source.ts)} UTC)`;
  const via = hit.via ? ` after ${hit.via} decoding` : "";
  switch (hit.kind) {
    case "text":
      return `"${hit.arg}" repeats text${via} returned by ${src}: ${JSON.stringify(hit.excerpt)}`;
    case "host":
      return `"${hit.arg}" names host ${hit.excerpt}${via}, which appeared in ${src}`;
    case "path":
      return `"${hit.arg}" names path ${hit.excerpt}${via}, which appeared in ${src}`;
  }
}

/** Check a call's arguments against every sink that applies to it. */
export function checkSinks(taint: TaintStore, sinks: SinkCheck[], args: unknown, ignoreHosts: string[]): SinkVerdict {
  let action: Action = "allow";
  const hits: TaintHit[] = [];
  const reasons: string[] = [];
  if (sinks.length === 0) return { action, hits, reasons };
  // The same text read twice from one tool is one finding: keep the most recent read.
  const latest = new Map<string, TaintHit>();
  for (const sink of sinks) {
    const found = taint.check(args, sink.checks, ignoreHosts);
    if (found.length === 0) continue;
    action = strictest(action, sink.action);
    for (const hit of found) {
      const key = [hit.arg, hit.label, hit.kind, hit.excerpt, hit.via ?? "", hit.source.server, hit.source.tool].join("\u0000");
      const seen = latest.get(key);
      if (!seen || hit.source.ts > seen.source.ts) latest.set(key, hit);
    }
  }
  hits.push(...latest.values());
  const hidden = scanHiddenJson(args);
  if (hidden.length > 0) {
    action = strictest(action, ...sinks.map((s) => s.action));
    reasons.push(`arguments contain hidden characters (${summarizeRuns(hidden.flatMap((h) => h.runs))})`);
  }
  if (hits.length > 0) {
    const labels = [...new Set(hits.map((h) => h.label))].join(", ");
    reasons.push(`arguments carry ${labels} content`);
  }
  return { action, hits, reasons };
}

/** The reasons on one line, then the taint path, one hit per line. */
export function explain(reasons: string[], hits: TaintHit[]): string {
  return [reasons.join("; "), ...hits.map((h) => `  - ${describeHit(h)}`)].filter(Boolean).join("\n");
}
