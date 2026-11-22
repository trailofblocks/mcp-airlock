import crypto from "node:crypto";
import path from "node:path";
import type { JSONRPCMessage, Transport } from "@modelcontextprotocol/server";
import { ApprovalStore } from "./approvals.js";
import { AuditLog } from "./audit.js";
import { checkSinks, describeHit, explain } from "./check.js";
import { revealHidden, scanHiddenJson, stripHiddenJson, summarizeRuns } from "./hidden.js";
import { snapshotTool, toolHash, PinStore } from "./pins.js";
import { type Action, decideRule, type Policy, sinksFor, sourcesFor, strictest } from "./policy.js";
import { TaintStore } from "./taint.js";
import { canonicalJson, isRecord, sha256, stringLeaves, truncate } from "./util/json.js";

export interface AirlockOptions {
  /** Logical name of the wrapped server. Policy rules, pins, and taint sources refer to it. */
  server: string;
  policy: Policy;
  stateDir: string;
  /** Taint is shared between Airlock processes with the same session (default: one global session). */
  session: string;
  /** Human-readable notices (blocks, pins). The CLI sends them to stderr. */
  log?: (line: string) => void;
}

export function statePaths(stateDir: string) {
  return {
    pins: path.join(stateDir, "pins"),
    approvals: path.join(stateDir, "approvals"),
    audit: path.join(stateDir, "audit.jsonl"),
    taint: path.join(stateDir, "taint.jsonl"),
    policy: path.join(stateDir, "policy.json"),
  };
}

type Id = string | number;

interface Msg {
  jsonrpc: "2.0";
  id?: Id;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
}

interface CallInfo {
  tool: string;
  args: unknown;
  argsHash: string;
}

interface Forwarded {
  method: string;
  params: Record<string, unknown>;
  call?: CallInfo;
  /** The user approved this call (a held `ask`), so later input rounds the server starts stay approved. */
  approved?: boolean;
}

export interface ToolVerdict {
  visible: boolean;
  reason?: string;
}

/**
 * State Airlock keeps for a multi-round-trip `tools/call` (protocol revision 2026-07-28). The client
 * echoes the token back as `requestState`, so it never leaves this process: the token is random and
 * single-use, and everything it stands for stays here.
 */
interface RoundState {
  /** `approval`: Airlock asked the user. `continue`: an approved call the server asked more of. */
  kind: "approval" | "continue";
  tool: string;
  argsHash: string;
  expires: number;
  /** For `continue`: the server's own `requestState`, restored before the retry is forwarded. */
  serverState?: string;
}

/** What a retried call carried back of Airlock's own state. */
type Resume = { kind: "continue" } | { kind: "approval"; accepted: boolean };

const key = (id: Id) => `${typeof id}:${id}`;
const PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_META = "io.modelcontextprotocol/clientCapabilities";
/** Key of Airlock's approval form in an `input_required` result's `inputRequests`. */
export const APPROVAL_INPUT_KEY = "airlock_approval";
const STATE_PREFIX = "airlock.v1.";
const isRequest = (m: Msg) => typeof m.method === "string" && m.id !== undefined;
const isNotification = (m: Msg) => typeof m.method === "string" && m.id === undefined;
const isResponse = (m: Msg) => m.method === undefined && m.id !== undefined;

function supportsFormElicitation(capabilities: unknown): boolean {
  if (!isRecord(capabilities) || !isRecord(capabilities.elicitation)) return false;
  const e = capabilities.elicitation;
  return Object.keys(e).length === 0 || isRecord(e.form);
}

/** A request from a client speaking revision 2026-07-28 or later carries its version in `_meta`. */
function isModern(meta: unknown): boolean {
  return isRecord(meta) && meta[PROTOCOL_VERSION_META] !== undefined;
}

const APPROVAL_SCHEMA = {
  type: "object",
  properties: {
    approve: { type: "boolean", title: "Allow this call", description: "Airlock will forward it to the server once.", default: false },
  },
  required: ["approve"],
} as const;

function approvedAnswer(answer: unknown): boolean {
  return isRecord(answer) && answer.action === "accept" && isRecord(answer.content) && answer.content.approve === true;
}

/** Every piece of text a model reads from a tool result. */
export function resultTexts(result: unknown): string[] {
  if (!isRecord(result)) return [];
  const texts: string[] = [];
  if (Array.isArray(result.content)) {
    for (const block of result.content) {
      if (!isRecord(block)) continue;
      if (typeof block.text === "string") texts.push(block.text);
      if (isRecord(block.resource) && typeof block.resource.text === "string") texts.push(block.resource.text);
      if (block.type === "resource_link") {
        for (const k of ["uri", "name", "title", "description"]) if (typeof block[k] === "string") texts.push(block[k] as string);
      }
    }
  }
  if (result.structuredContent !== undefined) {
    for (const leaf of stringLeaves(result.structuredContent)) texts.push(leaf.value);
  }
  return texts;
}

function toolMetadataTexts(tool: Record<string, unknown>): string[] {
  return stringLeaves(snapshotTool(tool)).map((l) => l.value);
}

function changedFields(before: Record<string, unknown>, after: Record<string, unknown>): string[] {
  return ["title", "description", "inputSchema", "outputSchema", "annotations"].filter(
    (k) => canonicalJson(before[k] ?? null) !== canonicalJson(after[k] ?? null),
  );
}

export { describeHit };

/**
 * A message-level MCP proxy. It forwards every JSON-RPC message between the client and the server
 * unchanged, except:
 *
 * - `tools/list` results: tools that are denied, carry hidden characters, are new under a strict
 *   policy, or changed since they were pinned are removed before the client (and the model) sees them.
 * - `tools/call` requests: checked against policy rules, the tool's verdict, and taint. Blocked calls
 *   are answered by Airlock with an error result and never reach the server.
 * - `tools/call` results: hidden characters are stripped, and results from source tools are fingerprinted.
 *
 * Because it never terminates the protocol itself, the handshake (`initialize` or `server/discover`)
 * and every other feature pass straight through, whatever protocol revision the two sides speak.
 */
export class Airlock {
  readonly pins: PinStore;
  readonly taint: TaintStore;
  readonly audit: AuditLog;
  readonly approvals: ApprovalStore;

  private readonly forwarded = new Map<string, Forwarded>();
  private readonly ownToServer = new Map<string, (m: Msg) => void>();
  private readonly ownToClient = new Map<string, (m: Msg) => void>();
  private readonly taskCalls = new Map<string, CallInfo>();
  private readonly rounds = new Map<string, RoundState>();
  private readonly tools = new Map<string, ToolVerdict>();
  private readonly announced = new Set<string>();
  private listed = false;
  private stale = false;
  private refreshing?: Promise<void>;
  private clientElicitation = false;
  private seq = 0;
  private readonly idPrefix = `airlock-${crypto.randomBytes(3).toString("hex")}-`;
  private closed = false;
  private resolveClosed!: (reason: string) => void;
  /** Resolves when either side disconnects. */
  readonly done: Promise<string> = new Promise((resolve) => (this.resolveClosed = resolve));

  constructor(
    private readonly downstream: Transport,
    private readonly upstream: Transport,
    private readonly opts: AirlockOptions,
  ) {
    const paths = statePaths(opts.stateDir);
    const t = opts.policy.taint;
    this.pins = new PinStore(paths.pins);
    this.approvals = new ApprovalStore(paths.approvals);
    this.audit = new AuditLog(paths.audit, { session: opts.session, server: opts.server });
    this.taint = new TaintStore({
      file: paths.taint,
      session: opts.session,
      minMatch: t.minMatch,
      ttlMs: t.ttlHours * 3_600_000,
      maxTextChars: t.maxTextChars,
    });
  }

  async start(): Promise<void> {
    this.upstream.onmessage = (m) => this.guard(() => this.fromServer(m as Msg));
    this.downstream.onmessage = (m) => this.guard(() => this.fromClient(m as Msg));
    this.upstream.onclose = () => this.shutdown("server closed");
    this.downstream.onclose = () => this.shutdown("client closed");
    this.upstream.onerror = (err) => this.notice(`server transport error: ${err.message}`);
    this.downstream.onerror = (err) => this.notice(`client transport error: ${err.message}`);
    await this.upstream.start();
    await this.downstream.start();
    this.audit.write({ type: "start", details: { pid: process.pid } });
  }

  async close(): Promise<void> {
    this.shutdown("closed");
  }

  /** The current verdict for each tool in the server's latest listing. */
  verdicts(): ReadonlyMap<string, ToolVerdict> {
    return this.tools;
  }

  private guard(fn: () => void | Promise<void>): void {
    Promise.resolve()
      .then(fn)
      .catch((err: unknown) => this.notice(`internal error: ${(err as Error).stack ?? err}`));
  }

  private shutdown(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.audit.write({ type: "stop", reason });
    for (const resolve of this.ownToServer.values()) resolve({ jsonrpc: "2.0", error: { code: -32000, message: reason } });
    for (const resolve of this.ownToClient.values()) resolve({ jsonrpc: "2.0", error: { code: -32000, message: reason } });
    void this.upstream.close().catch(() => {});
    void this.downstream.close().catch(() => {});
    this.resolveClosed(reason);
  }

  private notice(line: string): void {
    this.opts.log?.(`[airlock:${this.opts.server}] ${line}`);
  }

  private send(to: Transport, msg: Msg): void {
    if (this.closed) return;
    to.send(msg as JSONRPCMessage).catch((err: Error) => this.notice(`send failed: ${err.message}`));
  }

  // -------------------------------------------------------------------------------------------
  // client -> server

  private async fromClient(msg: Msg): Promise<void> {
    if (isResponse(msg)) {
      const own = this.ownToClient.get(key(msg.id!));
      if (own) {
        this.ownToClient.delete(key(msg.id!));
        own(msg);
        return;
      }
      this.send(this.upstream, msg);
      return;
    }
    if (isRequest(msg)) {
      const params = msg.params ?? {};
      if (msg.method === "initialize") this.clientElicitation = supportsFormElicitation(params.capabilities);
      if (msg.method === "tools/call") {
        await this.handleCall(msg);
        return;
      }
      this.forwarded.set(key(msg.id!), { method: msg.method!, params });
    }
    this.send(this.upstream, msg);
  }

  private async handleCall(original: Msg): Promise<void> {
    const name = String(original.params?.name ?? "");
    const args = original.params?.arguments ?? {};
    const call: CallInfo = { tool: name, args, argsHash: sha256(canonicalJson({ name, args })) };
    // A retry of a call Airlock answered with `input_required` carries Airlock's own fields; take them
    // out here, so the server only ever sees its own.
    const { params, resume } = this.takeRoundState(original.params ?? {}, call);
    const msg: Msg = { ...original, params };
    const server = this.opts.server;
    const policy = this.opts.policy;

    const verdict = await this.verdictFor(name, params._meta);
    if (!verdict) return this.deny(msg, call, `tool "${name}" is not in the server's tool list`);
    if (!verdict.visible) return this.deny(msg, call, verdict.reason ?? "tool is blocked");

    const rule = decideRule(policy, server, name);
    const reasons: string[] = [];
    if (rule.action !== "allow") {
      reasons.push(rule.rule === undefined ? `policy default is "${rule.action}"` : `policy rule #${rule.rule + 1} says "${rule.action}"`);
    }
    const sinks = checkSinks(this.taint, sinksFor(policy, server, name), args, policy.taint.ignoreHosts);
    const hits = sinks.hits;
    reasons.push(...sinks.reasons);
    const action: Action = strictest(rule.action, sinks.action);

    const details = (): Record<string, unknown> => ({
      args: truncate(JSON.stringify(args), 400),
      ...(hits.length > 0 ? { taint: hits.map((h) => ({ ...h, explained: describeHit(h) })) } : {}),
    });
    const why = explain(reasons, hits);

    if (action === "deny") return this.deny(msg, call, why, details());

    if (action === "ask") {
      const approved = (reason: string) => {
        this.audit.write({ type: "call_approved", tool: name, argsHash: call.argsHash, reason, details: details() });
        this.forwardCall(msg, call, true);
      };
      if (resume?.kind === "continue") return approved("approved earlier; the server asked for more input");
      if (resume?.kind === "approval") {
        if (resume.accepted) return approved("approved in client (input_required)");
        return this.deny(msg, call, `${why}\nThe user declined this call.`, details());
      }
      const used = this.approvals.consume(server, name, call.argsHash);
      if (used) return approved(`approved out of band (${used.id})`);
      const prompt = `Airlock: allow ${server}/${name}?\n${why}\n\nArguments: ${truncate(JSON.stringify(args), 600)}`;
      if (policy.approvals.elicitation && this.clientElicitation) {
        if (await this.elicit(prompt)) return approved("approved in client");
        return this.deny(msg, call, `${why}\nThe user declined this call.`, details());
      }
      // Revision 2026-07-28 has no server-to-client requests: a server asks for input by answering
      // the call with `input_required`, and the client retries it with the answers.
      const meta = params._meta;
      if (policy.approvals.elicitation && isModern(meta) && isRecord(meta) && supportsFormElicitation(meta[CLIENT_CAPABILITIES_META])) {
        return this.askInputRequired(msg, call, prompt, why, details());
      }
      const req = this.approvals.request({
        server,
        tool: name,
        argsHash: call.argsHash,
        argsPreview: truncate(JSON.stringify(args), 600),
        reason: why,
      });
      return this.deny(msg, call, why, { ...details(), approvalId: req.id }, req.id);
    }

    this.audit.write({ type: "call_allowed", tool: name, argsHash: call.argsHash });
    this.forwardCall(msg, call);
  }

  private forwardCall(msg: Msg, call: CallInfo, approved = false): void {
    this.forwarded.set(key(msg.id!), { method: "tools/call", params: msg.params ?? {}, call, ...(approved ? { approved } : {}) });
    this.send(this.upstream, msg);
  }

  // -------------------------------------------------------------------------------------------
  // multi-round-trip approval (revision 2026-07-28)

  private mintRound(state: Omit<RoundState, "expires">): string {
    const now = Date.now();
    for (const [token, s] of this.rounds) if (s.expires <= now) this.rounds.delete(token);
    const token = `${STATE_PREFIX}${crypto.randomBytes(18).toString("base64url")}`;
    this.rounds.set(token, { ...state, expires: now + this.opts.policy.approvals.timeoutSeconds * 1000 });
    return token;
  }

  /**
   * Split Airlock's own multi-round-trip fields off a `tools/call`. A token is good once, for the
   * call it was minted for; anything else that looks like Airlock's is dropped and the call is
   * judged afresh.
   */
  private takeRoundState(params: Record<string, unknown>, call: CallInfo): { params: Record<string, unknown>; resume?: Resume } {
    const token = params.requestState;
    if (typeof token !== "string" || !token.startsWith(STATE_PREFIX)) return { params };
    const state = this.rounds.get(token);
    this.rounds.delete(token);
    const next: Record<string, unknown> = { ...params };
    delete next.requestState;
    const valid = state !== undefined && state.expires > Date.now() && state.tool === call.tool && state.argsHash === call.argsHash;

    if (valid && state.kind === "continue") {
      // The server's own round: its answers stay, and its state goes back where it was.
      if (state.serverState !== undefined) next.requestState = state.serverState;
      return { params: next, resume: { kind: "continue" } };
    }
    let answer: unknown;
    if (isRecord(next.inputResponses) && APPROVAL_INPUT_KEY in next.inputResponses) {
      const { [APPROVAL_INPUT_KEY]: own, ...rest } = next.inputResponses;
      answer = own;
      if (Object.keys(rest).length > 0) next.inputResponses = rest;
      else delete next.inputResponses;
    }
    if (!valid) {
      this.notice(`ignored ${state ? "a mismatched or expired" : "an unknown"} approval state on a call to ${call.tool}`);
      return { params: next };
    }
    return { params: next, resume: { kind: "approval", accepted: approvedAnswer(answer) } };
  }

  private askInputRequired(msg: Msg, call: CallInfo, prompt: string, why: string, details: Record<string, unknown>): void {
    const token = this.mintRound({ kind: "approval", tool: call.tool, argsHash: call.argsHash });
    this.audit.write({ type: "call_asked", tool: call.tool, argsHash: call.argsHash, reason: why.split("\n")[0], details });
    this.notice(`asked the user about ${call.tool}: ${why.replace(/\n/g, " ")}`);
    this.send(this.downstream, {
      jsonrpc: "2.0",
      id: msg.id!,
      result: {
        resultType: "input_required",
        inputRequests: {
          [APPROVAL_INPUT_KEY]: { method: "elicitation/create", params: { mode: "form", message: prompt, requestedSchema: APPROVAL_SCHEMA } },
        },
        requestState: token,
      },
    });
  }

  private deny(msg: Msg, call: CallInfo, why: string, details: Record<string, unknown> = {}, approvalId?: string): void {
    const server = this.opts.server;
    const text = approvalId
      ? `Airlock is holding this call to ${server}/${call.tool} for approval.\n${why}\n\nTo allow it once, run in a terminal:\n  airlock approve ${approvalId}\nthen make the same call again.`
      : `Airlock blocked this call to ${server}/${call.tool}.\n${why}`;
    this.audit.write({
      type: "call_denied",
      tool: call.tool,
      argsHash: call.argsHash,
      reason: why.split("\n")[0],
      details: { ...details, ...(approvalId ? { pendingApproval: approvalId } : {}) },
    });
    this.notice(`${approvalId ? "held" : "blocked"} ${call.tool}: ${why.replace(/\n/g, " ")}`);
    // Revision 2026-07-28 requires every result to say what kind it is; a request carrying the
    // per-request protocol-version claim comes from a client speaking that revision.
    const modern = isModern(msg.params?._meta);
    this.send(this.downstream, {
      jsonrpc: "2.0",
      id: msg.id!,
      result: { ...(modern ? { resultType: "complete" } : {}), content: [{ type: "text", text }], isError: true },
    });
  }

  private elicit(message: string): Promise<boolean> {
    const id = `${this.idPrefix}${++this.seq}`;
    const timeoutMs = this.opts.policy.approvals.timeoutSeconds * 1000;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.ownToClient.delete(key(id));
        resolve(false);
      }, timeoutMs);
      this.ownToClient.set(key(id), (resp) => {
        clearTimeout(timer);
        const r = resp.result;
        resolve(!!r && r.action === "accept" && isRecord(r.content) && r.content.approve === true);
      });
      this.send(this.downstream, {
        jsonrpc: "2.0",
        id,
        method: "elicitation/create",
        params: { message, requestedSchema: APPROVAL_SCHEMA },
      });
    });
  }

  // -------------------------------------------------------------------------------------------
  // tool listing

  private async verdictFor(name: string, meta: unknown): Promise<ToolVerdict | undefined> {
    if (!this.listed || this.stale || !this.tools.has(name)) {
      this.refreshing ??= this.refreshTools(meta).finally(() => (this.refreshing = undefined));
      await this.refreshing;
    }
    return this.tools.get(name);
  }

  /** List the server's tools ourselves, for calls made before (or without) a fresh client listing. */
  private async refreshTools(meta: unknown): Promise<void> {
    let cursor: unknown;
    let first = true;
    for (let page = 0; page < 100; page++) {
      const params: Record<string, unknown> = {};
      if (cursor !== undefined) params.cursor = cursor;
      if (isRecord(meta)) {
        const { progressToken: _p, ...rest } = meta;
        if (Object.keys(rest).length > 0) params._meta = rest;
      }
      const resp = await this.requestServer("tools/list", params);
      if (!resp.result) return;
      this.processToolList(resp.result, first);
      first = false;
      cursor = resp.result.nextCursor;
      if (cursor === undefined || cursor === null) return;
    }
  }

  private requestServer(method: string, params: Record<string, unknown>): Promise<Msg> {
    const id = `${this.idPrefix}${++this.seq}`;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.ownToServer.delete(key(id));
        resolve({ jsonrpc: "2.0", error: { code: -32001, message: "timeout" } });
      }, 30_000);
      this.ownToServer.set(key(id), (m) => {
        clearTimeout(timer);
        resolve(m);
      });
      this.send(this.upstream, { jsonrpc: "2.0", id, method, params });
    });
  }

  private once(key: string, fn: () => void): void {
    if (this.announced.has(key)) return;
    this.announced.add(key);
    fn();
  }

  /** Filter one page of a `tools/list` result in place. */
  private processToolList(result: Record<string, unknown>, firstPage: boolean): void {
    if (!Array.isArray(result.tools)) return;
    if (firstPage) this.tools.clear();
    const kept: unknown[] = [];
    for (const raw of result.tools) {
      if (!isRecord(raw) || typeof raw.name !== "string") continue;
      const { verdict, tool } = this.evaluateTool(raw);
      this.tools.set(raw.name, verdict);
      if (verdict.visible) kept.push(tool);
    }
    result.tools = kept;
    if (result.nextCursor === undefined || result.nextCursor === null) {
      this.listed = true;
      this.stale = false;
    }
  }

  private evaluateTool(raw: Record<string, unknown>): { verdict: ToolVerdict; tool: Record<string, unknown> } {
    const { policy, server } = this.opts;
    const name = raw.name as string;
    const hash = toolHash(raw);
    let tool = raw;

    const rule = decideRule(policy, server, name);
    if (rule.action === "deny") {
      const reason = rule.rule === undefined ? "denied by the policy default" : `denied by policy rule #${rule.rule + 1}`;
      this.once(`deny|${name}`, () => this.audit.write({ type: "tool_hidden", tool: name, reason }));
      return { verdict: { visible: false, reason }, tool };
    }

    if (policy.hiddenText.enabled) {
      const findings = scanHiddenJson(snapshotTool(raw));
      if (findings.length > 0) {
        const summary = summarizeRuns(findings.flatMap((f) => f.runs));
        const details = { fields: findings.map((f) => ({ path: f.path, revealed: truncate(f.revealed, 2000) })) };
        const mode = policy.hiddenText.toolMetadata;
        if (mode === "block") {
          const reason = `tool metadata contains hidden characters (${summary}); see \`airlock inspect\``;
          this.once(`hidden|${hash}`, () => {
            this.audit.write({ type: "tool_hidden", tool: name, reason, details });
            this.notice(`hid tool ${name}: ${reason}`);
          });
          return { verdict: { visible: false, reason }, tool };
        }
        if (mode === "strip") {
          tool = stripHiddenJson(raw).value;
          this.once(`strip|${hash}`, () => this.audit.write({ type: "tool_stripped", tool: name, reason: summary, details }));
        } else {
          this.once(`warn|${hash}`, () => this.audit.write({ type: "hidden_text_warning", tool: name, reason: summary, details }));
        }
      }
    }

    if (policy.pinning.enabled) {
      const pin = this.pins.get(server, name);
      if (!pin) {
        if (policy.pinning.onNew === "block") {
          const reason = "new tool, not approved yet; review it with `airlock inspect --approve`";
          this.once(`new|${hash}`, () => this.audit.write({ type: "tool_hidden", tool: name, reason }));
          return { verdict: { visible: false, reason }, tool };
        }
        this.pins.set(server, raw, "first-use");
        this.audit.write({ type: "tool_pinned", tool: name, details: { hash } });
      } else if (pin.hash !== hash) {
        const fields = changedFields(pin.tool as unknown as Record<string, unknown>, snapshotTool(raw) as unknown as Record<string, unknown>);
        const reason = `tool definition changed since it was approved on ${pin.approvedAt.slice(0, 10)} (${fields.join(", ") || "name"}); review it with \`airlock inspect --approve\``;
        this.once(`changed|${hash}`, () => {
          this.audit.write({
            type: "tool_hidden",
            tool: name,
            reason,
            details: {
              approvedHash: pin.hash,
              currentHash: hash,
              changed: fields,
              ...(fields.includes("description")
                ? {
                    approvedDescription: truncate(revealHidden(String(pin.tool.description ?? "")), 2000),
                    currentDescription: truncate(revealHidden(String(raw.description ?? "")), 2000),
                  }
                : {}),
            },
          });
          this.notice(`hid tool ${name}: ${reason}`);
        });
        return { verdict: { visible: false, reason }, tool };
      }
    }

    // A source server's tool descriptions are as untrusted as its results.
    for (const source of sourcesFor(policy, server, name)) {
      this.once(`meta|${source.label}|${hash}`, () => {
        this.taint.record({ server, tool: name, label: source.label, indicators: source.indicators }, toolMetadataTexts(tool));
      });
    }
    return { verdict: { visible: true }, tool };
  }

  // -------------------------------------------------------------------------------------------
  // server -> client

  private fromServer(msg: Msg): void {
    if (isResponse(msg)) {
      const own = this.ownToServer.get(key(msg.id!));
      if (own) {
        this.ownToServer.delete(key(msg.id!));
        own(msg);
        return;
      }
      const req = this.forwarded.get(key(msg.id!));
      this.forwarded.delete(key(msg.id!));
      if (req && msg.result) {
        // HTTP transports send the negotiated version as a header on later requests.
        if (req.method === "initialize" && typeof msg.result.protocolVersion === "string") {
          this.upstream.setProtocolVersion?.(msg.result.protocolVersion);
        }
        if (req.method === "tools/list") this.processToolList(msg.result, req.params.cursor === undefined);
        if (req.method === "tools/call" && req.call) {
          const task = msg.result.task;
          if (msg.result.resultType === "input_required") {
            // Not the call's result yet: the server wants input first, and the client will retry.
            // If the user already approved this call, carry that approval into the retry, so they
            // aren't asked again, by keeping the server's state here and handing out a token for it.
            if (req.approved) {
              const serverState = msg.result.requestState;
              msg.result.requestState = this.mintRound({
                kind: "continue",
                tool: req.call.tool,
                argsHash: req.call.argsHash,
                ...(typeof serverState === "string" ? { serverState } : {}),
              });
            }
          } else if (isRecord(task) && typeof task.taskId === "string" && !Array.isArray(msg.result.content)) {
            this.taskCalls.set(task.taskId, req.call);
          } else {
            this.processResult(req.call, msg);
          }
        }
        if (req.method === "tasks/result" && typeof req.params.taskId === "string") {
          const call = this.taskCalls.get(req.params.taskId);
          if (call) this.processResult(call, msg);
        }
      } else if (req?.call && msg.error) {
        this.processResult(req.call, msg);
      }
      this.send(this.downstream, msg);
      return;
    }
    if (isNotification(msg) && msg.method === "notifications/tools/list_changed") this.stale = true;
    this.send(this.downstream, msg);
  }

  private processResult(call: CallInfo, msg: Msg): void {
    const { policy, server } = this.opts;
    const texts = msg.result ? resultTexts(msg.result) : [msg.error?.message ?? "", JSON.stringify(msg.error?.data ?? "")];

    // Fingerprint what the model would read, before any stripping, so hidden instructions count too.
    for (const source of sourcesFor(policy, server, call.tool)) {
      const rec = this.taint.record({ server, tool: call.tool, label: source.label, indicators: source.indicators }, texts);
      if (rec) {
        this.audit.write({
          type: "taint_recorded",
          tool: call.tool,
          details: { label: source.label, record: rec.id, windows: rec.grams.length, hosts: rec.hosts, paths: rec.paths },
        });
      }
    }

    if (!policy.hiddenText.enabled || !msg.result) return;
    const findings = scanHiddenJson({ content: msg.result.content, structuredContent: msg.result.structuredContent });
    if (findings.length === 0) return;
    const runs = findings.flatMap((f) => f.runs);
    const summary = summarizeRuns(runs);
    const details = { fields: findings.map((f) => ({ path: f.path, revealed: truncate(f.revealed, 2000) })) };
    const mode = policy.hiddenText.toolResults;
    if (mode === "strip") {
      const stripped = stripHiddenJson({ content: msg.result.content, structuredContent: msg.result.structuredContent }).value;
      const content = Array.isArray(stripped.content) ? [...stripped.content] : [];
      content.push({ type: "text", text: `[airlock] Removed hidden characters from this result (${summary}).` });
      msg.result = { ...msg.result, content, ...(stripped.structuredContent !== undefined ? { structuredContent: stripped.structuredContent } : {}) };
      this.audit.write({ type: "result_stripped", tool: call.tool, argsHash: call.argsHash, reason: summary, details });
      this.notice(`stripped hidden characters from ${call.tool} result (${summary})`);
    } else if (mode === "block") {
      msg.result = {
        ...(msg.result.resultType !== undefined ? { resultType: msg.result.resultType } : {}),
        content: [{ type: "text", text: `Airlock blocked this result from ${server}/${call.tool}: it contains hidden characters (${summary}).` }],
        isError: true,
      };
      this.audit.write({ type: "result_blocked", tool: call.tool, argsHash: call.argsHash, reason: summary, details });
      this.notice(`blocked ${call.tool} result: hidden characters (${summary})`);
    } else {
      this.audit.write({ type: "hidden_text_warning", tool: call.tool, argsHash: call.argsHash, reason: summary, details });
    }
  }
}
