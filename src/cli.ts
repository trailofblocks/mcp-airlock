#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline/promises";
import { Client, StreamableHTTPClientTransport, type Transport } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { Command, InvalidArgumentError, Option } from "commander";
import { diffWords } from "diff";
import { ApprovalStore } from "./approvals.js";
import { type AuditEvent, readAudit } from "./audit.js";
import { revealHidden, scanHidden, scanHiddenJson, summarizeRuns } from "./hidden.js";
import { formatReport, runLab, summarize } from "./lab/runner.js";
import { PinStore, SERVER_NAME, snapshotTool, toolHash } from "./pins.js";
import { defaultPolicy, loadPolicy, type Policy, PolicyError } from "./policy.js";
import { Airlock, statePaths } from "./proxy.js";
import { deriveName } from "./util/name.js";

const VERSION: string = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: number) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = paint(1);
const dim = paint(2);
const red = paint(31);
const green = paint(32);
const yellow = paint(33);

function defaultStateDir(): string {
  return process.env.AIRLOCK_HOME || path.join(os.homedir(), ".airlock");
}

function serverName(value: string): string {
  if (!SERVER_NAME.test(value)) throw new InvalidArgumentError("use letters, digits, '.', '_' or '-' (max 64)");
  return value;
}

function resolvePolicy(file: string | undefined, stateDir: string): Policy {
  if (file) return loadPolicy(path.resolve(file));
  const fallback = statePaths(stateDir).policy;
  return fs.existsSync(fallback) ? loadPolicy(fallback) : defaultPolicy();
}

interface UpstreamOpts {
  url?: string;
  header: string[];
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function fail(message: string): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(2);
}

/** The wrapped server: a command to spawn over stdio, or a Streamable HTTP URL. */
function upstreamFor(cmd: string[], opts: UpstreamOpts, usage: string): { transport: Transport; derivedName: string } {
  if (opts.url && cmd.length > 0) fail(`give either --url or a server command, not both. Usage: ${usage}`);
  if (opts.url) {
    let url: URL;
    try {
      url = new URL(opts.url);
    } catch {
      fail(`invalid --url: ${opts.url}`);
    }
    const headers: Record<string, string> = {};
    for (const h of opts.header) {
      const i = h.indexOf(":");
      if (i <= 0) fail(`invalid --header (expected "Name: value"): ${h}`);
      headers[h.slice(0, i).trim()] = h.slice(i + 1).trim();
    }
    return {
      transport: new StreamableHTTPClientTransport(url, { requestInit: { headers } }),
      derivedName: deriveName([url.hostname]),
    };
  }
  if (cmd.length === 0) fail(`no server command. Usage: ${usage}`);
  return {
    transport: new StdioClientTransport({ command: cmd[0]!, args: cmd.slice(1), env: childEnv(), stderr: "inherit" }),
    derivedName: deriveName(cmd),
  };
}

function childEnv(): Record<string, string> {
  // The wrapped server gets exactly the environment the MCP client gave Airlock.
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) env[k] = v;
  return env;
}

const program = new Command()
  .name("airlock")
  .description("A runtime firewall for MCP servers.")
  .version(VERSION)
  .enablePositionalOptions();

// -------------------------------------------------------------------------------------------- run

program
  .command("run", { isDefault: true })
  .description("Wrap an MCP server: airlock run --name github -- npx -y @modelcontextprotocol/server-github")
  .argument("[command...]", "the server command, after --")
  .option("--url <url>", "wrap a Streamable HTTP server instead of a command")
  .option("-H, --header <header>", 'HTTP header for --url, e.g. "Authorization: Bearer ..." (repeatable)', collect, [])
  .option("-n, --name <name>", "server name used by policy rules and pins (default: derived from the command)", serverName)
  .option("-p, --policy <file>", "policy file (default: $AIRLOCK_HOME/policy.json, else built-in defaults)")
  .option("--state-dir <dir>", "pins, approvals, taint, and audit log", defaultStateDir())
  .option("--session <id>", "taint is shared between Airlock processes in the same session", process.env.AIRLOCK_SESSION || "default")
  .option("-q, --quiet", "don't print notices to stderr")
  .passThroughOptions()
  .action(async (cmd: string[], opts: UpstreamOpts & { name?: string; policy?: string; stateDir: string; session: string; quiet?: boolean }) => {
    const usage = "airlock run [--name n] -- <command> [args...]  or  airlock run --url <url>";
    const { transport: upstream, derivedName } = upstreamFor(cmd, opts, usage);
    const name = opts.name ?? derivedName;
    const policy = resolvePolicy(opts.policy, opts.stateDir);
    const downstream = new StdioServerTransport();
    const airlock = new Airlock(downstream, upstream, {
      server: name,
      policy,
      stateDir: path.resolve(opts.stateDir),
      session: opts.session,
      log: opts.quiet ? undefined : (line) => process.stderr.write(`${line}\n`),
    });
    await airlock.start();
    const reason = await airlock.done;
    if (!opts.quiet && reason === "server closed") process.stderr.write(`[airlock:${name}] server exited\n`);
    process.exit(0);
  });

// -------------------------------------------------------------------------------------------- inspect

interface InspectOpts extends UpstreamOpts {
  name?: string;
  policy?: string;
  stateDir: string;
  approve?: boolean;
  json?: boolean;
}

program
  .command("inspect")
  .description("Connect to a server, show its tools as a model would read them, and compare them with your pins")
  .argument("[command...]", "the server command, after --")
  .option("--url <url>", "inspect a Streamable HTTP server instead of a command")
  .option("-H, --header <header>", "HTTP header for --url (repeatable)", collect, [])
  .option("-n, --name <name>", "server name (must match the name you use with `airlock run`)", serverName)
  .option("--state-dir <dir>", "where pins are stored", defaultStateDir())
  .option("--approve", "pin every tool's current definition (after you've read this output)")
  .option("--json", "machine-readable output")
  .passThroughOptions()
  .action(async (cmd: string[], opts: InspectOpts) => {
    const { transport, derivedName } = upstreamFor(cmd, opts, "airlock inspect [--name n] [--approve] -- <command> [args...]");
    const name = opts.name ?? derivedName;
    const pins = new PinStore(statePaths(path.resolve(opts.stateDir)).pins);
    const client = new Client({ name: "airlock-inspect", version: VERSION });
    await client.connect(transport);
    const { tools } = await client.listTools();
    await client.close();

    const report = tools.map((tool) => {
      const raw = tool as unknown as Record<string, unknown>;
      const pin = pins.get(name, tool.name);
      const hash = toolHash(raw);
      const hidden = scanHiddenJson(snapshotTool(raw));
      const status = !pin ? "new" : pin.hash === hash ? "pinned" : "changed";
      return { tool, raw, pin, hash, hidden, status };
    });

    if (opts.json) {
      process.stdout.write(
        `${JSON.stringify(
          report.map((r) => ({
            name: r.tool.name,
            status: r.status,
            hash: r.hash,
            hiddenText: r.hidden.map((h) => ({ path: h.path, revealed: h.revealed, summary: summarizeRuns(h.runs) })),
          })),
          null,
          2,
        )}\n`,
      );
    } else {
      process.stdout.write(`${bold(name)}: ${tools.length} tool${tools.length === 1 ? "" : "s"}\n`);
      for (const r of report) {
        const tag = r.status === "pinned" ? green("pinned") : r.status === "new" ? yellow("new") : red("CHANGED since approval");
        process.stdout.write(`\n${bold(r.tool.name)}  ${tag}${r.hidden.length ? `  ${red(`hidden text: ${summarizeRuns(r.hidden.flatMap((h) => h.runs))}`)}` : ""}\n`);
        const description = String(r.tool.description ?? "");
        if (r.status === "changed" && r.pin) {
          process.stdout.write(dim(`  approved ${r.pin.approvedAt} (${r.pin.approvedBy}); differences in what the model reads:\n`));
          process.stdout.write("  ");
          for (const part of diffWords(revealHidden(String(r.pin.tool.description ?? "")), revealHidden(description))) {
            process.stdout.write(part.added ? green(`[+${part.value}]`) : part.removed ? red(`[-${part.value}]`) : part.value);
          }
          process.stdout.write("\n");
        } else {
          process.stdout.write(`  ${revealHidden(description).replace(/\n/g, "\n  ")}\n`);
        }
        for (const h of r.hidden.filter((h) => h.path !== "description")) {
          process.stdout.write(`  ${red(h.path)}: ${h.revealed}\n`);
        }
      }
    }

    if (opts.approve) {
      for (const r of report) if (r.status !== "pinned") pins.set(name, r.raw, "user");
      const changed = report.filter((r) => r.status !== "pinned").length;
      process.stderr.write(`\nPinned ${changed} tool${changed === 1 ? "" : "s"} for ${name}.\n`);
    } else if (report.some((r) => r.status !== "pinned")) {
      process.stderr.write(dim(`\nRun again with --approve to pin these definitions.\n`));
    }
  });

// -------------------------------------------------------------------------------------------- pins

const pinsCmd = program.command("pins").description("List or forget pinned tool definitions");
pinsCmd
  .command("list", { isDefault: true })
  .option("--state-dir <dir>", "", defaultStateDir())
  .action((opts: { stateDir: string }) => {
    const pins = new PinStore(statePaths(path.resolve(opts.stateDir)).pins);
    const servers = pins.servers();
    if (servers.length === 0) process.stdout.write("No pins yet.\n");
    for (const server of servers) {
      process.stdout.write(`${bold(server)}\n`);
      for (const [tool, pin] of Object.entries(pins.all(server))) {
        process.stdout.write(`  ${tool.padEnd(32)} ${pin.hash.slice(0, 12)}  ${pin.approvedAt}  ${dim(pin.approvedBy)}\n`);
      }
    }
  });
pinsCmd
  .command("forget")
  .argument("<server>")
  .argument("[tool]")
  .option("--state-dir <dir>", "", defaultStateDir())
  .action((server: string, tool: string | undefined, opts: { stateDir: string }) => {
    const n = new PinStore(statePaths(path.resolve(opts.stateDir)).pins).forget(server, tool);
    process.stdout.write(`Forgot ${n} pin${n === 1 ? "" : "s"}.\n`);
  });

// -------------------------------------------------------------------------------------------- approvals

program
  .command("approvals")
  .description("List calls waiting for approval")
  .option("--state-dir <dir>", "", defaultStateDir())
  .action((opts: { stateDir: string }) => {
    const pending = new ApprovalStore(statePaths(path.resolve(opts.stateDir)).approvals).list().filter((r) => r.status === "pending");
    if (pending.length === 0) process.stdout.write("Nothing waiting.\n");
    for (const r of pending) {
      process.stdout.write(`${bold(r.id)}  ${r.server}/${r.tool}  ${dim(r.createdAt)}\n  ${r.reason.replace(/\n/g, "\n  ")}\n  args: ${r.argsPreview}\n\n`);
    }
  });

for (const verb of ["approve", "deny"] as const) {
  program
    .command(verb)
    .description(verb === "approve" ? "Allow one held call to go through once (needs an interactive terminal)" : "Reject a held call")
    .argument("<id>")
    .option("--state-dir <dir>", "", defaultStateDir())
    .action(async (id: string, opts: { stateDir: string }) => {
      const stateDir = path.resolve(opts.stateDir);
      const store = new ApprovalStore(statePaths(stateDir).approvals);
      const req = store.get(id);
      if (!req) {
        process.stderr.write(`No request ${id}.\n`);
        process.exit(1);
      }
      process.stdout.write(`${bold(`${req.server}/${req.tool}`)}\n${req.reason}\nargs: ${req.argsPreview}\n\n`);
      if (verb === "approve") {
        // An agent with a shell tool could otherwise approve its own blocked call.
        if (!process.stdin.isTTY || !process.stdout.isTTY) {
          process.stderr.write("Refusing to approve without an interactive terminal.\n");
          process.exit(1);
        }
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        const answer = await rl.question(`Type ${bold(id)} to allow this call once: `);
        rl.close();
        if (answer.trim() !== id) {
          process.stdout.write("Not approved.\n");
          process.exit(1);
        }
      }
      const ttl = resolvePolicy(undefined, stateDir).approvals.ttlMinutes;
      store.decide(id, verb === "approve", ttl);
      process.stdout.write(verb === "approve" ? green(`Approved. The next identical call within ${ttl} minutes goes through.\n`) : "Denied.\n");
    });
}

// -------------------------------------------------------------------------------------------- log

function formatEvent(e: AuditEvent): string {
  const color = e.type === "call_denied" || e.type === "tool_hidden" || e.type === "result_blocked" ? red : e.type.includes("stripped") ? yellow : dim;
  const head = `${dim(e.ts.replace("T", " ").slice(0, 19))} ${e.server.padEnd(12)} ${color(e.type.padEnd(16))} ${e.tool ?? ""}`;
  const lines = [head];
  if (e.reason) lines.push(`    ${e.reason}`);
  const taint = e.details?.taint;
  if (Array.isArray(taint)) for (const t of taint) lines.push(`    - ${(t as { explained: string }).explained}`);
  if (typeof e.details?.pendingApproval === "string") lines.push(`    approve with: airlock approve ${e.details.pendingApproval}`);
  return lines.join("\n");
}

program
  .command("log")
  .description("Show the audit log")
  .option("--state-dir <dir>", "", defaultStateDir())
  .option("-n, --limit <n>", "most recent events", (v) => Number.parseInt(v, 10), 30)
  .option("--server <name>")
  .option("--all", "include routine events (allowed calls, taint records)")
  .option("--json", "raw JSONL")
  .action((opts: { stateDir: string; limit: number; server?: string; all?: boolean; json?: boolean }) => {
    const routine = new Set(["start", "stop", "call_allowed", "taint_recorded", "tool_pinned"]);
    const events = readAudit(statePaths(path.resolve(opts.stateDir)).audit)
      .filter((e) => !opts.server || e.server === opts.server)
      .filter((e) => opts.all || opts.json || !routine.has(e.type))
      .slice(-opts.limit);
    for (const e of events) process.stdout.write(`${opts.json ? JSON.stringify(e) : formatEvent(e)}\n`);
  });

// -------------------------------------------------------------------------------------------- reveal

program
  .command("reveal")
  .description("Show hidden characters in a file (or stdin). Exit code 1 if any are found.")
  .argument("[file]")
  .action((file: string | undefined) => {
    const text = fs.readFileSync(file ?? 0, "utf8");
    const runs = scanHidden(text);
    process.stdout.write(revealHidden(text));
    if (!text.endsWith("\n")) process.stdout.write("\n");
    if (runs.length > 0) {
      process.stderr.write(red(`\n${runs.length} hidden run${runs.length === 1 ? "" : "s"}: ${summarizeRuns(runs)}\n`));
      process.exit(1);
    }
  });

// -------------------------------------------------------------------------------------------- policy

program
  .command("policy")
  .description("Validate a policy file and print it with defaults filled in")
  .argument("[file]")
  .option("--state-dir <dir>", "", defaultStateDir())
  .action((file: string | undefined, opts: { stateDir: string }) => {
    process.stdout.write(`${JSON.stringify(resolvePolicy(file, path.resolve(opts.stateDir)), null, 2)}\n`);
  });

// -------------------------------------------------------------------------------------------- lab

program
  .command("lab")
  .description("Run the attack lab: every attack and benign workflow, without and with Airlock")
  .addOption(new Option("--mode <mode>", "in-process transports, or real stdio processes through `airlock run`").choices(["inprocess", "process"]).default("inprocess"))
  .option("--ablation", "also run each attack with one defense layer at a time")
  .option("--only <ids>", "comma-separated scenario ids, e.g. A1,B4")
  .option("--markdown", "print tables as Markdown")
  .option("--json", "print the full report as JSON")
  .action(async (opts: { mode: "inprocess" | "process"; ablation?: boolean; only?: string; markdown?: boolean; json?: boolean }) => {
    const report = await runLab({
      mode: opts.mode,
      ablation: opts.ablation,
      ...(opts.only ? { only: opts.only.split(",").map((s) => s.trim()) } : {}),
      onResult: (r) => {
        if (!opts.json) process.stderr.write(dim(`  ${r.scenario} ${r.airlock ? "with" : "without"} airlock\n`));
      },
    });
    process.stdout.write(opts.json ? `${JSON.stringify(report, null, 2)}\n` : `${formatReport(report, opts.markdown)}\n`);
    const s = summarize(report);
    // Exit non-zero if the lab itself is broken or an attack gets through.
    process.exit(s.stopped === s.attacks && s.succeededWithout === s.attacks ? 0 : 1);
  });

program.parseAsync().catch((err: unknown) => {
  if (err instanceof PolicyError) process.stderr.write(`${err.message}\n`);
  else process.stderr.write(`${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
