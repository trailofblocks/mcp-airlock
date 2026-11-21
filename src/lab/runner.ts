import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import { type AuditEvent, readAudit } from "../audit.js";
import { parsePolicy } from "../policy.js";
import { Airlock, statePaths } from "../proxy.js";
import { GullibleAgent, type AgentCall } from "./agent.js";
import { createLabHome } from "./fixtures.js";
import { SCENARIOS, type Scenario } from "./scenarios.js";
import { createLabServer, type Effect, readEffects } from "./servers.js";

export interface Layers {
  pinning: boolean;
  hiddenText: boolean;
  taint: boolean;
}

export const ALL_LAYERS: Layers = { pinning: true, hiddenText: true, taint: true };
export const LAYER_NAMES: Array<keyof Layers> = ["pinning", "hiddenText", "taint"];

/** The policy the lab runs under. It is also a worked example of a real policy file. */
export function labPolicyJson(layers: Layers = ALL_LAYERS): Record<string, unknown> {
  return {
    default: "allow",
    pinning: { enabled: layers.pinning, onNew: "pin" },
    hiddenText: { enabled: layers.hiddenText, toolMetadata: "block", toolResults: "strip" },
    taint: {
      enabled: layers.taint,
      sources: [
        { server: "issues", tool: "*", label: "untrusted" },
        { server: "web", tool: "*", label: "untrusted" },
        { server: "weather", tool: "*", label: "untrusted" },
        { server: "workspace", tool: "read_file", label: "private", indicators: false },
      ],
      sinks: [
        { server: "workspace", tool: "run_shell", action: "ask", checks: { untrusted: ["command"] } },
        { server: "workspace", tool: "write_file", action: "ask", checks: { untrusted: ["path"] } },
        { server: "workspace", tool: "http_post", action: "deny", checks: { untrusted: ["url"], private: ["*"] } },
        { server: "workspace", tool: "git_push", action: "deny", checks: { untrusted: ["remote"] } },
      ],
      ignoreHosts: ["github.com"],
    },
  };
}

export type Mode = "inprocess" | "process";

export interface RunResult {
  scenario: string;
  airlock: boolean;
  harmful?: boolean;
  succeeded?: boolean;
  calls: AgentCall[];
  effects: Effect[];
  audit: AuditEvent[];
  /** What Airlock did, e.g. "blocked http_post", "held run_shell for approval", "hid search_notes". */
  interventions: string[];
  stderr: string;
}

const fromSource = import.meta.url.endsWith(".ts");
const ext = fromSource ? ".ts" : ".js";
const SERVER_MAIN = fileURLToPath(new URL(`./server-main${ext}`, import.meta.url));
const CLI = fileURLToPath(new URL(`../cli${ext}`, import.meta.url));
const NODE_ARGS = fromSource ? ["--import", import.meta.resolve("tsx")] : [];

export function interventions(audit: AuditEvent[]): string[] {
  const out: string[] = [];
  for (const e of audit) {
    if (e.type === "call_denied") out.push(e.details?.pendingApproval ? `held ${e.tool} for approval` : `blocked ${e.tool}`);
    if (e.type === "tool_hidden") out.push(`hid ${e.tool}`);
    if (e.type === "result_stripped") out.push(`stripped ${e.tool} result`);
    if (e.type === "result_blocked") out.push(`blocked ${e.tool} result`);
  }
  return [...new Set(out)];
}

export async function runScenario(
  scenario: Scenario,
  opts: { airlock: boolean; layers?: Layers; mode: Mode; workDir: string },
): Promise<RunResult> {
  const dir = fs.mkdtempSync(path.join(opts.workDir, `${scenario.id}-`));
  const home = path.join(dir, "home");
  const ledger = path.join(dir, "effects.jsonl");
  const stateDir = path.join(dir, "airlock");
  createLabHome(home);
  fs.writeFileSync(ledger, "");
  const policyJson = labPolicyJson(opts.layers ?? ALL_LAYERS);
  const policyFile = path.join(dir, "policy.json");
  fs.writeFileSync(policyFile, JSON.stringify(policyJson, null, 2));
  const policy = parsePolicy(policyJson);

  const clients: Record<string, Client> = {};
  const closers: Array<() => Promise<unknown>> = [];
  let stderr = "";
  try {
    for (const spec of scenario.servers) {
      const client = new Client({ name: "airlock-lab-agent", version: "0.1.0" });
      if (opts.mode === "inprocess") {
        const server = createLabServer(spec.kind, spec.variant, { home, ledger });
        const [clientSide, serverFacing] = InMemoryTransport.createLinkedPair();
        if (opts.airlock) {
          const [upstream, serverSide] = InMemoryTransport.createLinkedPair();
          await server.connect(serverSide);
          const airlock = new Airlock(serverFacing, upstream, { server: spec.name, policy, stateDir, session: "lab" });
          await airlock.start();
          closers.push(() => airlock.close());
        } else {
          await server.connect(serverFacing);
        }
        closers.push(() => server.close());
        await client.connect(clientSide);
      } else {
        const serverCmd = [...NODE_ARGS, SERVER_MAIN, spec.kind, ...(spec.variant ? [spec.variant] : [])];
        const args = opts.airlock
          ? [...NODE_ARGS, CLI, "run", "--name", spec.name, "--policy", policyFile, "--state-dir", stateDir, "--session", "lab", "--", process.execPath, ...serverCmd]
          : serverCmd;
        const transport = new StdioClientTransport({
          command: process.execPath,
          args,
          env: { ...getDefaultEnvironment(), LAB_HOME: home, LAB_LEDGER: ledger },
          stderr: "pipe",
        });
        transport.stderr?.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
        await client.connect(transport);
      }
      clients[spec.name] = client;
      closers.push(() => client.close());
    }

    const agent = new GullibleAgent(clients);
    await agent.run(scenario.steps);
    const effects = readEffects(ledger);
    const audit = readAudit(statePaths(stateDir).audit);
    const observation = { effects, calls: agent.calls };
    return {
      scenario: scenario.id,
      airlock: opts.airlock,
      ...(scenario.harmful ? { harmful: scenario.harmful(observation) } : {}),
      ...(scenario.succeeded ? { succeeded: scenario.succeeded(observation) } : {}),
      calls: agent.calls,
      effects,
      audit,
      interventions: interventions(audit),
      stderr,
    };
  } finally {
    for (const close of closers.reverse()) await close().catch(() => {});
  }
}

export interface AttackRow {
  id: string;
  title: string;
  vector: string;
  harmfulWithout: boolean;
  harmfulWith: boolean;
  interventions: string[];
  /** Whether each defense layer, enabled alone, stops the attack. */
  stoppedBy?: Record<keyof Layers, boolean>;
}

export interface BenignRow {
  id: string;
  title: string;
  vector: string;
  succeededWithout: boolean;
  succeededWith: boolean;
  interventions: string[];
}

export interface LabReport {
  mode: Mode;
  attacks: AttackRow[];
  benign: BenignRow[];
}

export async function runLab(opts: {
  mode: Mode;
  ablation?: boolean;
  only?: string[];
  workDir?: string;
  onResult?: (r: RunResult) => void;
}): Promise<LabReport> {
  const workDir = opts.workDir ?? fs.mkdtempSync(path.join(os.tmpdir(), "airlock-lab-"));
  const cleanup = opts.workDir === undefined;
  const report: LabReport = { mode: opts.mode, attacks: [], benign: [] };
  try {
    for (const s of SCENARIOS) {
      if (opts.only && !opts.only.includes(s.id)) continue;
      const without = await runScenario(s, { airlock: false, mode: opts.mode, workDir });
      opts.onResult?.(without);
      const withA = await runScenario(s, { airlock: true, mode: opts.mode, workDir });
      opts.onResult?.(withA);
      if (s.kind === "attack") {
        const row: AttackRow = {
          id: s.id,
          title: s.title,
          vector: s.vector,
          harmfulWithout: without.harmful === true,
          harmfulWith: withA.harmful === true,
          interventions: withA.interventions,
        };
        if (opts.ablation) {
          const stoppedBy = {} as Record<keyof Layers, boolean>;
          for (const layer of LAYER_NAMES) {
            const layers: Layers = { pinning: false, hiddenText: false, taint: false, [layer]: true };
            const r = await runScenario(s, { airlock: true, layers, mode: opts.mode, workDir });
            opts.onResult?.(r);
            stoppedBy[layer] = r.harmful !== true;
          }
          row.stoppedBy = stoppedBy;
        }
        report.attacks.push(row);
      } else {
        report.benign.push({
          id: s.id,
          title: s.title,
          vector: s.vector,
          succeededWithout: without.succeeded === true,
          succeededWith: withA.succeeded === true,
          interventions: withA.interventions,
        });
      }
    }
  } finally {
    if (cleanup) fs.rmSync(workDir, { recursive: true, force: true });
  }
  return report;
}

export function summarize(report: LabReport) {
  const attacks = report.attacks.length;
  const succeededWithout = report.attacks.filter((a) => a.harmfulWithout).length;
  const stopped = report.attacks.filter((a) => !a.harmfulWith).length;
  const benign = report.benign.length;
  const clean = report.benign.filter((b) => b.succeededWith && b.interventions.length === 0).length;
  const interrupted = report.benign.filter((b) => b.interventions.length > 0 || !b.succeededWith).length;
  return { attacks, succeededWithout, stopped, benign, clean, interrupted };
}

const LAYER_LABEL: Record<keyof Layers, string> = { pinning: "pinning", hiddenText: "hidden text", taint: "taint" };

export function formatReport(report: LabReport, markdown = false): string {
  const s = summarize(report);
  const lines: string[] = [];
  const row = (cells: string[]) => (markdown ? `| ${cells.join(" | ")} |` : cells.join("  "));
  const ablation = report.attacks.some((a) => a.stoppedBy);

  if (markdown) {
    lines.push(row(["Attack", "Without Airlock", "With Airlock", ...(ablation ? ["Stopped by (each layer alone)"] : [])]));
    lines.push(row(["---", "---", "---", ...(ablation ? ["---"] : [])]));
  } else {
    lines.push("ATTACKS");
  }
  for (const a of report.attacks) {
    const layers = a.stoppedBy
      ? LAYER_NAMES.filter((l) => a.stoppedBy![l]).map((l) => LAYER_LABEL[l]).join(", ") || "none alone"
      : "";
    if (markdown) {
      lines.push(
        row([
          `**${a.id}** ${a.title}`,
          a.harmfulWithout ? "attack succeeds" : "attack fails (lab bug)",
          a.harmfulWith ? "**attack succeeds**" : `stopped: ${a.interventions.join("; ")}`,
          ...(ablation ? [layers] : []),
        ]),
      );
    } else {
      const status = a.harmfulWith ? "NOT STOPPED" : "stopped";
      lines.push(`  ${a.id.padEnd(4)}${a.title.padEnd(38)}without: ${a.harmfulWithout ? "succeeds" : "FAILS"}   with: ${status}`);
      lines.push(`        ${a.interventions.join("; ") || "-"}${a.stoppedBy ? `   [alone: ${layers}]` : ""}`);
    }
  }
  lines.push("");
  if (markdown) {
    lines.push(row(["Benign workflow", "Without Airlock", "With Airlock"]));
    lines.push(row(["---", "---", "---"]));
  } else {
    lines.push("BENIGN WORKFLOWS");
  }
  for (const b of report.benign) {
    const withText = b.succeededWith && b.interventions.length === 0 ? "completes, no prompts" : `${b.succeededWith ? "completes" : "interrupted"}: ${b.interventions.join("; ") || "-"}`;
    if (markdown) {
      lines.push(row([`**${b.id}** ${b.title}`, b.succeededWithout ? "completes" : "fails (lab bug)", withText]));
    } else {
      lines.push(`  ${b.id.padEnd(4)}${b.title.padEnd(44)}without: ${b.succeededWithout ? "completes" : "FAILS"}   with: ${withText}`);
    }
  }
  lines.push("");
  lines.push(
    `Attacks stopped: ${s.stopped}/${s.attacks} (${s.succeededWithout}/${s.attacks} succeed without Airlock). ` +
      `Benign workflows completed with no prompt or block: ${s.clean}/${s.benign} (false-positive rate ${s.interrupted}/${s.benign}).`,
  );
  return lines.join("\n");
}
