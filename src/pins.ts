import fs from "node:fs";
import path from "node:path";
import { canonicalJson, isRecord, readJsonFile, sha256, writeFileAtomic } from "./util/json.js";

/** The parts of a tool definition a model reads or relies on. Any change to these needs re-approval. */
export interface ToolSnapshot {
  name: string;
  title?: unknown;
  description?: unknown;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: unknown;
}

export interface Pin {
  hash: string;
  approvedAt: string;
  /** `first-use` when pinned automatically the first time it was seen, `user` when approved explicitly. */
  approvedBy: "first-use" | "user";
  tool: ToolSnapshot;
}

interface PinFile {
  server: string;
  tools: Record<string, Pin>;
}

export function snapshotTool(tool: Record<string, unknown>): ToolSnapshot {
  const snap: ToolSnapshot = { name: String(tool.name) };
  for (const key of ["title", "description", "inputSchema", "outputSchema", "annotations"] as const) {
    if (tool[key] !== undefined) snap[key] = tool[key];
  }
  return snap;
}

export function toolHash(tool: Record<string, unknown>): string {
  return sha256(canonicalJson(snapshotTool(tool)));
}

export const SERVER_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/** One JSON file per server, so Airlock processes wrapping different servers never write the same file. */
export class PinStore {
  constructor(private readonly dir: string) {}

  private file(server: string): string {
    if (!SERVER_NAME.test(server)) throw new Error(`invalid server name: ${server}`);
    return path.join(this.dir, `${server}.json`);
  }

  private load(server: string): PinFile {
    const file = this.file(server);
    if (!fs.existsSync(file)) return { server, tools: {} };
    const raw = readJsonFile(file);
    if (!isRecord(raw) || !isRecord(raw.tools)) throw new Error(`corrupt pin file: ${file}`);
    return { server, tools: raw.tools as Record<string, Pin> };
  }

  private save(data: PinFile): void {
    writeFileAtomic(this.file(data.server), `${JSON.stringify(data, null, 2)}\n`);
  }

  get(server: string, tool: string): Pin | undefined {
    const tools = this.load(server).tools;
    return Object.hasOwn(tools, tool) ? tools[tool] : undefined;
  }

  set(server: string, tool: Record<string, unknown>, approvedBy: Pin["approvedBy"]): Pin {
    const data = this.load(server);
    const pin: Pin = { hash: toolHash(tool), approvedAt: new Date().toISOString(), approvedBy, tool: snapshotTool(tool) };
    data.tools[String(tool.name)] = pin;
    this.save(data);
    return pin;
  }

  forget(server: string, tool?: string): number {
    const data = this.load(server);
    const names = tool ? [tool].filter((t) => Object.hasOwn(data.tools, t)) : Object.keys(data.tools);
    for (const name of names) delete data.tools[name];
    this.save(data);
    return names.length;
  }

  servers(): string[] {
    if (!fs.existsSync(this.dir)) return [];
    return fs
      .readdirSync(this.dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.slice(0, -5))
      .filter((s) => SERVER_NAME.test(s))
      .sort();
  }

  all(server: string): Record<string, Pin> {
    return this.load(server).tools;
  }
}
