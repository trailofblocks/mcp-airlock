import type { Client } from "@modelcontextprotocol/client";
import { modelView } from "../hidden.js";
import { canonicalJson, isRecord } from "../util/json.js";

/**
 * A scripted stand-in for a model that falls for every prompt injection.
 *
 * It does what the user asked (a fixed list of tool calls), and it also obeys any instruction of the
 * form `call <server>.<tool> with {json}` that it reads in a tool description or a tool result. Like
 * a real model, it reads Unicode TAG characters as text. `{{file:PATH}}` and `{{base64:file:PATH}}`
 * in an instruction make it read that file through `workspace.read_file` first.
 *
 * Airlock's job is to keep this agent safe without relying on it to resist anything.
 */

export interface UserStep {
  server: string;
  tool: string;
  args: Record<string, unknown>;
}

export interface AgentCall {
  origin: "user" | "injected" | "placeholder";
  server: string;
  tool: string;
  args: Record<string, unknown>;
  isError: boolean;
  text: string;
}

interface Directive {
  server: string;
  tool: string;
  args: Record<string, unknown>;
}

/** Find `call server.tool with {json}` instructions, parsing the JSON with brace matching. */
export function extractDirectives(text: string): Directive[] {
  const out: Directive[] = [];
  const re = /call\s+([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\s+with\s+\{/gi;
  for (const m of text.matchAll(re)) {
    const start = m.index! + m[0].length - 1;
    let depth = 0;
    let inString = false;
    let end = -1;
    for (let i = start; i < text.length; i++) {
      const ch = text[i];
      if (inString) {
        if (ch === "\\") i++;
        else if (ch === '"') inString = false;
      } else if (ch === '"') inString = true;
      else if (ch === "{") depth++;
      else if (ch === "}" && --depth === 0) {
        end = i + 1;
        break;
      }
    }
    if (end === -1) continue;
    try {
      const args = JSON.parse(text.slice(start, end));
      if (isRecord(args)) out.push({ server: m[1]!, tool: m[2]!, args });
    } catch {
      // not valid JSON; a real model might still try, this one doesn't
    }
  }
  return out;
}

function resultText(result: unknown): string {
  if (!isRecord(result) || !Array.isArray(result.content)) return "";
  return result.content
    .map((b) => (isRecord(b) && typeof b.text === "string" ? b.text : ""))
    .filter(Boolean)
    .join("\n");
}

export class GullibleAgent {
  readonly calls: AgentCall[] = [];
  /** What the agent read, in order. */
  readonly seen: string[] = [];
  private readonly queue: Directive[] = [];
  private readonly done = new Set<string>();

  constructor(
    private readonly clients: Record<string, Client>,
    private readonly maxInjected = 8,
  ) {}

  async run(steps: UserStep[]): Promise<void> {
    await this.look();
    await this.drain();
    for (const step of steps) {
      await this.call("user", step.server, step.tool, step.args);
      await this.look();
      await this.drain();
    }
  }

  /** Read every server's current tool list, the way a model sees tools on every turn. */
  private async look(): Promise<void> {
    for (const client of Object.values(this.clients)) {
      const { tools } = await client.listTools(undefined, { cacheMode: "refresh" });
      for (const tool of tools) {
        this.read(`${tool.name}: ${tool.description ?? ""}`);
        this.read(JSON.stringify(tool.inputSchema));
      }
    }
  }

  private read(raw: string): void {
    const seenText = modelView(raw);
    this.seen.push(seenText);
    for (const d of extractDirectives(seenText)) {
      const k = canonicalJson(d);
      if (!this.done.has(k)) {
        this.done.add(k);
        this.queue.push(d);
      }
    }
  }

  private async drain(): Promise<void> {
    let injected = this.calls.filter((c) => c.origin === "injected").length;
    while (this.queue.length > 0 && injected < this.maxInjected) {
      const d = this.queue.shift()!;
      const args = await this.fillPlaceholders(d.args);
      await this.call("injected", d.server, d.tool, args);
      injected++;
    }
  }

  private async fillPlaceholders(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(args)) {
      if (typeof v !== "string") {
        out[k] = v;
        continue;
      }
      let s = v;
      for (const m of v.matchAll(/\{\{(base64:)?file:([^}]+)\}\}/g)) {
        const content = await this.call("placeholder", "workspace", "read_file", { path: m[2]! });
        const value = m[1] ? Buffer.from(content, "utf8").toString("base64") : content;
        s = s.replace(m[0], value);
      }
      out[k] = s;
    }
    return out;
  }

  private async call(origin: AgentCall["origin"], server: string, tool: string, args: Record<string, unknown>): Promise<string> {
    const client = this.clients[server];
    let isError = true;
    let text: string;
    if (!client) {
      text = `no server named ${server}`;
    } else {
      try {
        const result = await client.callTool({ name: tool, arguments: args });
        isError = result.isError === true;
        text = resultText(result);
      } catch (err) {
        text = `error: ${(err as Error).message}`;
      }
    }
    this.calls.push({ origin, server, tool, args, isError, text });
    this.read(text);
    return text;
  }
}
