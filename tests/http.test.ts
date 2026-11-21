import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { readAudit } from "../src/audit.js";
import { createLabHome } from "../src/lab/fixtures.js";
import { createLabServer, type ServerKind } from "../src/lab/servers.js";
import { statePaths } from "../src/proxy.js";

const repo = fileURLToPath(new URL("..", import.meta.url));

/** Serve a lab server over Streamable HTTP with the SDK's own handler, on a random local port. */
async function serveHttp(kind: ServerKind, variant: string | undefined, env: { home: string; ledger: string }) {
  const handler = createMcpHandler(() => createLabServer(kind, variant, env));
  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(", ") : v);
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    const response = await handler.fetch(
      new Request(`http://127.0.0.1${req.url}`, { method: req.method, headers, ...(hasBody ? { body: Buffer.concat(chunks) } : {}) }),
    );
    res.writeHead(response.status, Object.fromEntries(response.headers));
    if (response.body) for await (const chunk of response.body) res.write(chunk);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: async () => {
      await handler.close();
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    },
  };
}

describe("streamable HTTP upstream", () => {
  it("airlock run --url filters a remote server's tools and checks its calls", { timeout: 60_000 }, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "airlock-http-"));
    const env = { home: path.join(dir, "home"), ledger: path.join(dir, "effects.jsonl") };
    createLabHome(env.home);
    const stateDir = path.join(dir, "state");
    const remote = await serveHttp("notes", "poisoned", env);

    const client = new Client({ name: "http-test", version: "1.0.0" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ["--import", import.meta.resolve("tsx"), path.join(repo, "src", "cli.ts"), "run", "--url", remote.url, "--name", "notes", "--state-dir", stateDir, "--quiet"],
      env: getDefaultEnvironment(),
      stderr: "pipe",
    });
    let stderr = "";
    transport.stderr?.on("data", (c: Buffer) => (stderr += c.toString()));
    try {
      await client.connect(transport);
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name), ["read_note"], stderr);
      const ok = await client.callTool({ name: "read_note", arguments: { id: "n2" } });
      assert.match(JSON.stringify(ok.content), /Release 2\.4 on Thursday/);
      const blocked = await client.callTool({ name: "search_notes", arguments: { query: "x" } });
      assert.equal(blocked.isError, true);
      assert.match(JSON.stringify(blocked.content), /hidden characters/);
    } finally {
      await client.close();
      await remote.close();
    }
    const types = readAudit(statePaths(stateDir).audit).map((e) => e.type);
    assert.ok(types.includes("tool_hidden") && types.includes("call_denied"));
  });
});
