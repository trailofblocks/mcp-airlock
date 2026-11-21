import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { ApprovalStore } from "../src/approvals.js";
import { PinStore, toolHash } from "../src/pins.js";
import { decideRule, defaultPolicy, loadPolicy, parsePolicy, PolicyError, sinksFor, sourcesFor, strictest } from "../src/policy.js";
import { matchGlob } from "../src/util/glob.js";
import { deriveName } from "../src/util/name.js";

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "airlock-policy-"));

describe("policy", () => {
  it("has safe defaults", () => {
    const p = defaultPolicy();
    assert.equal(p.default, "allow");
    assert.equal(p.pinning.onNew, "pin");
    assert.equal(p.hiddenText.toolMetadata, "block");
    assert.equal(p.hiddenText.toolResults, "strip");
    assert.equal(p.taint.minMatch, 20);
  });

  it("uses the first matching rule", () => {
    const p = parsePolicy({
      default: "ask",
      rules: [
        { server: "github", tool: "get_*", action: "allow" },
        { server: "github", action: "deny" },
      ],
    });
    assert.deepEqual(decideRule(p, "github", "get_issue"), { action: "allow", rule: 0 });
    assert.deepEqual(decideRule(p, "github", "push_files"), { action: "deny", rule: 1 });
    assert.deepEqual(decideRule(p, "fetch", "fetch"), { action: "ask" });
  });

  it("matches sources and sinks by server and tool globs", () => {
    const p = parsePolicy({
      taint: {
        sources: [{ server: "issues" }],
        sinks: [{ tool: "*shell*", checks: { untrusted: ["command"] } }],
      },
    });
    assert.equal(sourcesFor(p, "issues", "get_issue")[0]!.label, "untrusted");
    assert.equal(sourcesFor(p, "notes", "get_issue").length, 0);
    assert.equal(sinksFor(p, "any", "run_shell")[0]!.action, "ask");
    assert.equal(sinksFor(parsePolicy({ ...p, taint: { ...p.taint, enabled: false } }), "any", "run_shell").length, 0);
  });

  it("rejects unknown keys and bad values with a readable message", () => {
    assert.throws(() => parsePolicy({ defualt: "deny" }), (err: Error) => err instanceof PolicyError && /defualt/.test(err.message));
    assert.throws(() => parsePolicy({ rules: [{ tool: "x", action: "maybe" }] }), /rules\.0\.action/);
    assert.throws(() => parsePolicy({ taint: { minMatch: 3 } }), /taint\.minMatch/);
  });

  it("ships an example policy that validates", () => {
    const p = loadPolicy(fileURLToPath(new URL("../examples/airlock.policy.json", import.meta.url)));
    assert.ok(p.taint.sinks.length > 0);
  });

  it("orders actions by severity", () => {
    assert.equal(strictest("allow", "ask"), "ask");
    assert.equal(strictest("deny", "ask", "allow"), "deny");
    assert.equal(strictest(), "allow");
  });

  it("matches globs literally apart from * and ?", () => {
    assert.ok(matchGlob("get_*", "get_issue"));
    assert.ok(matchGlob("v?", "v2"));
    assert.ok(!matchGlob("a.b", "axb"));
    assert.ok(!matchGlob("get_*", "Get_issue"));
  });

  it("derives a server name from its command", () => {
    assert.equal(deriveName(["npx", "-y", "@modelcontextprotocol/server-github"]), "server-github");
    assert.equal(deriveName(["npx", "-y", "@scope/thing@1.2.3"]), "thing");
    assert.equal(deriveName(["node", "C:\\mcp\\server.js"]), "server");
    assert.equal(deriveName(["uvx", "mcp-server-fetch"]), "mcp-server-fetch");
  });
});

describe("pins", () => {
  const tool = {
    name: "search",
    description: "Search notes",
    inputSchema: { type: "object", properties: { q: { type: "string" } } },
  };

  it("hashes what the model reads, independent of key order", () => {
    const reordered = { inputSchema: { properties: { q: { type: "string" } }, type: "object" }, description: "Search notes", name: "search" };
    assert.equal(toolHash(tool), toolHash(reordered));
    assert.notEqual(toolHash(tool), toolHash({ ...tool, description: "Search notes." }));
    assert.notEqual(toolHash(tool), toolHash({ ...tool, inputSchema: { type: "object", properties: { q: { type: "number" } } } }));
    assert.notEqual(toolHash(tool), toolHash({ ...tool, annotations: { destructiveHint: true } }));
    assert.equal(toolHash(tool), toolHash({ ...tool, _meta: { build: 7 }, icons: [] }));
  });

  it("stores one file per server and forgets on request", () => {
    const pins = new PinStore(tmp());
    pins.set("notes", tool, "first-use");
    assert.equal(pins.get("notes", "search")!.hash, toolHash(tool));
    assert.equal(pins.get("other", "search"), undefined);
    assert.equal(pins.get("notes", "constructor"), undefined);
    assert.deepEqual(pins.servers(), ["notes"]);
    assert.equal(pins.forget("notes"), 1);
    assert.equal(pins.get("notes", "search"), undefined);
    assert.throws(() => pins.set("../etc", tool, "user"), /invalid server name/);
  });
});

describe("approvals", () => {
  it("files one request per call, and an approval works once", () => {
    const store = new ApprovalStore(tmp());
    const input = { server: "w", tool: "run_shell", argsHash: "h1", argsPreview: "{}", reason: "tainted" };
    const a = store.request(input);
    assert.equal(store.request(input).id, a.id);
    assert.equal(store.consume("w", "run_shell", "h1"), undefined);
    store.decide(a.id, true, 5);
    assert.equal(store.consume("w", "run_shell", "other"), undefined);
    assert.equal(store.consume("w", "run_shell", "h1")!.id, a.id);
    assert.equal(store.consume("w", "run_shell", "h1"), undefined);
  });

  it("does not use expired or denied approvals", () => {
    const store = new ApprovalStore(tmp());
    const a = store.request({ server: "w", tool: "t", argsHash: "h", argsPreview: "{}", reason: "r" });
    store.decide(a.id, true, -1);
    assert.equal(store.consume("w", "t", "h"), undefined);
    const b = store.request({ server: "w", tool: "t2", argsHash: "h", argsPreview: "{}", reason: "r" });
    store.decide(b.id, false, 5);
    assert.equal(store.consume("w", "t2", "h"), undefined);
    assert.throws(() => store.decide(b.id, true, 5), /already denied/);
    assert.throws(() => store.get("../x"), /invalid approval id/);
  });
});
