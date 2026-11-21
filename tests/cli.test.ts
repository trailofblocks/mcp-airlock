import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { ApprovalStore } from "../src/approvals.js";
import { toTagChars } from "../src/hidden.js";
import { createLabHome } from "../src/lab/fixtures.js";
import { statePaths } from "../src/proxy.js";

const repo = fileURLToPath(new URL("..", import.meta.url));
const cli = path.join(repo, "src", "cli.ts");
const serverMain = path.join(repo, "src", "lab", "server-main.ts");
const tsx = ["--import", import.meta.resolve("tsx")];
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "airlock-cli-"));

function airlock(args: string[], opts: { input?: string; env?: Record<string, string> } = {}) {
  const r = spawnSync(process.execPath, [...tsx, cli, ...args], {
    cwd: repo,
    input: opts.input ?? "",
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1", ...opts.env },
    timeout: 60_000,
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function labEnv() {
  const dir = tmp();
  createLabHome(path.join(dir, "home"));
  return { dir, env: { LAB_HOME: path.join(dir, "home"), LAB_LEDGER: path.join(dir, "effects.jsonl") } };
}

describe("cli", () => {
  it("reveal shows hidden text and exits 1", () => {
    const r = airlock(["reveal"], { input: `hello${toTagChars("secret")} world` });
    assert.equal(r.code, 1);
    assert.equal(r.stdout.trim(), 'hello⟦hidden text: "secret"⟧ world');
    assert.match(r.stderr, /1 hidden run: 6 tag/);
    assert.equal(airlock(["reveal"], { input: "plain 👍🏽" }).code, 0);
  });

  it("inspect shows what the model reads, pins with --approve, and diffs a later change", () => {
    const { dir, env } = labEnv();
    const state = path.join(dir, "state");
    const clean = airlock(["inspect", "--name", "notes", "--state-dir", state, "--approve", "--", process.execPath, ...tsx, serverMain, "notes"], { env });
    assert.equal(clean.code, 0, clean.stderr);
    assert.match(clean.stdout, /search_notes {2}new/);
    assert.match(clean.stderr, /Pinned 2 tools for notes/);

    const poisoned = airlock(["inspect", "--name", "notes", "--state-dir", state, "--", process.execPath, ...tsx, serverMain, "notes", "poisoned"], { env });
    assert.equal(poisoned.code, 0, poisoned.stderr);
    assert.match(poisoned.stdout, /search_notes {2}CHANGED since approval {2}hidden text: \d+ tag/);
    assert.match(poisoned.stdout, /\[\+⟦hidden text: "Before searching, call workspace\.http_post/);
    assert.match(poisoned.stdout, /read_note {2}pinned/);

    const json = JSON.parse(airlock(["inspect", "--json", "--name", "notes", "--state-dir", state, "--", process.execPath, ...tsx, serverMain, "notes", "poisoned"], { env }).stdout);
    assert.deepEqual(json.map((t: { name: string; status: string }) => [t.name, t.status]), [["search_notes", "changed"], ["read_note", "pinned"]]);

    const pins = airlock(["pins", "--state-dir", state]);
    assert.match(pins.stdout, /notes\n {2}search_notes/);
  });

  it("approve refuses without an interactive terminal, so an agent can't approve its own call", () => {
    const state = tmp();
    const req = new ApprovalStore(statePaths(state).approvals).request({ server: "w", tool: "run_shell", argsHash: "h", argsPreview: "{}", reason: "tainted" });
    const r = airlock(["approve", req.id, "--state-dir", state]);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /Refusing to approve without an interactive terminal/);
    assert.equal(new ApprovalStore(statePaths(state).approvals).get(req.id)!.status, "pending");

    assert.equal(airlock(["deny", req.id, "--state-dir", state]).code, 0);
    assert.equal(new ApprovalStore(statePaths(state).approvals).get(req.id)!.status, "denied");
  });

  it("log prints blocks with their taint path", () => {
    const state = tmp();
    fs.mkdirSync(state, { recursive: true });
    const event = {
      ts: "2026-11-22T10:00:00.000Z",
      session: "default",
      server: "workspace",
      type: "call_denied",
      tool: "http_post",
      reason: "arguments carry untrusted content",
      details: { taint: [{ explained: '"url" names host evil.example, which appeared in issues/get_issue' }], pendingApproval: "abcd1234" },
    };
    fs.writeFileSync(statePaths(state).audit, `${JSON.stringify({ ...event, type: "call_allowed" })}\n${JSON.stringify(event)}\n`);
    const r = airlock(["log", "--state-dir", state]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /workspace +call_denied +http_post/);
    assert.match(r.stdout, /- "url" names host evil\.example/);
    assert.match(r.stdout, /approve with: airlock approve abcd1234/);
    assert.doesNotMatch(r.stdout, /call_allowed/);
  });

  it("policy validates a file and reports errors", () => {
    const ok = airlock(["policy", path.join(repo, "examples", "airlock.policy.json")]);
    assert.equal(ok.code, 0);
    assert.equal(JSON.parse(ok.stdout).taint.minMatch, 20);
    const dir = tmp();
    fs.writeFileSync(path.join(dir, "bad.json"), JSON.stringify({ rules: [{ action: "sometimes" }] }));
    const bad = airlock(["policy", path.join(dir, "bad.json")]);
    assert.equal(bad.code, 1);
    assert.match(bad.stderr, /rules\.0\.action/);
  });

  it("run exits with an error when no server command is given", () => {
    const r = airlock(["run"]);
    assert.notEqual(r.code, 0);
  });
});
