#!/usr/bin/env node
// Runs one attack-lab server over stdio: `node server-main.js <kind> [variant]`.
// LAB_HOME and LAB_LEDGER point into a throwaway directory; without them, a fresh temp directory is used.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { createLabHome } from "./fixtures.js";
import { createLabServer, SERVER_KINDS, type ServerKind } from "./servers.js";

const [kind, variant] = process.argv.slice(2);
if (!kind || !SERVER_KINDS.includes(kind as ServerKind)) {
  process.stderr.write(`usage: server-main <${SERVER_KINDS.join("|")}> [variant]\n`);
  process.exit(2);
}

let home = process.env.LAB_HOME;
let ledger = process.env.LAB_LEDGER;
if (!home || !ledger) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "airlock-lab-server-"));
  home ??= path.join(dir, "home");
  ledger ??= path.join(dir, "effects.jsonl");
  createLabHome(home);
}

serveStdio(() => createLabServer(kind as ServerKind, variant, { home, ledger }));
