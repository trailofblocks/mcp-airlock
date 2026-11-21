import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isRecord, readJsonFile, writeFileAtomic } from "./util/json.js";

export interface ApprovalRequest {
  id: string;
  server: string;
  tool: string;
  argsHash: string;
  argsPreview: string;
  reason: string;
  createdAt: string;
  status: "pending" | "approved" | "denied";
  /** Set when approved: the approval may be used once, until this time. */
  expiresAt?: string;
}

const ID = /^[0-9a-f]{8}$/;

/**
 * Out-of-band approvals for clients that can't show an MCP elicitation prompt.
 * Airlock files a pending request and blocks the call; the user runs `airlock approve <id>` in a
 * terminal; the next identical call (same server, tool, and arguments) goes through once.
 */
export class ApprovalStore {
  constructor(private readonly dir: string) {}

  private file(id: string): string {
    if (!ID.test(id)) throw new Error(`invalid approval id: ${id}`);
    return path.join(this.dir, `${id}.json`);
  }

  private read(id: string): ApprovalRequest | undefined {
    const file = this.file(id);
    if (!fs.existsSync(file)) return undefined;
    const raw = readJsonFile(file);
    return isRecord(raw) ? (raw as unknown as ApprovalRequest) : undefined;
  }

  list(): ApprovalRequest[] {
    if (!fs.existsSync(this.dir)) return [];
    return fs
      .readdirSync(this.dir)
      .filter((f) => ID.test(f.replace(/\.json$/, "")))
      .map((f) => this.read(f.replace(/\.json$/, "")))
      .filter((r): r is ApprovalRequest => r !== undefined)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  get(id: string): ApprovalRequest | undefined {
    return this.read(id);
  }

  /** File a pending request, or return the existing one for the same call. */
  request(input: Omit<ApprovalRequest, "id" | "createdAt" | "status">): ApprovalRequest {
    const existing = this.list().find(
      (r) => r.status === "pending" && r.server === input.server && r.tool === input.tool && r.argsHash === input.argsHash,
    );
    if (existing) return existing;
    const req: ApprovalRequest = {
      ...input,
      id: crypto.randomBytes(4).toString("hex"),
      createdAt: new Date().toISOString(),
      status: "pending",
    };
    writeFileAtomic(this.file(req.id), `${JSON.stringify(req, null, 2)}\n`);
    return req;
  }

  decide(id: string, approve: boolean, ttlMinutes: number): ApprovalRequest {
    const req = this.read(id);
    if (!req) throw new Error(`no approval request ${id}`);
    if (req.status !== "pending") throw new Error(`request ${id} is already ${req.status}`);
    const updated: ApprovalRequest = approve
      ? { ...req, status: "approved", expiresAt: new Date(Date.now() + ttlMinutes * 60_000).toISOString() }
      : { ...req, status: "denied" };
    writeFileAtomic(this.file(id), `${JSON.stringify(updated, null, 2)}\n`);
    return updated;
  }

  /** Use up an approval for this exact call, if there is a live one. */
  consume(server: string, tool: string, argsHash: string): ApprovalRequest | undefined {
    const now = Date.now();
    const match = this.list().find(
      (r) =>
        r.status === "approved" &&
        r.server === server &&
        r.tool === tool &&
        r.argsHash === argsHash &&
        r.expiresAt !== undefined &&
        Date.parse(r.expiresAt) > now,
    );
    if (!match) return undefined;
    try {
      fs.unlinkSync(this.file(match.id));
    } catch {
      return undefined; // another process used it first
    }
    return match;
  }
}
