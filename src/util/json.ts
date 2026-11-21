import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** JSON with object keys sorted at every level, so equal values always serialize identically. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) out[key] = sortKeys(value[key]);
    }
    return out;
  }
  return value;
}

export function sha256(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

/** Every string inside a JSON value, with a dotted path to it. Object keys are visited too. */
export function stringLeaves(value: unknown, prefix = ""): Array<{ path: string; value: string }> {
  const out: Array<{ path: string; value: string }> = [];
  const walk = (v: unknown, p: string): void => {
    if (typeof v === "string") out.push({ path: p, value: v });
    else if (Array.isArray(v)) v.forEach((item, i) => walk(item, `${p}[${i}]`));
    else if (isRecord(v)) {
      for (const [key, child] of Object.entries(v)) {
        const childPath = p ? `${p}.${key}` : key;
        out.push({ path: `${childPath}<key>`, value: key });
        walk(child, childPath);
      }
    }
  };
  walk(value, prefix);
  return out;
}

/** Deep copy of a JSON value with every string (keys included) passed through `fn`. */
export function mapStrings(value: unknown, fn: (s: string) => string): unknown {
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((v) => mapStrings(v, fn));
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) out[fn(key)] = mapStrings(child, fn);
    return out;
  }
  return value;
}

/** Write a file so readers never see a half-written version. */
export function writeFileAtomic(file: string, content: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  fs.writeFileSync(tmp, content, "utf8");
  fs.renameSync(tmp, file);
}

export function readJsonFile(file: string): unknown {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function truncate(text: string, max: number): string {
  const chars = [...text];
  return chars.length <= max ? text : `${chars.slice(0, max - 1).join("")}…`;
}
