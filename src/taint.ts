import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { modelView } from "./hidden.js";
import { matchGlob } from "./util/glob.js";
import { isRecord, stringLeaves, truncate } from "./util/json.js";

/**
 * Taint tracking by fingerprint.
 *
 * When a tool marked as a source returns content, Airlock stores a hash of every `minMatch`-character
 * window of it (after normalizing case, whitespace, Unicode forms, and hidden characters), plus the
 * hosts and file paths it mentions. Raw content is never written to disk.
 *
 * When a sink tool is called, each checked argument is normalized the same way, along with its
 * URL-decoded, base64-decoded, and hex-decoded forms. The argument is tainted if any window matches,
 * meaning it shares at least `minMatch` consecutive characters with untrusted content, or if it names
 * a host or sensitive path that the untrusted content named.
 *
 * Records are appended to one JSONL file in the state directory, so separate Airlock processes (one per
 * MCP server) see each other's sources: content read through one server can block a call on another.
 */

export interface TaintRecord {
  v: 1;
  id: string;
  ts: number;
  session: string;
  server: string;
  tool: string;
  label: string;
  /** 48-bit hashes (base64url) of every normalized window of the content. */
  grams: string[];
  hosts: string[];
  paths: string[];
}

export interface TaintSource {
  server: string;
  tool: string;
  label: string;
  /** Also remember hosts and paths the content mentions. */
  indicators: boolean;
}

export type HitKind = "text" | "host" | "path";

export interface TaintHit {
  /** Argument path, e.g. `command` or `headers.authorization`. */
  arg: string;
  label: string;
  kind: HitKind;
  /** The matching part of the argument (normalized), or the host or path it names. */
  excerpt: string;
  /** Set when the match was found only after decoding the argument. */
  via?: "url-encoding" | "base64" | "hex";
  source: { id: string; server: string; tool: string; ts: number };
}

export interface TaintOptions {
  file: string;
  session: string;
  minMatch: number;
  ttlMs: number;
  maxTextChars: number;
  now?: () => number;
}

const HIDDEN_OR_FORMAT = /[\p{Cf}ᅟᅠㅤﾠ︀-️\u{e0100}-\u{e01ef}]/gu;

/** Text as compared for taint: what a model would read, NFKC-folded, lowercased, whitespace collapsed. */
export function normalizeForMatch(text: string): string {
  return modelView(text).normalize("NFKC").replace(HIDDEN_OR_FORMAT, "").toLowerCase().replace(/\s+/g, " ").trim();
}

function prepForIndicators(text: string): string {
  return modelView(text).normalize("NFKC").replace(HIDDEN_OR_FORMAT, "").toLowerCase();
}

function hashGram(gram: string): string {
  return crypto.createHash("sha1").update(gram, "utf8").digest().subarray(0, 6).toString("base64url");
}

const ALNUM = /[\p{L}\p{N}]/u;

/** Windows that are mostly punctuation or whitespace match too easily to mean anything. */
function trivialGram(chars: string[], start: number, k: number): boolean {
  let alnum = 0;
  const distinct = new Set<string>();
  for (let i = start; i < start + k; i++) {
    const ch = chars[i]!;
    if (ALNUM.test(ch)) alnum++;
    distinct.add(ch);
  }
  return alnum < 6 || distinct.size < 5;
}

export function fingerprint(text: string, k: number, maxChars: number): string[] {
  const chars = Array.from(normalizeForMatch(text)).slice(0, maxChars);
  const out = new Set<string>();
  for (let i = 0; i + k <= chars.length; i++) {
    if (trivialGram(chars, i, k)) continue;
    out.add(hashGram(chars.slice(i, i + k).join("")));
  }
  return [...out];
}

// ---------------------------------------------------------------------------------------------
// Indicators: hosts and file paths

const TLDS =
  "com|net|org|io|dev|app|ai|co|xyz|info|biz|site|online|me|cloud|example|test|top|ru|cn|tk|pw|cc|link|click|zip|mov|uk|de|fr|jp|in|us|ca|au|nl|eu|ch|se|no|pl|br|kr|tv|gg|ly|so|to|is|it|es|ws|su|ir";
const URL_RE = /\b(?:https?|ftp|wss?|ssh|git|sftp):\/\/[^\s"'<>`\\^{}|]+/g;
const EMAIL_RE = /\b[a-z0-9._%+-]+@((?:[a-z0-9-]+\.)+[a-z0-9-]{2,})\b/g;
const DOMAIN_RE = new RegExp(`(?<![\\w.@/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${TLDS}))(?![\\w-])`, "g");
const IPV4_RE = /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])/g;

const PATH_END = String.raw`[^\s"'\x60<>|;,)\]]`;
const HOME_PATH_RE = new RegExp(String.raw`(?:~|\$home|\$\{home\}|%userprofile%)[\\/]${PATH_END}+`, "g");
const UNIX_PATH_RE = new RegExp(
  String.raw`(?<![\w.~$%-])\/(?:etc|root|home|users|var|tmp|usr|opt|private|proc|dev|bin|sbin|srv|mnt|lib|boot|sys)\/${PATH_END}*`,
  "g",
);
const WIN_PATH_RE = new RegExp(String.raw`\b[a-z]:[\\/]${PATH_END}+`, "g");
const SENSITIVE_NAME_RE =
  /(?:\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.bashrc|\.zshrc|\.profile|\.bash_profile|id_rsa|id_ed25519|id_ecdsa|\.env)(?![\w-])/g;

function normalizePath(p: string): string {
  return p
    .replace(/\\/g, "/")
    .replace(/^(?:\$home|\$\{home\}|%userprofile%)\//, "~/")
    .replace(/[.,:;!?]+$/, "");
}

export function extractHosts(text: string): string[] {
  const s = prepForIndicators(text);
  const hosts = new Set<string>();
  for (const m of s.matchAll(URL_RE)) {
    try {
      const host = new URL(m[0]).hostname.replace(/^\[|\]$/g, "");
      if (host) hosts.add(host);
    } catch {
      // not a parseable URL
    }
  }
  for (const m of s.matchAll(EMAIL_RE)) hosts.add(m[1]!);
  for (const m of s.matchAll(DOMAIN_RE)) hosts.add(m[1]!);
  for (const m of s.matchAll(IPV4_RE)) hosts.add(m[0]);
  return [...hosts];
}

export function extractPaths(text: string): string[] {
  const s = prepForIndicators(text);
  const paths = new Set<string>();
  for (const re of [HOME_PATH_RE, UNIX_PATH_RE, WIN_PATH_RE]) {
    for (const m of s.matchAll(re)) {
      const p = normalizePath(m[0]);
      if (p.length >= 4) paths.add(p);
    }
  }
  for (const m of s.matchAll(SENSITIVE_NAME_RE)) paths.add(m[0]);
  return [...paths];
}

function hostMatches(argHost: string, tainted: string): boolean {
  return argHost === tainted || argHost.endsWith(`.${tainted}`);
}

// ---------------------------------------------------------------------------------------------
// Decoding: exfiltration often encodes what it sends

const PRINTABLE = /[\p{L}\p{N}\p{P}\p{S}\s]/u;

function mostlyPrintable(text: string): boolean {
  const chars = [...text];
  if (chars.length < 8 || text.includes("�")) return false;
  return chars.filter((ch) => PRINTABLE.test(ch)).length / chars.length >= 0.9;
}

export function decodings(value: string): Array<{ text: string; via?: TaintHit["via"] }> {
  const out: Array<{ text: string; via?: TaintHit["via"] }> = [{ text: value }];
  const bases = [value];
  if (/%[0-9a-f]{2}/i.test(value)) {
    const decoded = value.replace(/(?:%[0-9a-f]{2})+/gi, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
    if (decoded !== value) {
      out.push({ text: decoded, via: "url-encoding" });
      bases.push(decoded);
    }
  }
  for (const base of bases) {
    const b64 = [...base.matchAll(/[A-Za-z0-9+/_-]{20,}={0,2}/g)]
      .map((m) => Buffer.from(m[0], "base64").toString("utf8"))
      .filter(mostlyPrintable);
    if (b64.length > 0) out.push({ text: b64.join("\n"), via: "base64" });
    const hex = [...base.matchAll(/(?<![0-9a-f])(?:[0-9a-f]{2}){12,}(?![0-9a-f])/gi)]
      .map((m) => Buffer.from(m[0], "hex").toString("utf8"))
      .filter(mostlyPrintable);
    if (hex.length > 0) out.push({ text: hex.join("\n"), via: "hex" });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------

/** Which string arguments a set of top-level argument-name globs selects. */
export function selectArgs(args: unknown, globs: string[]): Array<{ path: string; value: string }> {
  if (!isRecord(args)) {
    return globs.includes("*") ? stringLeaves(args).filter((l) => !l.path.endsWith("<key>")) : [];
  }
  const out: Array<{ path: string; value: string }> = [];
  for (const [key, value] of Object.entries(args)) {
    if (!globs.some((g) => matchGlob(g, key))) continue;
    for (const leaf of stringLeaves(value, key)) {
      if (!leaf.path.endsWith("<key>")) out.push(leaf);
    }
  }
  return out;
}

export class TaintStore {
  private readonly records = new Map<string, TaintRecord>();
  private readonly index = new Map<string, string[]>();
  private offset = 0;
  private partial = "";

  constructor(private readonly opts: TaintOptions) {}

  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }

  private add(record: TaintRecord): void {
    if (this.records.has(record.id) || record.session !== this.opts.session) return;
    this.records.set(record.id, record);
    for (const g of record.grams) {
      const ids = this.index.get(g);
      if (ids) ids.push(record.id);
      else this.index.set(g, [record.id]);
    }
  }

  /** Pick up records other Airlock processes appended since the last look. */
  refresh(): void {
    let fd: number;
    try {
      fd = fs.openSync(this.opts.file, "r");
    } catch {
      return;
    }
    try {
      const size = fs.fstatSync(fd).size;
      if (size < this.offset) {
        this.offset = 0;
        this.partial = "";
      }
      if (size === this.offset) return;
      const buf = Buffer.alloc(size - this.offset);
      fs.readSync(fd, buf, 0, buf.length, this.offset);
      this.offset = size;
      const text = this.partial + buf.toString("utf8");
      const lines = text.split("\n");
      this.partial = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const rec = JSON.parse(line) as TaintRecord;
          if (rec.v === 1 && Array.isArray(rec.grams)) this.add(rec);
        } catch {
          // a torn or foreign line; skip it
        }
      }
    } finally {
      fs.closeSync(fd);
    }
  }

  record(source: TaintSource, texts: string[]): TaintRecord | undefined {
    const text = texts.filter((t) => t.length > 0).join("\n");
    if (!text.trim()) return undefined;
    const record: TaintRecord = {
      v: 1,
      id: crypto.randomBytes(6).toString("hex"),
      ts: this.now(),
      session: this.opts.session,
      server: source.server,
      tool: source.tool,
      label: source.label,
      grams: fingerprint(text, this.opts.minMatch, this.opts.maxTextChars),
      hosts: source.indicators ? extractHosts(text) : [],
      paths: source.indicators ? extractPaths(text) : [],
    };
    fs.mkdirSync(path.dirname(this.opts.file), { recursive: true });
    fs.appendFileSync(this.opts.file, `${JSON.stringify(record)}\n`, "utf8");
    this.add(record);
    return record;
  }

  private live(labels: Set<string>): TaintRecord[] {
    const cutoff = this.now() - this.opts.ttlMs;
    return [...this.records.values()].filter((r) => r.ts >= cutoff && labels.has(r.label));
  }

  /**
   * Find tainted content in a sink call's arguments.
   * `checks` maps a label to the argument-name globs that must not carry content with that label.
   */
  check(args: unknown, checks: Record<string, string[]>, ignoreHosts: string[] = []): TaintHit[] {
    this.refresh();
    const hits: TaintHit[] = [];
    const seen = new Set<string>();
    const k = this.opts.minMatch;
    const cutoff = this.now() - this.opts.ttlMs;
    const ignored = (host: string) => ignoreHosts.some((h) => hostMatches(host, h.toLowerCase()));

    for (const [label, globs] of Object.entries(checks)) {
      const labelSet = new Set([label]);
      const indicatorRecords = this.live(labelSet);
      for (const leaf of selectArgs(args, globs)) {
        for (const variant of decodings(leaf.value)) {
          const push = (hit: TaintHit) => {
            const key = `${hit.arg}|${hit.label}|${hit.kind}|${hit.source.id}|${hit.excerpt}`;
            if (seen.has(key)) return;
            seen.add(key);
            hits.push(hit);
          };
          const base = { arg: leaf.path, label, ...(variant.via ? { via: variant.via } : {}) };

          // Shared text: mark every window that matches a live record, then report merged spans.
          const chars = Array.from(normalizeForMatch(variant.text));
          const spans = new Map<string, Array<[number, number]>>();
          for (let i = 0; i + k <= chars.length; i++) {
            if (trivialGram(chars, i, k)) continue;
            const ids = this.index.get(hashGram(chars.slice(i, i + k).join("")));
            if (!ids) continue;
            for (const id of ids) {
              const rec = this.records.get(id)!;
              if (rec.label !== label || rec.ts < cutoff) continue;
              const list = spans.get(id) ?? [];
              const last = list[list.length - 1];
              if (last && i <= last[1]) last[1] = i + k;
              else list.push([i, i + k]);
              spans.set(id, list);
            }
          }
          for (const [id, list] of spans) {
            const rec = this.records.get(id)!;
            const [s, e] = list.reduce((a, b) => (b[1] - b[0] > a[1] - a[0] ? b : a));
            push({
              ...base,
              kind: "text",
              excerpt: truncate(chars.slice(s, e).join("").trim(), 160),
              source: { id, server: rec.server, tool: rec.tool, ts: rec.ts },
            });
          }

          // Hosts and paths the untrusted content named.
          if (indicatorRecords.length > 0) {
            const argHosts = extractHosts(variant.text).filter((h) => !ignored(h));
            const argText = prepForIndicators(variant.text).replace(/\\/g, "/");
            for (const rec of indicatorRecords) {
              for (const tainted of rec.hosts) {
                if (ignored(tainted)) continue;
                const match = argHosts.find((h) => hostMatches(h, tainted));
                if (match) {
                  push({ ...base, kind: "host", excerpt: match, source: { id: rec.id, server: rec.server, tool: rec.tool, ts: rec.ts } });
                }
              }
              for (const p of rec.paths) {
                if (argText.includes(p)) {
                  push({ ...base, kind: "path", excerpt: p, source: { id: rec.id, server: rec.server, tool: rec.tool, ts: rec.ts } });
                }
              }
            }
          }
        }
      }
    }
    return hits;
  }
}
