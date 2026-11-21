import { mapStrings, stringLeaves } from "./util/json.js";

/**
 * Characters a model reads but a person usually can't see.
 *
 * - tag: Unicode TAG block (U+E0000-E007F). Each one mirrors an ASCII character, so a run of them
 *   spells out invisible text ("ASCII smuggling"). Models tokenize and follow it.
 * - bidi: embedding, override, and isolate controls that reorder how text is displayed.
 * - invisible: zero-width and other blank characters that can hide or split words.
 * - variation: runs of variation selectors, which can encode arbitrary bytes after one visible character.
 */
export type HiddenKind = "tag" | "bidi" | "invisible" | "variation";

export interface HiddenRun {
  kind: HiddenKind;
  /** UTF-16 offsets into the scanned string, end exclusive. */
  start: number;
  end: number;
  codePoints: number[];
  /** For tag runs: the ASCII the run spells. For variation runs: the bytes they encode, if they decode to text. */
  decoded?: string;
}

const BIDI_NAMES: Record<number, string> = {
  0x202a: "LRE",
  0x202b: "RLE",
  0x202c: "PDF",
  0x202d: "LRO",
  0x202e: "RLO",
  0x2066: "LRI",
  0x2067: "RLI",
  0x2068: "FSI",
  0x2069: "PDI",
};

const INVISIBLE_NAMES: Record<number, string> = {
  0x200b: "ZWSP",
  0x200c: "ZWNJ",
  0x200d: "ZWJ",
  0x2060: "WJ",
  0x2061: "FUNCTION APPLICATION",
  0x2062: "INVISIBLE TIMES",
  0x2063: "INVISIBLE SEPARATOR",
  0x2064: "INVISIBLE PLUS",
  0xfeff: "ZWNBSP",
  0x180e: "MVS",
  0x115f: "HANGUL CHOSEONG FILLER",
  0x1160: "HANGUL JUNGSEONG FILLER",
  0x3164: "HANGUL FILLER",
  0xffa0: "HALFWIDTH HANGUL FILLER",
};

function isTag(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

function isBidiControl(cp: number): boolean {
  return cp in BIDI_NAMES;
}

function isInvisible(cp: number): boolean {
  return (
    cp in INVISIBLE_NAMES ||
    (cp >= 0x206a && cp <= 0x206f) || // deprecated format characters
    (cp >= 0xfff9 && cp <= 0xfffb) || // interlinear annotation
    (cp >= 0x1d173 && cp <= 0x1d17a) // musical formatting
  );
}

function isVariationSelector(cp: number): boolean {
  return (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
}

const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;
const EMOJI_MODIFIER = (cp: number) => cp >= 0x1f3fb && cp <= 0x1f3ff;
const NON_LATIN_LETTER = /^[\p{L}\p{M}]$/u;
const LATIN = /\p{Script=Latin}/u;

function isEmojiSide(cp: number | undefined): boolean {
  if (cp === undefined) return false;
  return PICTOGRAPHIC.test(String.fromCodePoint(cp)) || EMOJI_MODIFIER(cp) || cp === 0xfe0f;
}

function isNonLatinLetter(cp: number | undefined): boolean {
  if (cp === undefined || cp < 0x80) return false;
  const ch = String.fromCodePoint(cp);
  return NON_LATIN_LETTER.test(ch) && !LATIN.test(ch);
}

interface Cp {
  cp: number;
  index: number;
  size: number;
}

function codePoints(text: string): Cp[] {
  const out: Cp[] = [];
  let index = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    out.push({ cp, index, size: ch.length });
    index += ch.length;
  }
  return out;
}

/** A subdivision flag such as England: U+1F3F4, tag letters/digits, then CANCEL TAG (U+E007F). */
function benignFlagTagRun(cps: Cp[], start: number, end: number): boolean {
  if (start === 0 || cps[start - 1]!.cp !== 0x1f3f4) return false;
  const length = end - start;
  if (length < 3 || length > 8 || cps[end - 1]!.cp !== 0xe007f) return false;
  for (let i = start; i < end - 1; i++) {
    const c = cps[i]!.cp - 0xe0000;
    const isLower = c >= 0x61 && c <= 0x7a;
    const isDigit = c >= 0x30 && c <= 0x39;
    if (!isLower && !isDigit) return false;
  }
  return true;
}

function decodeTags(points: number[]): string {
  let out = "";
  for (const cp of points) {
    const c = cp - 0xe0000;
    if (c >= 0x20 && c <= 0x7e) out += String.fromCharCode(c);
    else if (c === 0x0a || c === 0x0d || c === 0x09) out += String.fromCharCode(c);
  }
  return out;
}

/** Variation selectors as bytes: VS1-16 are 0-15, VS17-256 are 16-255. */
function decodeVariation(points: number[]): string | undefined {
  const bytes = points.map((cp) => (cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16));
  const text = new TextDecoder("utf-8", { fatal: false }).decode(Uint8Array.from(bytes));
  const printable = [...text].filter((ch) => /[\p{L}\p{N}\p{P}\p{S}\p{Zs}]/u.test(ch)).length;
  return text.length > 0 && printable / [...text].length >= 0.8 ? text : undefined;
}

/** Find every run of hidden characters in `text`, skipping the common benign uses (emoji, flags, BOM, Persian/Indic joiners). */
export function scanHidden(text: string): HiddenRun[] {
  if (!/[​-‍⁠-⁯‪-‮﻿᠎︀-️￹-￻ᅟᅠㅤﾠ\u{e0000}-\u{e01ef}\u{1d173}-\u{1d17a}]/u.test(text)) {
    return [];
  }
  const cps = codePoints(text);
  const kinds: Array<HiddenKind | undefined> = new Array(cps.length);

  for (let i = 0; i < cps.length; i++) {
    const { cp } = cps[i]!;
    if (isTag(cp)) {
      let j = i;
      while (j < cps.length && isTag(cps[j]!.cp)) j++;
      if (!benignFlagTagRun(cps, i, j)) for (let k = i; k < j; k++) kinds[k] = "tag";
      i = j - 1;
    } else if (isBidiControl(cp)) {
      kinds[i] = "bidi";
    } else if (isVariationSelector(cp)) {
      let j = i;
      while (j < cps.length && isVariationSelector(cps[j]!.cp)) j++;
      // One selector after a visible character picks a glyph style (emoji, CJK variants). Two or more never do.
      const single = j - i === 1 && i > 0;
      if (!single) for (let k = i; k < j; k++) kinds[k] = "variation";
      i = j - 1;
    } else if (isInvisible(cp)) {
      const prev = cps[i - 1]?.cp;
      const next = cps[i + 1]?.cp;
      const joiner = cp === 0x200d || cp === 0x200c;
      const benign =
        (cp === 0xfeff && i === 0) ||
        (cp === 0x200d && isEmojiSide(prev) && next !== undefined && PICTOGRAPHIC.test(String.fromCodePoint(next))) ||
        (joiner && isNonLatinLetter(prev) && isNonLatinLetter(next));
      if (!benign) kinds[i] = "invisible";
    }
  }

  const runs: HiddenRun[] = [];
  for (let i = 0; i < cps.length; i++) {
    const kind = kinds[i];
    if (!kind) continue;
    let j = i;
    while (j < cps.length && kinds[j] === kind) j++;
    const points = cps.slice(i, j).map((c) => c.cp);
    const last = cps[j - 1]!;
    const run: HiddenRun = { kind, start: cps[i]!.index, end: last.index + last.size, codePoints: points };
    if (kind === "tag") run.decoded = decodeTags(points);
    if (kind === "variation") {
      const decoded = decodeVariation(points);
      if (decoded !== undefined) run.decoded = decoded;
    }
    runs.push(run);
    i = j - 1;
  }
  return runs;
}

/** Remove every flagged run. Benign uses (emoji joiners, flags, a leading BOM) are kept. */
export function stripHidden(text: string): { text: string; runs: HiddenRun[]; removed: number } {
  const runs = scanHidden(text);
  if (runs.length === 0) return { text, runs, removed: 0 };
  let out = "";
  let pos = 0;
  let removed = 0;
  for (const run of runs) {
    out += text.slice(pos, run.start);
    pos = run.end;
    removed += run.codePoints.length;
  }
  out += text.slice(pos);
  return { text: out, runs, removed };
}

function hex(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

function describeRun(run: HiddenRun): string {
  switch (run.kind) {
    case "tag":
      return `⟦hidden text: ${JSON.stringify(run.decoded ?? "")}⟧`;
    case "variation":
      return run.decoded !== undefined
        ? `⟦${run.codePoints.length} variation selectors encoding ${JSON.stringify(run.decoded)}⟧`
        : `⟦${run.codePoints.length} variation selectors⟧`;
    case "bidi":
      return `⟦${run.codePoints.map((cp) => BIDI_NAMES[cp] ?? hex(cp)).join(" ")}⟧`;
    case "invisible": {
      const names = run.codePoints.map((cp) => INVISIBLE_NAMES[cp] ?? hex(cp));
      const same = names.every((n) => n === names[0]);
      return same && names.length > 1 ? `⟦${names[0]}×${names.length}⟧` : `⟦${names.join(" ")}⟧`;
    }
  }
}

/** The text with each hidden run replaced by a visible marker that says what a model would read there. */
export function revealHidden(text: string): string {
  const runs = scanHidden(text);
  let out = "";
  let pos = 0;
  for (const run of runs) {
    out += text.slice(pos, run.start) + describeRun(run);
    pos = run.end;
  }
  return out + text.slice(pos);
}

export function summarizeRuns(runs: HiddenRun[]): string {
  const counts = new Map<HiddenKind, number>();
  for (const run of runs) counts.set(run.kind, (counts.get(run.kind) ?? 0) + run.codePoints.length);
  return [...counts].map(([kind, n]) => `${n} ${kind}`).join(", ");
}

export interface HiddenInJson {
  path: string;
  runs: HiddenRun[];
  revealed: string;
}

/** Scan every string (and object key) in a JSON value. */
export function scanHiddenJson(value: unknown): HiddenInJson[] {
  const out: HiddenInJson[] = [];
  for (const leaf of stringLeaves(value)) {
    const runs = scanHidden(leaf.value);
    if (runs.length > 0) out.push({ path: leaf.path || "(root)", runs, revealed: revealHidden(leaf.value) });
  }
  return out;
}

export function stripHiddenJson<T>(value: T): { value: T; removed: number } {
  let removed = 0;
  const stripped = mapStrings(value, (s) => {
    const r = stripHidden(s);
    removed += r.removed;
    return r.text;
  }) as T;
  return { value: stripped, removed };
}

/** What a model reads in this text: hidden tag runs become plain ASCII, other hidden characters are dropped. */
export function modelView(text: string): string {
  const runs = scanHidden(text);
  let out = "";
  let pos = 0;
  for (const run of runs) {
    out += text.slice(pos, run.start) + (run.kind === "tag" ? (run.decoded ?? "") : "");
    pos = run.end;
  }
  return out + text.slice(pos);
}

/** Encode ASCII as invisible TAG characters. Used by the attack lab and the tests. */
export function toTagChars(ascii: string): string {
  return [...ascii].map((ch) => String.fromCodePoint(0xe0000 + ch.charCodeAt(0))).join("");
}
