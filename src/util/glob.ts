const cache = new Map<string, RegExp>();

/** `*` matches any run of characters, `?` matches one. Everything else is literal. Case-sensitive. */
export function matchGlob(pattern: string, value: string): boolean {
  let re = cache.get(pattern);
  if (!re) {
    const body = pattern
      .split("")
      .map((ch) => (ch === "*" ? ".*" : ch === "?" ? "." : ch.replace(/[.+^${}()|[\]\\]/g, "\\$&")))
      .join("");
    re = new RegExp(`^${body}$`, "s");
    cache.set(pattern, re);
  }
  return re.test(value);
}
