import path from "node:path";

/** A readable default server name from its command: `npx -y @scope/server-github@1.2` -> `server-github`. */
export function deriveName(command: string[]): string {
  const tokens = command.filter((t) => !t.startsWith("-"));
  const last = tokens[tokens.length - 1] ?? "server";
  const base = path
    .basename(last.replace(/(.)@[^/@]*$/, "$1"))
    .replace(/\.(m?[jt]s|c?js|py|exe|cmd)$/i, "");
  const clean = base.replace(/[^A-Za-z0-9._-]/g, "-").replace(/^[^A-Za-z0-9]+/, "").slice(0, 64);
  return clean || "server";
}
