import { readFile } from "node:fs/promises";
import { join } from "node:path";

export class KitConfigError extends Error {}

export async function readKitConfig(cwd) {
  const pkg = JSON.parse(await readFile(join(cwd, "package.json"), "utf8"));
  const kit = pkg.kit || {};
  if (typeof kit.build !== "string" || !kit.build.trim()) {
    throw new KitConfigError(`package.json: "kit.build" must be the command that builds the site, e.g. "python3 build.py"`);
  }
  return {
    build: kit.build,
    output: typeof kit.output === "string" && kit.output ? kit.output : "site",
    qaAllow: Array.isArray(kit.qaAllow) ? kit.qaAllow.map(String) : [],
  };
}
