import { readFile } from "node:fs/promises";
import { join } from "node:path";

export class KitConfigError extends Error {}

function bearerPaths(v) {
  if (v === undefined) return [];
  const bad = () => { throw new KitConfigError(`package.json: "kit.bearerPaths" must be a list of absolute path prefixes such as "/api/comments" (not "/", no "..", no %-encoding)`); };
  if (!Array.isArray(v)) bad();
  for (const p of v) {
    if (typeof p !== "string" || !p.startsWith("/") || p === "/" || p.includes("%") || p.includes("\\") || p.split("/").some((s) => s === ".." || s === ".")) bad();
  }
  return v;
}

// Exact paths of images served without the password, such as a link preview card (og:image) that
// Slack or Teams fetch with no cookie. Images only, so a page can never be listed here.
const IMAGE_RE = /^\/[A-Za-z0-9_.\/-]+\.(png|jpe?g|webp)$/;
function publicImages(v) {
  if (v === undefined) return [];
  const bad = () => { throw new KitConfigError(`package.json: "kit.publicImages" must be a list of exact image paths such as "/og.png" (.png, .jpg or .webp; no "..", no %-encoding)`); };
  if (!Array.isArray(v)) bad();
  for (const p of v) {
    if (typeof p !== "string" || !IMAGE_RE.test(p) || p.split("/").some((s) => s === ".." || s === ".")) bad();
  }
  return v;
}

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
    bearerPaths: bearerPaths(kit.bearerPaths),
    publicImages: publicImages(kit.publicImages),
  };
}
