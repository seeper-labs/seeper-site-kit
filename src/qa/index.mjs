import { stat, readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { readKitConfig } from "../config.mjs";
import { files } from "./walk.mjs";
import { check as links } from "./links.mjs";
import { check as size } from "./size.mjs";
import { check as leaks } from "./leaks.mjs";

const exists = async (p) => { try { await access(p); return true; } catch { return false; } };

// Anything that would let Pages serve the site without the gate: a _worker.js replaces functions/,
// a _routes.json can exclude paths from the middleware, and a wrangler config replaces the
// project's bindings, SITE_GATE included.
async function gateBypass(cwd, site) {
  const problems = [];
  for (const name of ["wrangler.toml", "wrangler.json", "wrangler.jsonc"]) {
    if (await exists(join(cwd, name))) problems.push(`${name}: remove it; the controller sets this site's bindings, and a wrangler config would replace them`);
  }
  if (await exists(join(site, "_worker.js"))) problems.push("_worker.js: Pages would run it instead of the gate");
  if (await exists(join(site, "_routes.json"))) {
    let routes = {};
    try { routes = JSON.parse(await readFile(join(site, "_routes.json"), "utf8")); } catch { /* reported below */ }
    const all = JSON.stringify(routes.include) === '["/*"]' && Array.isArray(routes.exclude) && routes.exclude.length === 0;
    if (!all) problems.push('_routes.json: the gate must run on every path (include ["/*"], exclude [])');
  }
  return problems;
}

export async function run(cwd) {
  const cfg = await readKitConfig(cwd);
  const site = join(cwd, cfg.output);
  try { if (!(await stat(site)).isDirectory()) throw 0; } catch {
    console.error(`site-kit qa: ${cfg.output}/ does not exist; build the site first`);
    return 1;
  }
  const problems = [...(await gateBypass(cwd, site)), ...(await links(site, cfg)), ...(await size(site, cfg)), ...(await leaks(site, cfg))];
  for (const p of problems) console.error(`  ${p}`);
  if (problems.length) { console.error(`site-kit qa: ${problems.length} problems in ${cfg.output}/`); return 1; }
  let n = 0; for await (const _ of files(site)) n++;
  console.log(`site-kit qa: ok (${n} files)`);
  return 0;
}
