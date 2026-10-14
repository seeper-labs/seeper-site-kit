import { readFile, stat } from "node:fs/promises";
import { join, dirname, normalize, relative, sep, extname } from "node:path";
import { files } from "./walk.mjs";

const ATTR_RE = /\s(?:href|src)\s*=\s*["']([^"']+)["']/gi;
const SRCSET_RE = /\ssrcset\s*=\s*["']([^"']+)["']/gi;
const isFile = async (p) => { try { return (await stat(p)).isFile(); } catch { return false; } };
const isDir = async (p) => { try { return (await stat(p)).isDirectory(); } catch { return false; } };

// Code samples, scripts, styles and comments hold text that looks like links but isn't.
const NOT_MARKUP_RE = /<!--[\s\S]*?-->|<(pre|code|script|style)\b[\s\S]*?<\/\1\s*>/gi;

function refs(html) {
  html = html.replace(NOT_MARKUP_RE, "");
  const out = [];
  for (const m of html.matchAll(ATTR_RE)) out.push(m[1]);
  for (const m of html.matchAll(SRCSET_RE)) for (const part of m[1].split(",")) out.push(part.trim().split(/\s+/)[0]);
  return out;
}

// The file a reference points at, or null when it isn't a local file.
async function target(site, page, ref) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(ref) || ref.startsWith("//")) return null;
  let path = ref.split("#")[0].split("?")[0];
  if (!path) return null;
  try { path = decodeURIComponent(path); } catch { return { malformed: true }; }
  const base = path.startsWith("/") ? site : dirname(page);
  const full = normalize(join(base, path.replace(/^\/+/, "")));
  if (path.endsWith("/") || (await isDir(full))) return join(full, "index.html");
  if (!extname(full) && (await isFile(full + ".html"))) return full + ".html"; // Pages serves /name from name.html
  return full;
}

export async function check(site, cfg = {}) {
  const allow = new Set(cfg.qaAllow || []);
  const problems = [];
  for await (const page of files(site)) {
    if (!page.endsWith(".html")) continue;
    for (const ref of refs(await readFile(page, "utf8"))) {
      if (allow.has(ref)) continue;
      const t = await target(site, page, ref);
      if (t === null) continue;
      if (t.malformed) { problems.push(`${relative(site, page)}: malformed link ${ref}`); continue; }
      if (!t.startsWith(site + sep) || !(await isFile(t))) problems.push(`${relative(site, page)}: broken ${ref}`);
    }
  }
  return problems;
}
