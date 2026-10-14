#!/usr/bin/env node
// This repo is public. Refuse anything licensed or internal before it can be pushed.
import { execFileSync } from "node:child_process";
import { mkdtemp, cp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, extname } from "node:path";
import { check } from "../src/qa/leaks.mjs";

const root = new URL("..", import.meta.url).pathname;
const BANNED = new Set([".woff", ".woff2", ".ttf", ".otf", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".mp4", ".zip", ".pdf"]);
const tracked = execFileSync("git", ["ls-files"], { cwd: root, encoding: "utf8" }).split("\n").filter(Boolean);
const problems = tracked.filter((f) => BANNED.has(extname(f).toLowerCase())).map((f) => `${f}: binary or licensed asset type`);

const copy = await mkdtemp(join(tmpdir(), "kit-guard-"));
for (const f of tracked.filter((f) => !f.startsWith("test/"))) {
  await cp(join(root, f), join(copy, f), { recursive: true });
}
problems.push(...(await check(copy, { qaAllow: [] })));

for (const p of problems) console.error(p);
if (problems.length) { console.error(`guard: ${problems.length} problems`); process.exit(1); }
console.log("guard: ok");
