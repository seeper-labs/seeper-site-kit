import { stat } from "node:fs/promises";
import { relative } from "node:path";
import { files } from "./walk.mjs";

const LIMIT = 25 * 1024 * 1024;

export async function check(site) {
  const problems = [];
  for await (const f of files(site)) {
    const { size } = await stat(f);
    if (size > LIMIT) problems.push(`${relative(site, f)}: ${(size / 1024 / 1024).toFixed(1)} MiB is over Cloudflare Pages' 25 MiB file limit`);
  }
  return problems;
}
