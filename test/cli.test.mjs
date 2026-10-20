import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readKitConfig, KitConfigError } from "../src/config.mjs";

const run = promisify(execFile);
const BIN = new URL("../bin/site-kit.mjs", import.meta.url).pathname;

test("--version prints the package version", async () => {
  const { stdout } = await run("node", [BIN, "--version"]);
  assert.equal(stdout.trim(), "1.1.1");
});

test("an unknown command exits 2 with usage", async () => {
  await assert.rejects(run("node", [BIN, "nope"]), (e) => e.code === 2 && /usage: site-kit/.test(e.stderr));
});

async function site(pkg) {
  const dir = await mkdtemp(join(tmpdir(), "kit-"));
  await writeFile(join(dir, "package.json"), JSON.stringify(pkg));
  return dir;
}

test("readKitConfig applies defaults", async () => {
  const dir = await site({ kit: { build: "true" } });
  assert.deepEqual(await readKitConfig(dir), { build: "true", output: "site", qaAllow: [], bearerPaths: [] });
});

test("readKitConfig names package.json when kit.build is missing", async () => {
  const dir = await site({ name: "x" });
  await assert.rejects(readKitConfig(dir), (e) => e instanceof KitConfigError && /package\.json.*kit\.build/.test(e.message));
});
