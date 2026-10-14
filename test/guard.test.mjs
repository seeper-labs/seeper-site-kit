import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

test("the kit repo itself passes its guard", async () => {
  const { stdout } = await promisify(execFile)("node", [new URL("../tools/guard.mjs", import.meta.url).pathname]);
  assert.match(stdout, /guard: ok/);
});
