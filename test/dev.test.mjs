import { test } from "node:test";
import assert from "node:assert/strict";
import { devArgs } from "../src/dev.mjs";

test("dev runs wrangler pages dev on the output with the dev password and no KV", () => {
  assert.deepEqual(devArgs({ output: "site" }, 8788, "dev"), [
    "--yes", "wrangler@4", "pages", "dev", "site", "--port", "8788",
    "--binding", "SITE_GATE_DEV_PASSWORD=dev",
  ]);
});
