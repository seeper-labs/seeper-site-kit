import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { once } from "node:events";
import { devArgs, devSpawn, portInUse } from "../src/dev.mjs";

test("dev runs wrangler pages dev on the output with the dev password and no KV", () => {
  assert.deepEqual(devArgs({ output: "site" }, 8788, "dev"), [
    "--yes", "wrangler@4", "pages", "dev", "site", "--port", "8788",
    "--binding", "SITE_GATE_DEV_PASSWORD=dev",
  ]);
});

test("dev spawns npx directly off Windows and through the shell on Windows", () => {
  const args = devArgs({ output: "site" }, 8788, "dev");
  assert.deepEqual(devSpawn(args, "linux"), { cmd: "npx", args, shell: false });
  assert.deepEqual(devSpawn(args, "win32"), { cmd: "npx", args, shell: true });
});

test("dev quotes a Windows arg that cmd.exe would split", () => {
  const { args } = devSpawn(devArgs({ output: "my site" }, 8788, 'a b"c'), "win32");
  assert.equal(args[4], '"my site"');
  assert.equal(args[8], '"SITE_GATE_DEV_PASSWORD=a b""c"');
});

test("dev sees a port another server is listening on", async () => {
  const server = createServer().listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  assert.equal(await portInUse(port), true);
  server.close();
  await once(server, "close");
  assert.equal(await portInUse(port), false);
});
