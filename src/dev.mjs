import { spawn } from "node:child_process";
import { connect } from "node:net";
import { readKitConfig } from "./config.mjs";
import { run as build } from "./build.mjs";

export function devArgs(cfg, port, password) {
  return ["--yes", "wrangler@4", "pages", "dev", cfg.output, "--port", String(port), "--binding", `SITE_GATE_DEV_PASSWORD=${password}`];
}

// npx is npx.cmd on Windows, and Node will not spawn a .cmd without a shell,
// so there the args go through cmd.exe and need quoting.
export function devSpawn(args, platform = process.platform) {
  if (platform !== "win32") return { cmd: "npx", args, shell: false };
  return { cmd: "npx", args: args.map((a) => (/^[\w@.:=\/-]+$/.test(a) ? a : `"${a.replace(/"/g, '""')}"`)), shell: true };
}

// On Windows a second wrangler can bind a port another one already holds, and
// the browser gets the other site, so check by connecting rather than binding.
export function portInUse(port, host = "127.0.0.1") {
  return new Promise((resolve) => {
    const s = connect({ port, host });
    s.setTimeout(1000);
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("timeout", () => { s.destroy(); resolve(false); });
    s.once("error", () => resolve(false));
  });
}

export async function run(cwd, args) {
  const i = args.indexOf("--port");
  const port = i >= 0 ? Number(args[i + 1]) : 8788;
  const password = process.env.SITE_GATE_DEV_PASSWORD || "dev";
  if (await portInUse(port)) {
    throw new Error(`port ${port} is already in use (another site-kit dev?); stop it or pass --port ${port + 1}`);
  }
  await build(cwd);
  const cfg = await readKitConfig(cwd);
  console.log(`site-kit dev: http://localhost:${port}  (password: ${password === "dev" ? "dev" : "from SITE_GATE_DEV_PASSWORD"})`);
  const { cmd, args: spawnArgs, shell } = devSpawn(devArgs(cfg, port, password));
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, spawnArgs, { cwd, shell, stdio: "inherit" });
    p.on("error", reject);
    p.on("exit", (code) => resolve(code ?? 1));
  });
}
