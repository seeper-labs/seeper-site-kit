import { spawn } from "node:child_process";
import { readKitConfig } from "./config.mjs";
import { run as build } from "./build.mjs";

export function devArgs(cfg, port, password) {
  return ["--yes", "wrangler@4", "pages", "dev", cfg.output, "--port", String(port), "--binding", `SITE_GATE_DEV_PASSWORD=${password}`];
}

export async function run(cwd, args) {
  const i = args.indexOf("--port");
  const port = i >= 0 ? Number(args[i + 1]) : 8788;
  const password = process.env.SITE_GATE_DEV_PASSWORD || "dev";
  await build(cwd);
  const cfg = await readKitConfig(cwd);
  console.log(`site-kit dev: http://localhost:${port}  (password: ${password === "dev" ? "dev" : "from SITE_GATE_DEV_PASSWORD"})`);
  return new Promise((resolve) => {
    const p = spawn("npx", devArgs(cfg, port, password), { cwd, stdio: "inherit" });
    p.on("exit", (code) => resolve(code ?? 1));
  });
}
