#!/usr/bin/env node
import { readFileSync } from "node:fs";

const USAGE = "usage: site-kit <build|qa|dev> | --version";
const [cmd, ...args] = process.argv.slice(2);
const version = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;

const commands = {
  build: () => import("../src/build.mjs"),
  qa: () => import("../src/qa/index.mjs"),
  dev: () => import("../src/dev.mjs"),
};

if (cmd === "--version") {
  console.log(version);
} else if (!commands[cmd]) {
  console.error(USAGE);
  process.exit(2);
} else {
  const mod = await commands[cmd]();
  try {
    process.exitCode = await mod.run(process.cwd(), args);
  } catch (e) {
    console.error(`site-kit ${cmd}: ${e.message}`);
    process.exitCode = 1;
  }
}
