import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, truncate } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { check as links } from "../src/qa/links.mjs";
import { check as size } from "../src/qa/size.mjs";
import { check as leaks } from "../src/qa/leaks.mjs";
import { run } from "../src/qa/index.mjs";

async function siteWith(files) {
  const dir = await mkdtemp(join(tmpdir(), "kit-qa-"));
  for (const [p, body] of Object.entries(files)) {
    await mkdir(dirname(join(dir, p)), { recursive: true });
    await writeFile(join(dir, p), body);
  }
  return dir;
}
const cfg = { qaAllow: [] };

test("links: resolves relative, absolute, directory and extensionless refs", async () => {
  const d = await siteWith({
    "index.html": '<a href="a.html">a</a><a href="/sub/">s</a><a href="b">b</a><img src="img/x.webp"><a href="https://e.com/x">e</a><a href="#top">t</a>',
    "a.html": "", "b.html": "", "sub/index.html": "", "img/x.webp": "x",
  });
  assert.deepEqual(await links(d, cfg), []);
});

test("links: reports missing files, srcset entries and escapes", async () => {
  const d = await siteWith({ "p/index.html": '<a href="gone.html">x</a><img srcset="/i/1.webp 1x, /i/2.webp 2x"><a href="../../etc/passwd">x</a>', "i/1.webp": "x" });
  assert.deepEqual((await links(d, cfg)).sort(), [
    "p/index.html: broken ../../etc/passwd",
    "p/index.html: broken /i/2.webp",
    "p/index.html: broken gone.html",
  ]);
});

test("size: a file over 25 MiB is reported", async () => {
  const d = await siteWith({ "big.bin": "" });
  await truncate(join(d, "big.bin"), 25 * 1024 * 1024 + 1);
  assert.deepEqual(await size(d, cfg), ["big.bin: 25.0 MiB is over Cloudflare Pages' 25 MiB file limit"]);
});

test("leaks: IPs, internal hostnames, tokens, 1Password refs, home paths", async () => {
  const d = await siteWith({
    "a.html": "host 10.0.0.1 and 192.168.0.2 and 172.20.1.2 and 100.100.1.1",
    "b.js": "fetch('http://printer.lan:8080'); const x='box.see';",
    "c.txt": "ghp_" + "a".repeat(36) + " AKIA" + "B".repeat(16) + " op://vault/item/field /home/someone/projects",
    "d.css": "/* -----BEGIN OPENSSH PRIVATE KEY----- */",
    "e.webp": "\u0000RIFF 10.0.0.1",
  });
  const found = await leaks(d, cfg);
  const count = (label) => found.filter((p) => p.includes(`: ${label} "`)).length;
  assert.equal(count("private IP address"), 4);
  assert.equal(count("internal hostname"), 2);
  for (const label of ["GitHub token", "AWS access key", "1Password reference", "home directory path", "private key"]) {
    assert.equal(count(label), 1, label);
  }
  assert.ok(found.every((p) => !p.startsWith("e.webp")), "binary files are not scanned");
  assert.ok(found.every((p) => !p.includes("a".repeat(20))), "a token is never printed whole");
});

test("leaks: more secret formats and paths", async () => {
  const d = await siteWith({
    "a.html": [
      "github_pat_" + "A1".repeat(20),
      "sk_live_" + "x".repeat(24),
      "AIza" + "Q".repeat(35),
      "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0." + "s".repeat(30),
      "node.tail1234.ts.net",
      " /root/.ssh/id",
    ].join(" "),
  });
  const found = (await leaks(d, cfg)).join("\n");
  for (const label of ["GitHub token", "API key", "Google API key", "JSON web token", "internal hostname", "home directory path"]) {
    assert.match(found, new RegExp(`: ${label} "`), label);
  }
});

test("leaks: files of any text type are scanned, binaries are not", async () => {
  const d = await siteWith({ ".env": "DB=10.0.0.1", "_headers": "/x\n  X-Origin: box.lan", "deploy.yml": "op://vault/i/f", "img.bin": "\u0000\u0000 10.0.0.1" });
  const found = await leaks(d, cfg);
  assert.ok(found.some((p) => p.startsWith(".env:")), ".env");
  assert.ok(found.some((p) => p.startsWith("_headers:")), "_headers");
  assert.ok(found.some((p) => p.startsWith("deploy.yml:")), "yml");
  assert.ok(!found.some((p) => p.startsWith("img.bin:")), "binary skipped");
});

test("leaks: JavaScript property access and URL paths are not hostnames or home paths", async () => {
  const d = await siteWith({
    "app.min.js": "function f(e){return e.local||this.internal||(t.env.local)}",
    "a.html": "<p>Copy .env.local first.</p><a href=\"https://example.com/home/x/page\">x</a>",
  });
  assert.deepEqual(await leaks(d, cfg), []);
});

test("leaks: addresses, hostnames and paths are printed whole so they can be allowed", async () => {
  const d = await siteWith({ "a.html": "<p>the printer is metadata-server.local today</p>" });
  const found = await leaks(d, cfg);
  assert.deepEqual(found, ['a.html: internal hostname "metadata-server.local"']);
  assert.deepEqual(await leaks(d, { qaAllow: ["metadata-server.local"] }), []);
});

test("leaks: ordinary prose and public addresses pass", async () => {
  const d = await siteWith({ "a.html": "Version 1.2.3, 10 Oct 2026, see https://seeper-labs.com, 8.8.8.8, plan.html, e.g. the board" });
  assert.deepEqual(await leaks(d, cfg), []);
});

test("qaAllow suppresses an exact match", async () => {
  const d = await siteWith({ "a.html": "firmware 10.3.1.2 shipped" });
  assert.equal((await leaks(d, cfg)).length, 1);
  assert.deepEqual(await leaks(d, { qaAllow: ["10.3.1.2"] }), []);
});

test("links: code samples are not links", async () => {
  const d = await siteWith({ "a.html": '<pre><code>&lt;a href="example.html"&gt;</code></pre><code><a href="nope.html">x</a></code><script>x="<a href=\'gone.html\'>"</script><!-- <a href="old.html"> -->' });
  assert.deepEqual(await links(d, cfg), []);
});

test("links: a malformed escape is reported, not a crash", async () => {
  const d = await siteWith({ "a.html": '<a href="100%.html">x</a>' });
  assert.deepEqual(await links(d, cfg), ["a.html: malformed link 100%.html"]);
});

test("links: qaAllow skips a link", async () => {
  const d = await siteWith({ "a.html": '<a href="later.html">x</a>' });
  assert.deepEqual(await links(d, { qaAllow: ["later.html"] }), []);
});

test("run: _worker.js in the output fails, because it switches the gate off", async () => {
  const d = await siteWith({ "package.json": JSON.stringify({ kit: { build: "true" } }), "site/index.html": "<p>ok</p>", "site/_worker.js": "export default {}" });
  assert.equal(await run(d), 1);
});

test("run: _routes.json that excludes paths fails; one covering everything passes", async () => {
  const bad = await siteWith({ "package.json": JSON.stringify({ kit: { build: "true" } }), "site/index.html": "<p>ok</p>", "site/_routes.json": JSON.stringify({ version: 1, include: ["/*"], exclude: ["/assets/*"] }) });
  assert.equal(await run(bad), 1);
  const good = await siteWith({ "package.json": JSON.stringify({ kit: { build: "true" } }), "site/index.html": "<p>ok</p>", "site/_routes.json": JSON.stringify({ version: 1, include: ["/*"], exclude: [] }) });
  assert.equal(await run(good), 0);
});

test("run: a wrangler config in the site fails, because it would replace the gate binding", async () => {
  for (const name of ["wrangler.toml", "wrangler.json", "wrangler.jsonc"]) {
    const d = await siteWith({ "package.json": JSON.stringify({ kit: { build: "true" } }), "site/index.html": "<p>ok</p>", [name]: "" });
    assert.equal(await run(d), 1, name);
  }
});

test("run: missing output folder fails", async () => {
  const d = await siteWith({ "package.json": JSON.stringify({ kit: { build: "true" } }) });
  assert.equal(await run(d), 1);
});

test("run: a clean site passes", async () => {
  const d = await siteWith({ "package.json": JSON.stringify({ kit: { build: "true" } }), "site/index.html": "<p>ok</p>" });
  assert.equal(await run(d), 0);
});
