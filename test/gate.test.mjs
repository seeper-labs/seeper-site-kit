import { test } from "node:test";
import assert from "node:assert/strict";
import { handle, sha256hex, token, COOKIE } from "../src/gate.js";

const LOGIN = "<form>LOGIN<!--gate:error--></form>";
const PASSWORD = "correct horse";
const kv = (value) => ({ get: async (k) => (k === "password-sha256" ? value : null) });
const ok = () => new Response("SITE", { status: 200, headers: { "content-type": "text/html" } });
const file = () => new Response("token-body", { status: 200, headers: { "content-type": "text/plain" } });
const req = (path, init = {}) => new Request("https://a.seeper-labs.com" + path, init);
const post = (p) => req("/__auth", { method: "POST", body: new URLSearchParams({ p }) });

async function env() { return { SITE_GATE: kv(await sha256hex(PASSWORD)) }; }

test("fails closed without SITE_GATE", async () => {
  const r = await handle(req("/"), {}, ok, LOGIN);
  assert.equal(r.status, 503);
});

test("fails closed when the key is absent", async () => {
  const r = await handle(req("/"), { SITE_GATE: kv(null) }, ok, LOGIN);
  assert.equal(r.status, 503);
  assert.doesNotMatch(await r.text(), /SITE/);
});

test("no cookie gets the login page without the error", async () => {
  const r = await handle(req("/"), await env(), ok, LOGIN);
  assert.equal(r.status, 200);
  const body = await r.text();
  assert.match(body, /LOGIN/);
  assert.doesNotMatch(body, /Not that one/);
  assert.equal(r.headers.get("cache-control"), "no-store");
});

test("wrong password gets 401 and the error", async () => {
  const r = await handle(post("nope"), await env(), ok, LOGIN);
  assert.equal(r.status, 401);
  assert.match(await r.text(), /Not that one/);
});

test("right password sets a host bound cookie and redirects", async () => {
  const e = await env();
  const r = await handle(post(PASSWORD), e, ok, LOGIN);
  assert.equal(r.status, 303);
  const expected = await token(await sha256hex(PASSWORD), "a.seeper-labs.com");
  assert.match(r.headers.get("set-cookie"), new RegExp(`^${COOKIE}=${expected}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800$`));
});

test("trims pasted whitespace", async () => {
  const r = await handle(post(`  ${PASSWORD}\n`), await env(), ok, LOGIN);
  assert.equal(r.status, 303);
});

test("a valid cookie reaches the site", async () => {
  const e = await env();
  const t = await token(await sha256hex(PASSWORD), "a.seeper-labs.com");
  const r = await handle(req("/", { headers: { cookie: `x=1; ${COOKIE}=${t}` } }), e, ok, LOGIN);
  assert.equal(await r.text(), "SITE");
});

test("a cookie from another host is refused", async () => {
  const e = await env();
  const t = await token(await sha256hex(PASSWORD), "b.seeper-labs.com");
  const r = await handle(req("/", { headers: { cookie: `${COOKIE}=${t}` } }), e, ok, LOGIN);
  assert.match(await r.text(), /LOGIN/);
});

test("a plain ACME token path passes for a non HTML file", async () => {
  const r = await handle(req("/.well-known/acme-challenge/abc_DEF-1"), await env(), file, LOGIN);
  assert.equal(await r.text(), "token-body");
});

test("ACME path answered with HTML is 404", async () => {
  const r = await handle(req("/.well-known/acme-challenge/abc"), await env(), ok, LOGIN);
  assert.equal(r.status, 404);
});

test("any other .well-known path is 404, traversal included", async () => {
  for (const p of ["/.well-known/x", "/.well-known/acme-challenge/..%2fsecret", "/.well-known/acme-challenge/a/b"]) {
    const r = await handle(req(p), await env(), file, LOGIN);
    assert.equal(r.status, 404, p);
  }
});

test("dev password is used only when SITE_GATE is absent", async () => {
  const local = new Request("http://localhost:8788/__auth", { method: "POST", body: new URLSearchParams({ p: "dev" }) });
  const dev = await handle(local, { SITE_GATE_DEV_PASSWORD: "dev" }, ok, LOGIN);
  assert.equal(dev.status, 303);
  const both = await handle(post("dev"), { ...(await env()), SITE_GATE_DEV_PASSWORD: "dev" }, ok, LOGIN);
  assert.equal(both.status, 401);
});

test("dev password is ignored on any host but localhost", async () => {
  const r = await handle(post("dev"), { SITE_GATE_DEV_PASSWORD: "dev" }, ok, LOGIN);
  assert.equal(r.status, 503);
});
