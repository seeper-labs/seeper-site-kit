// Shared password gate for Seeper sites. One password for every Labs site: its SHA-256 sits in the
// shared KV namespace labs-site-gate (binding SITE_GATE, key password-sha256), so rotating it is one
// KV write and needs no redeploy. Limits: one password for everyone, no per person revocation, no
// record of who looked. When a site needs real access control, put Cloudflare Access in front.
//
// This file is copied verbatim into each site's functions/_middleware.js by `site-kit build`, so it
// must stay self contained: no imports.

export const COOKIE = "seeper_site_auth";
const LABEL = "seeper-site-auth-v1";
const MAX_AGE = 604800; // seven days
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

export async function sha256hex(text) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

// The cookie is an HMAC of a fixed label keyed by the hash and bound to this host, so it is no use
// on another Seeper site and reveals nothing about the password.
export async function token(hash, host) {
  const key = await crypto.subtle.importKey("raw", enc.encode(hash), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(LABEL + "|" + host)));
}

// No early return on length, so timing leaks nothing.
function same(a, b) {
  const x = enc.encode(a || ""), y = enc.encode(b || "");
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

// Paths an agent may reach with a bearer instead of the password (package.json kit.bearerPaths), such
// as a deck's comments API. Whole segment prefixes on the parsed path; anything with an encoded
// separator is refused, because the asset server decodes %2f. An unset secret opens nothing.
const BEARER_RE = /^Bearer ([^\s]+)$/;
function bearerAllowed(request, url, env, prefixes) {
  const secret = String(env.SITE_GATE_BEARER || "");
  if (!prefixes || !prefixes.length || !secret) return false;
  const path = url.pathname;
  if (/%2f|%5c|\\/i.test(path)) return false;
  if (!prefixes.some((p) => path === p || path.startsWith(p.replace(/\/$/, "") + "/"))) return false;
  const m = (request.headers.get("authorization") || "").match(BEARER_RE);
  return !!m && same(m[1], secret);
}

const COOKIE_RE = new RegExp(`(?:^|;\\s*)${COOKIE}=([a-f0-9]+)`);
const ACME_RE = /^\/\.well-known\/acme-challenge\/[A-Za-z0-9_-]+$/;
const ERROR_HTML = '<div class="err" role="alert">Not that one</div>';

function plain(status, text) {
  return new Response(text, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
}

function login(loginHtml, error) {
  return new Response(loginHtml.replace("<!--gate:error-->", error ? ERROR_HTML : ""), {
    status: error ? 401 : 200,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex, nofollow, noarchive" },
  });
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// The dev password exists for `site-kit dev` only. It is ignored on any real host, so a config file
// that drops the KV binding in production cannot leave a site behind the word "dev".
async function storedHash(env, hostname) {
  if (env.SITE_GATE) return (await env.SITE_GATE.get("password-sha256")) || null;
  if (env.SITE_GATE_DEV_PASSWORD && LOCAL_HOSTS.has(hostname)) return sha256hex(String(env.SITE_GATE_DEV_PASSWORD).trim());
  return null;
}

export async function handle(request, env, next, loginHtml, opts = {}) {
  const url = new URL(request.url);

  // Certificate probes must not get the login page. Only a plain ACME token path may pass: the asset
  // server decodes %2f and resolves "..", and answers unknown paths with index.html, so anything
  // looser, or an HTML answer, could leak a gated file.
  if (url.pathname.startsWith("/.well-known/")) {
    if (!ACME_RE.test(url.pathname)) return plain(404, "Not found");
    const probe = await next();
    const type = probe.headers.get("content-type") || "";
    return probe.status === 200 && !type.includes("text/html") ? probe : plain(404, "Not found");
  }

  const hash = await storedHash(env, url.hostname);
  if (!hash) return plain(503, "Site password is not configured.");
  if (bearerAllowed(request, url, env, opts.bearerPaths)) return next();
  const expected = await token(hash, url.host);

  if (url.pathname === "/__auth" && request.method === "POST") {
    const form = await request.formData();
    // trim: a password pasted from a password manager often carries a space or a line break
    const given = await sha256hex(String(form.get("p") || "").trim());
    if (!same(given, hash)) return login(loginHtml, true);
    return new Response(null, { status: 303, headers: {
      location: "/", "cache-control": "no-store",
      "set-cookie": `${COOKIE}=${expected}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}` } });
  }

  const m = (request.headers.get("cookie") || "").match(COOKIE_RE);
  if (m && same(m[1], expected)) return next();
  return login(loginHtml, false);
}
