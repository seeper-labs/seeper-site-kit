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

// Images served without the password (package.json kit.publicImages), such as the og:image a chat app
// fetches for a link preview with no cookie. Exact paths, GET or HEAD only, and only an image answer
// passes: the asset server answers an unknown path with index.html, which must never leak.
// Conditional and range headers are dropped first. Cloudflare's cache in front of a custom domain
// revalidates with If-None-Match, and the asset server's 304 has no type to check, so without this
// every other request was refused.
const CONDITIONAL = ["if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "if-range", "range"];
async function publicImage(request, url, next, paths) {
  if (!paths || !paths.includes(url.pathname) || !["GET", "HEAD"].includes(request.method)) return null;
  const headers = new Headers(request.headers);
  for (const h of CONDITIONAL) headers.delete(h);
  const r = await next(new Request(request, { headers }));
  const type = r.headers.get("content-type") || "";
  return r.status === 200 && type.startsWith("image/") ? r : plain(404, "Not found");
}

// Large assets (videos, 3D models and the like, over Pages' 25 MiB file limit) live in private object
// storage, not in the site. A signed in visitor asking for /_assets/<path> is redirected to a link
// signed for that one file. The link's time is rounded down to a six hour window so the same file has
// the same address for a while and the browser's cache works; it stays valid for at least six more
// hours, so a paused video can still seek. Plain characters only, so nothing needs URL encoding.
export const ASSETS = "/_assets/";
const ASSET_RE = /^\/_assets\/((?:[A-Za-z0-9_-][A-Za-z0-9._-]*\/)*[A-Za-z0-9_-][A-Za-z0-9._-]*)$/;
const ASSET_WINDOW_S = 21600;
const ASSET_VALID_S = 2 * ASSET_WINDOW_S;

const bytes = (b) => (typeof b === "string" ? enc.encode(b) : b);
async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", bytes(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}

// AWS Signature V4, query string form. B2 speaks it on its S3 compatible endpoint.
export async function signedAssetUrl(cfg, method, key, nowMs) {
  const start = Math.floor(nowMs / 1000 / ASSET_WINDOW_S) * ASSET_WINDOW_S;
  const stamp = new Date(start * 1000).toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const day = stamp.slice(0, 8);
  const scope = `${day}/${cfg.region}/s3/aws4_request`;
  const host = new URL(cfg.endpoint).host;
  const path = `/${cfg.bucket}/${key}`;
  // In canonical order: sorted by name.
  const query = [
    ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
    ["X-Amz-Credential", `${cfg.keyId}/${scope}`],
    ["X-Amz-Date", stamp],
    ["X-Amz-Expires", String(ASSET_VALID_S)],
    ["X-Amz-SignedHeaders", "host"],
  ].map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
  const canonical = [method, path, query, `host:${host}`, "", "host", "UNSIGNED-PAYLOAD"].join("\n");
  const toSign = ["AWS4-HMAC-SHA256", stamp, scope, await sha256hex(canonical)].join("\n");
  let k = await hmac(`AWS4${cfg.secret}`, day);
  for (const part of [cfg.region, "s3", "aws4_request"]) k = await hmac(k, part);
  return `https://${host}${path}?${query}&X-Amz-Signature=${hex(await hmac(k, toSign))}`;
}

function assetConfig(env) {
  const cfg = { keyId: env.SITE_ASSETS_KEY_ID, secret: env.SITE_ASSETS_KEY, bucket: env.SITE_ASSETS_BUCKET,
    endpoint: env.SITE_ASSETS_ENDPOINT, region: env.SITE_ASSETS_REGION, prefix: env.SITE_ASSETS_PREFIX };
  return Object.values(cfg).every(Boolean) ? cfg : null;
}

async function assetRedirect(request, url, env, nowMs) {
  if (!["GET", "HEAD"].includes(request.method)) return plain(405, "Method not allowed");
  const m = url.pathname.match(ASSET_RE);
  if (!m) return plain(404, "Not found");
  const cfg = assetConfig(env);
  if (!cfg) return plain(503, "Large assets are not set up here. They work on the published site and its previews, not in site-kit dev.");
  const target = await signedAssetUrl(cfg, request.method, `${cfg.prefix}${m[1]}`, nowMs);
  return new Response(null, { status: 302, headers: { location: target, "cache-control": "private, max-age=3600", "referrer-policy": "no-referrer" } });
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
  const image = await publicImage(request, url, next, opts.publicImages);
  if (image) return image;
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
  if (m && same(m[1], expected)) {
    return url.pathname.startsWith(ASSETS) ? assetRedirect(request, url, env, opts.now ? opts.now() : Date.now()) : next();
  }
  return login(loginHtml, false);
}
