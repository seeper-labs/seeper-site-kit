# seeper-site-kit

The shared parts of every Seeper site on Cloudflare Pages: the password gate and the automatic
checks. Sites made by `seeper-labs/seeper-sites-controller` depend on it by tag:

```json
"dependencies": { "@seeper-labs/site-kit": "github:seeper-labs/seeper-site-kit#v1.0.0" }
```

**This repo is public.** Never add fonts, images, brand assets, internal hostnames, addresses or
secrets. CI refuses them.

## A site's `kit` block in `package.json`

| Key | Required | Meaning |
|---|---|---|
| `build` | yes | The command that builds the site, e.g. `python3 build.py` |
| `output` | no, `site` | The folder that is published |
| `qaAllow` | no, `[]` | Exact strings the leak check should ignore |
| `bearerPaths` | no, `[]` | Path prefixes that also open with `Authorization: Bearer <SITE_GATE_BEARER>` (a Pages secret), for agents calling an API on the site. Pages stay behind the password |

The site also needs `gate/login.html`, its own login page, containing `<!--gate:error-->` where the
"wrong password" message goes. It is served before sign in, so it must not use gated assets.

## Commands

| | |
|---|---|
| `site-kit build` | Run the site's build, then write the gate into `functions/_middleware.js` (git ignore it) |
| `site-kit qa` | Check the built output: broken links and assets, files over 25 MiB, internal addresses, hostnames and credentials |
| `site-kit dev` | Build and serve locally with the real gate; the password is `dev`. A local D1 is bound as `DB`, so comments and live slide variants work (kept in the site's `.wrangler/state`, never the live database) |

Cloudflare builds each site with `npm ci && npx site-kit build && npx site-kit qa`, so a site that
fails a check does not go live.

## The gate

One password for every Labs site. Its SHA-256 sits in the shared KV namespace `labs-site-gate`,
bound to each site as `SITE_GATE`, under `password-sha256`. Rotating the password is one KV write,
with no redeploy. Without the hash the gate serves 503, never the site. A site may also let agents reach listed API paths with a bearer secret (`kit.bearerPaths`); it opens no pages and is not a second password.
