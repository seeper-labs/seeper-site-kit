import { readFile } from "node:fs/promises";
import { relative } from "node:path";
import { files } from "./walk.mjs";
import { isText } from "./text.mjs";

// Published files must never carry internal addresses, hostnames, paths or credentials.
// Addresses, hostnames and paths are printed whole so a false positive can be put in kit.qaAllow;
// anything secret shaped is cut short, so a real credential never lands whole in a build log.
// Hostnames and paths count only where text or a URL would put them (after a space, a quote, //,
// @ or >, and followed by a space, a quote, a port, a path or a full stop), so JavaScript property
// access is not a hostname.
const AT = String.raw`(?<=^|[\s"'\x60/@>(])`;
const RULES = [
  { what: "private IP address", re: /\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2})\b/g },
  { what: "internal hostname", re: new RegExp(String.raw`(?<![\w$.-])(?<=^|[\s"'\x60/@>])[a-z0-9][a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:lan|see|internal|local|ts\.net)(?=$|[\s"'\x60:/<]|\.(?:\s|$))`, "gim") },
  { what: "home directory path", re: new RegExp(AT + String.raw`\/(?:(?:home|Users)\/[A-Za-z0-9._-]+|root)\/`, "g") },
  { what: "GitHub token", secret: true, re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g },
  { what: "AWS access key", secret: true, re: /\bAKIA[0-9A-Z]{16}\b/g },
  { what: "Slack token", secret: true, re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { what: "API key", secret: true, re: /\b(?:sk-[A-Za-z0-9_-]{20,}|[sr]k_live_[A-Za-z0-9]{20,})\b/g },
  { what: "Google API key", secret: true, re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { what: "JSON web token", secret: true, re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { what: "private key", secret: true, re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { what: "1Password reference", secret: true, re: /\bop:\/\/[^\s"'<>]+/g },
];

const shown = (m, secret) => (secret && m.length > 12 ? m.slice(0, 12) + "…" : m);

export async function check(site, cfg) {
  const allow = new Set(cfg.qaAllow || []);
  const problems = [];
  for await (const f of files(site)) {
    if (!(await isText(f))) continue;
    const text = await readFile(f, "utf8");
    for (const { what, re, secret } of RULES) {
      for (const m of text.matchAll(re)) {
        if (!allow.has(m[0])) problems.push(`${relative(site, f)}: ${what} "${shown(m[0], secret)}"`);
      }
    }
  }
  return problems;
}
