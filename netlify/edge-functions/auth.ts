// ============================================================
// America250 Community Futures Challenge — Two-tier password gate
//
// Tier 1 — Site gate.   Cookie nn_auth.   Password from SITE_PASSWORD env var.
//                       Protects everything except excluded paths and /admin/*.
//
// Tier 2 — Admin gate.  Cookie nn_admin.  Password from ADMIN_PASSWORD env var.
//                       Protects /admin/* exclusively.
//
// Both gates use session-only cookies (no Max-Age/Expires) — they die when the
// browser session ends. Authenticated responses ship with Cache-Control: no-store
// so neither browser nor CDN holds the auth state.
// ============================================================

import type { Config, Context } from "https://edge.netlify.com";

// No hardcoded fallback — the gate fails closed if SITE_PASSWORD is unset.
// Passwords live only in Netlify env vars (SITE_PASSWORD / ADMIN_PASSWORD);
// never hardcode or document them in source.
const SITE_COOKIE = "nn_auth";
const ADMIN_COOKIE = "nn_admin";

// Canonical host. Any request for another host (alias domain) is 301'd here
// before the gate runs — so nextnow250.org and america250cfc.com/.net all
// land cleanly on the new primary.
const CANONICAL_HOST = "america250cfc.org";

// Constant-time string comparison — never short-circuit on first mismatch.
// Defends against timing attacks that measure per-byte response time.
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Still walk the longer string to keep timing roughly constant.
    let dummy = 0;
    for (let i = 0; i < Math.max(a.length, b.length); i++) dummy |= 1;
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// Session-token derivation.
//
// Cookie = HMAC-SHA256( NN_AUTH_SECRET,  scope + ":" + password )
//
// Why: an earlier scheme used the password itself as the HMAC key, so anyone
// who learned the password could compute a valid cookie offline and skip the
// brute-force-delayed /__auth and /__admin_auth endpoints entirely. Keying the
// HMAC on a server-side secret means a password leak alone is no longer enough
// to forge a cookie — an attacker would also need to compromise the env vars.
async function sessionToken(
  serverSecret: string,
  scope: string,
  password: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(serverSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(scope + ":" + password),
  );
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Extract every value for a cookie name from a single Cookie header.
//
// Why all values, not just the first: RFC 6265 §5.4 lets a client send
// multiple cookies with the same name (one per scope/domain/path), and
// while browsers usually send only one, a hostile party who can plant a
// cookie via cookie tossing (e.g. from a sibling Netlify-app subdomain
// before this domain pinned cookies to its own host) could force a stale
// or empty value to appear first. If we accept only the first match, the
// attacker can lock the victim out (DoS) or, in some patterns, downgrade
// auth. By collecting all values and accepting any that validates, we
// tolerate the noise without weakening the check itself.
function getCookieValues(header: string, name: string): string[] {
  if (!header) return [];
  const re = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`, "g");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(header)) !== null) {
    if (m[1] && m[1].length > 0) out.push(m[1]);
  }
  return out;
}

// Constant-time check: does any value in `candidates` match `expected`?
// Walk every candidate even after a hit so timing reveals only the
// number of candidates, not which (or whether) one matched.
function anyTimingSafeEqual(candidates: string[], expected: string): boolean {
  let found = false;
  for (const c of candidates) {
    if (timingSafeEqual(c, expected)) found = true;
  }
  return found;
}

function safeReturnTo(raw: string | null, defaultPath: string): string {
  if (!raw) return defaultPath;
  // Must be a same-origin absolute path. Reject anything whose second
  // character is "/" or "\\": browsers normalize "/\\" to "//", so a value
  // like "/\\evil.com" would otherwise be issued as a protocol-relative
  // Location and redirect off-site (open redirect / phishing). Also reject
  // control characters that could smuggle a scheme or split the header.
  if (!raw.startsWith("/")) return defaultPath;
  if (raw.length >= 2 && (raw[1] === "/" || raw[1] === "\\")) return defaultPath;
  if (/[\u0000-\u001f\u007f]/.test(raw)) return defaultPath;
  return raw;
}

function noStore(headers: Headers) {
  headers.set("Cache-Control", "private, no-store, no-cache, must-revalidate, max-age=0");
  headers.set("Pragma", "no-cache");
  headers.set("Expires", "0");
  headers.set("Vary", "Cookie");
  headers.set("Netlify-CDN-Cache-Control", "no-store");
  headers.set("CDN-Cache-Control", "no-store");
  // Belt-and-suspenders HSTS — netlify.toml also sets this on static
  // responses, but the edge function bypasses the toml header pipeline.
  // 2 years + subdomains + preload (matches netlify.toml).
  headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
}

// Brute-force soft delay — a fixed sleep on every failed auth attempt
// shifts the cost of guessing to the attacker. Doesn't stop a parallel
// botnet (Cloudflare WAF rules would), but raises the bar against a single
// attacker by ~1000x vs. the baseline (~30 req/sec → ~0.7 req/sec/conn).
async function authFailDelay(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 1200));
}

const GATE_CSP = [
  "default-src 'self'",
  "img-src 'self' data:",
  "font-src 'self' https://fonts.gstatic.com data:",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "script-src 'none'",
  "connect-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "object-src 'none'",
].join("; ");

interface GateOpts {
  variant: "site" | "admin";
  error?: string;
  returnTo: string;
}

function gateHtml(opts: GateOpts): string {
  const safe = (s: string) =>
    s.replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  const isAdmin = opts.variant === "admin";
  const title = isAdmin
    ? "America250 CFC — Admin"
    : "America250 CFC — Restricted preview";
  const heading = isAdmin
    ? "Admin dashboard"
    : "This is a private preview";
  const body = isAdmin
    ? "Enter the admin password to view applications, AI screening results, and live program metrics."
    : "Enter the password to view the preview site. The password expires when this browser session ends.";
  const action = isAdmin ? "/__admin_auth" : "/__auth";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<title>${title}</title>
<meta name="description" content="America250 Community Futures Challenge — a national platform from PMI U.S." />
<meta name="robots" content="noindex,nofollow" />
<meta name="theme-color" content="#1B459B" />
<meta property="og:title" content="${title}" />
<meta property="og:description" content="A national open call from PMI U.S. Five winners. $250,000 in grants. Submissions open Jun 2026." />
<meta property="og:type" content="website" />
<meta property="og:url" content="https://america250cfc.org${safe(opts.returnTo)}" />
<meta property="og:image" content="https://america250cfc.org/assets/og-image.jpg" />
<meta property="og:image:width" content="1200" />
<meta property="og:image:height" content="630" />
<meta property="og:image:alt" content="America250 Community Futures Challenge — a program of PMI U.S." />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="${title}" />
<meta name="twitter:description" content="A national open call from PMI U.S. Five winners. $250,000 in grants." />
<meta name="twitter:image" content="https://america250cfc.org/assets/og-image.jpg" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&display=swap" />
<style>
:root {
  --c-red:#8C1D40; --c-yellow:#F2D42B; --c-blue:#1B459B;
  --c-black:#000; --c-gray:#F1F1F2; --c-white:#fff;
  --fg-65:rgba(0,0,0,0.65); --line:rgba(0,0,0,0.07); --line-strong:rgba(0,0,0,0.20);
}
*, *::before, *::after { box-sizing: border-box; }
html, body { margin: 0; padding: 0; height: 100%; }
body {
  background: var(--c-blue);
  color: var(--c-black);
  font-family: "Lato", -apple-system, "Helvetica Neue", Arial, sans-serif;
  font-weight: 400;
  display: flex; align-items: center; justify-content: center;
  padding: 32px 20px; min-height: 100dvh;
}
.gate {
  width: 100%; max-width: 460px;
  background: var(--c-white);
  border-radius: 6px;
  padding: clamp(28px, 5vw, 40px);
}
.gate__brand { margin-bottom: 24px; }
.gate__brand img { display: block; height: 44px; width: auto; }
.rule-bar { display: block; width: 48px; height: 3px; background: var(--c-red); margin: 0 0 14px; }
.eyebrow {
  display: inline-block;
  font-weight: 700; font-size: 11px;
  letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--c-red); margin-bottom: 10px;
}
h1 {
  font-family: "Lato", sans-serif;
  font-weight: 700;
  font-size: clamp(24px, 4vw, 30px);
  line-height: 1.2;
  margin: 0 0 14px;
  color: var(--c-blue);
}
p {
  font-size: 15px; line-height: 1.55;
  color: var(--fg-65);
  margin: 0 0 24px;
  max-width: 42ch;
}
form { display: flex; flex-direction: column; gap: 10px; }
label {
  font-size: 11px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--c-black);
  font-weight: 700;
}
input[type="password"] {
  font: inherit; font-size: 16px;
  padding: 11px 14px;
  background: var(--c-white);
  border: 1px solid var(--line-strong);
  color: var(--c-black);
  border-radius: 6px;
  width: 100%; min-height: 44px;
  -webkit-appearance: none;
  transition: border-color 160ms ease, box-shadow 160ms ease;
}
input[type="password"]:focus {
  outline: none;
  border-color: var(--c-blue);
  box-shadow: 0 0 0 3px rgba(27,69,155,0.18);
}
button {
  font: inherit; cursor: pointer;
  padding: 13px 22px;
  background: var(--c-blue);
  color: var(--c-white);
  border: 0;
  border-radius: 6px;
  font-weight: 700;
  font-size: 13px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  transition: background 160ms cubic-bezier(0.2, 0.7, 0.2, 1);
  margin-top: 6px;
  min-height: 48px;
}
button:hover { background: #143577; }
.err {
  color: var(--c-red);
  font-size: 13px;
  margin-top: 4px;
  font-weight: 700;
}
.foot {
  margin-top: 28px;
  padding-top: 16px;
  border-top: 1px solid var(--line);
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--fg-65);
  line-height: 1.5;
}
</style>
</head>
<body>
  <main class="gate">
    <div class="gate__brand">
      <img src="/assets/pmi250-color.png" alt="PMI U.S. AMERICA 250" />
    </div>
    <span class="rule-bar" aria-hidden="true"></span>
    <h1>${heading}</h1>
    <p>${body}</p>
    <form method="post" action="${action}" autocomplete="off">
      <label for="pw">Password</label>
      <input id="pw" name="password" type="password" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" required autofocus />
      <input type="hidden" name="returnTo" value="${safe(opts.returnTo)}" />
      ${opts.error ? `<div class="err">${safe(opts.error)}</div>` : ""}
      <button type="submit">Continue →</button>
    </form>
    <div class="foot">America250 Community Futures Challenge &nbsp;·&nbsp; A program of PMI U.S.</div>
  </main>
</body>
</html>`;
}

function gateResponse(opts: GateOpts): Response {
  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": GATE_CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
  });
  noStore(headers);
  return new Response(gateHtml(opts), { status: 401, headers });
}

async function handleAuthSubmit(
  request: Request,
  password: string,
  cookieName: string,
  tokenLabel: string,
  defaultReturn: string,
  variant: "site" | "admin",
  serverSecret: string,
): Promise<Response> {
  const ct = request.headers.get("content-type") || "";
  let submitted = "";
  let returnTo = defaultReturn;

  if (ct.includes("application/x-www-form-urlencoded")) {
    const body = await request.text();
    const params = new URLSearchParams(body);
    submitted = params.get("password") ?? "";
    returnTo = safeReturnTo(params.get("returnTo"), defaultReturn);
  } else if (ct.includes("multipart/form-data")) {
    const form = await request.formData();
    submitted = String(form.get("password") ?? "");
    returnTo = safeReturnTo(String(form.get("returnTo") ?? defaultReturn), defaultReturn);
  }

  if (timingSafeEqual(submitted, password)) {
    const token = await sessionToken(serverSecret, tokenLabel, password);
    const headers = new Headers();
    headers.set(
      "Set-Cookie",
      `${cookieName}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`,
    );
    headers.set("Location", returnTo);
    noStore(headers);
    return new Response(null, { status: 303, headers });
  }

  // Brute-force soft delay before responding to a failed attempt.
  await authFailDelay();
  return gateResponse({ variant, error: "Wrong password.", returnTo });
}

export default async (
  request: Request,
  context: Context,
): Promise<Response | void> => {
  const url = new URL(request.url);

  // -------- Never serve raw function / edge-function source --------
  // The deploy publishes from the site root, which includes the netlify/
  // source tree, so /netlify/functions/*.mjs and /netlify/edge-functions/*.ts
  // would otherwise be downloadable. Block them here (the live-invoke path is
  // the dot-prefixed /.netlify/functions/*, which is unaffected). Runs before
  // the gate so the source is 404 whether or not the password gate is active.
  // (For full post-launch hardening, move static assets into a publish subdir
  // that excludes netlify/.)
  if (
    url.pathname === "/netlify" || url.pathname.startsWith("/netlify/") ||
    url.pathname.startsWith("/db/") || url.pathname === "/README.md" ||
    url.pathname.startsWith("/.git")
  ) {
    return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
  }

  // -------- Canonical-host redirect (runs BEFORE gate) --------
  // If the request hit a non-primary host (any alias), 301 to the canonical
  // host preserving path + query. Defenses below only apply to the canonical
  // host. Skip when running locally on Netlify's preview/dev domains so we
  // don't break deploy-preview URLs.
  const host = url.hostname.toLowerCase();
  const isPreview = host.endsWith(".netlify.app") || host === "localhost";
  if (!isPreview && host !== CANONICAL_HOST) {
    const target = `https://${CANONICAL_HOST}${url.pathname}${url.search}`;
    const headers = new Headers({ Location: target });
    noStore(headers);
    return new Response(null, { status: 301, headers });
  }

  const sitePassword = Deno.env.get("SITE_PASSWORD") ?? "";
  const adminPassword = Deno.env.get("ADMIN_PASSWORD") ?? "";
  const serverSecret = Deno.env.get("NN_AUTH_SECRET") ?? "";

  // SITE_PUBLIC=true disables ONLY the Tier-1 site gate so the site serves
  // publicly (going live). The admin gate (/admin/*), the canonical-host
  // redirect, and the source-file blocking above all stay active. Set this
  // env var + redeploy to launch; remove it to restore the preview gate.
  const sitePublic = (Deno.env.get("SITE_PUBLIC") ?? "").trim().toLowerCase() === "true";

  // Fail-closed: when the site gate is ON (not public), SITE_PASSWORD and
  // NN_AUTH_SECRET must both be configured or we deny everything. When
  // SITE_PUBLIC is set the gate is intentionally off, so a missing
  // SITE_PASSWORD is fine — the admin gate guards itself separately below.
  if (!sitePublic && (!sitePassword || !serverSecret)) {
    return new Response("Auth not configured", {
      status: 503,
      headers: { "Cache-Control": "no-store" },
    });
  }

  // Skip token derivation that isn't needed (and avoid an empty-key HMAC when
  // public with no secret set): the site token is unused in public mode, and
  // both tokens require the server secret.
  const expectedSiteToken = (!sitePublic && serverSecret)
    ? await sessionToken(serverSecret, "nn-session-v1", sitePassword)
    : "";
  const expectedAdminToken = (adminPassword && serverSecret)
    ? await sessionToken(serverSecret, "nn-admin-v1", adminPassword)
    : "";

  // -------- Site auth submit --------
  if (url.pathname === "/__auth" && request.method === "POST") {
    return handleAuthSubmit(request, sitePassword, SITE_COOKIE, "nn-session-v1", "/", "site", serverSecret);
  }

  // -------- Admin auth submit --------
  if (url.pathname === "/__admin_auth" && request.method === "POST") {
    if (!adminPassword) {
      return new Response("Admin password not configured", { status: 503 });
    }
    return handleAuthSubmit(request, adminPassword, ADMIN_COOKIE, "nn-admin-v1", "/admin/", "admin", serverSecret);
  }

  const cookieHeader = request.headers.get("cookie") ?? "";
  const isAdminPath = url.pathname.startsWith("/admin/") || url.pathname === "/admin";

  // -------- /admin/* — admin gate only --------
  if (isAdminPath) {
    if (!adminPassword) {
      return new Response("Admin password not configured", { status: 503 });
    }
    const candidates = getCookieValues(cookieHeader, ADMIN_COOKIE);
    if (!anyTimingSafeEqual(candidates, expectedAdminToken)) {
      return gateResponse({ variant: "admin", returnTo: url.pathname + url.search });
    }
    const response = await context.next();
    const out = new Response(response.body, response);
    noStore(out.headers);
    return out;
  }

  // -------- Public mode (SITE_PUBLIC=true): site gate off --------
  // Step aside so Netlify serves the page with its normal cache headers
  // (netlify.toml). Returning void passes the request through unmodified — no
  // gate, and no forced no-store, so the live site can be CDN-cached. Admin
  // (/admin/*) was already handled above and stays protected.
  if (sitePublic) {
    return;
  }

  // -------- Everything else — site gate --------
  // A valid admin cookie also satisfies the site gate. Admin access is
  // strictly more privileged than site access, and shared assets
  // (/styles.css, /admin/ pulls it in, fonts, etc.) need to load for an
  // admin-only user who hasn't separately entered the site password.
  const siteCandidates  = getCookieValues(cookieHeader, SITE_COOKIE);
  const adminCandidates = getCookieValues(cookieHeader, ADMIN_COOKIE);
  const siteAuthed  = anyTimingSafeEqual(siteCandidates, expectedSiteToken);
  const adminAuthed = expectedAdminToken && anyTimingSafeEqual(adminCandidates, expectedAdminToken);
  if (!siteAuthed && !adminAuthed) {
    return gateResponse({ variant: "site", returnTo: url.pathname + url.search });
  }

  const response = await context.next();
  const out = new Response(response.body, response);
  noStore(out.headers);
  return out;
};

export const config: Config = {
  // Match all paths; check inside the function whether to apply site or admin gate.
  // Excluded: gate-page assets, social previews, and Netlify functions
  // (which protect themselves with their own webhook secrets / admin cookies).
  path: "/*",
  excludedPath: [
    "/favicon.svg",
    "/assets/pmi250-color.png",
    "/assets/pmi250-notag-color.png",
    "/assets/pmi250-white.png",
    "/assets/pmi250-notag-white.png",
    "/assets/pmi250-mark-color.png",
    "/assets/pmi250-mark-white.png",
    "/assets/og-image.jpg",
    "/judge",
    "/judge/*",
    "/.netlify/functions/*",
    "/.well-known/*",
    "/robots.txt",
    "/sitemap.xml",
  ],
};
