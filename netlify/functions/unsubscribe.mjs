// ============================================================
// America250 CFC — Email unsubscribe (one-click + link)
// Recipients reach this from the footer link / List-Unsubscribe header
// of our transactional emails. The link carries the recipient address (e)
// and an HMAC token (t) signed with NN_AUTH_SECRET, so a recipient can only
// unsubscribe their OWN address (no enumeration / forging arbitrary opt-outs).
//
// On a valid request we upsert the address into `email_suppressions`
// (service-role only table). Any program-update / marketing send checks that
// list before sending. Transactional notices (the submission confirmation and
// finalist/winner outcome emails) are sent regardless, but all carry this link
// so recipients can opt out of future non-essential mail.
//
// GET  → records the opt-out and returns a branded confirmation page (link click).
// POST → one-click unsubscribe per RFC 8058 (List-Unsubscribe-Post); returns 200.
// This path is excluded from the site password gate (all /.netlify/functions/*).
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function unsubToken(email) {
  const secret = process.env.NN_AUTH_SECRET;
  if (!secret) throw new Error("NN_AUTH_SECRET not configured");
  return createHmac("sha256", secret).update("nn-unsub-v1:" + email).digest("hex");
}
function constantTimeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a, "utf8"), bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

const HTML_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

function page(title, message) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${esc(title)} — America250 Community Futures Challenge</title>
<style>
  body { font-family: "Lato", -apple-system, "Helvetica Neue", Helvetica, Arial, sans-serif; color: #000; background: #F1F1F2; margin: 0; padding: 0; }
  .wrap { max-width: 520px; margin: 0 auto; padding: 64px 24px; }
  .card { background: #fff; border: 1px solid rgba(0,0,0,0.08); border-radius: 6px; padding: 36px 32px; }
  .rule { display: block; width: 48px; height: 3px; background: #8C1D40; margin: 0 0 18px; }
  h1 { font-weight: 700; font-size: 22px; line-height: 1.25; margin: 0 0 14px; color: #1B459B; }
  p { font-size: 15px; line-height: 1.6; margin: 0 0 14px; }
  .muted { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; color: rgba(0,0,0,0.55); text-align: center; margin-top: 24px; }
  a { color: #1B459B; }
</style></head>
<body><div class="wrap"><div class="card">
  <span class="rule"></span>
  <h1>${esc(title)}</h1>
  ${message}
</div>
<p class="muted">A program of PMI U.S. &nbsp;·&nbsp; america250cfc.org</p>
</div></body></html>`;
}

async function suppress(email, userAgent) {
  // Upsert (idempotent) — repeat unsubscribes succeed quietly.
  const res = await fetch(`${SUPABASE_URL}/rest/v1/email_suppressions?on_conflict=email`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "resolution=merge-duplicates,return=minimal",
    },
    body: JSON.stringify({
      email,
      source: "email_link",
      user_agent: String(userAgent || "").slice(0, 400),
    }),
  });
  if (!res.ok && res.status !== 409) {
    const detail = await res.text();
    console.error("email_suppressions upsert failed:", res.status, detail);
    return false;
  }
  return true;
}

export const handler = async (event) => {
  const method = event.httpMethod;
  if (method !== "GET" && method !== "POST") {
    return { statusCode: 405, headers: HTML_HEADERS, body: page("Unsupported request", "<p>This link only handles unsubscribe requests.</p>") };
  }
  if (!SUPABASE_SERVICE_ROLE_KEY) {
    return { statusCode: 500, headers: HTML_HEADERS, body: page("Temporarily unavailable", "<p>We couldn't process this right now. Please email <a href=\"mailto:privacy@america250cfc.org\">privacy@america250cfc.org</a> and we'll take care of it.</p>") };
  }

  const q = event.queryStringParameters || {};
  const email = typeof q.e === "string" ? q.e.trim().toLowerCase() : "";
  const token = typeof q.t === "string" ? q.t : "";

  const valid = EMAIL_RE.test(email) && email.length <= 254 &&
    /^[0-9a-f]{64}$/i.test(token) && constantTimeEq(token, unsubToken(email));

  if (!valid) {
    // Don't reveal whether the address exists; just guide them to the manual path.
    const body = page(
      "We couldn't verify that link",
      "<p>This unsubscribe link looks invalid or expired. To opt out of program emails, write to <a href=\"mailto:privacy@america250cfc.org\">privacy@america250cfc.org</a> and we'll remove you right away.</p>"
    );
    // One-click POST clients expect a 2xx; still return 200 so the client shows success-neutral.
    return { statusCode: method === "POST" ? 200 : 400, headers: HTML_HEADERS, body };
  }

  const h = event.headers || {};
  const ok = await suppress(email, h["user-agent"] || h["User-Agent"]);

  if (method === "POST") {
    // RFC 8058 one-click: a 2xx with no body is sufficient.
    return { statusCode: ok ? 200 : 502, headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" }, body: ok ? "unsubscribed" : "error" };
  }

  if (!ok) {
    return { statusCode: 502, headers: HTML_HEADERS, body: page("Something went wrong", "<p>We couldn't complete your request. Please email <a href=\"mailto:privacy@america250cfc.org\">privacy@america250cfc.org</a> and we'll remove you right away.</p>") };
  }

  return {
    statusCode: 200,
    headers: HTML_HEADERS,
    body: page(
      "You've been unsubscribed.",
      `<p><strong>${esc(email)}</strong> will no longer receive program-update emails from the America250 Community Futures Challenge.</p>
       <p>You may still receive essential messages tied to an application you submitted (for example, a submission confirmation or a finalist/winner notice).</p>
       <p>Changed your mind, or need anything else? Write <a href="mailto:privacy@america250cfc.org">privacy@america250cfc.org</a>.</p>`
    ),
  };
};
