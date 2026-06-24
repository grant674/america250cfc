// ============================================================
// America250 CFC — Admin: update application status
// Lets the admin override the AI screening verdict (approve a
// flagged app, reject a passing one, send to judging, etc.).
// Verifies the admin cookie, then PATCHes via service-role.
// Writes an audit_log row for every status change.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

function constantTimeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const ALLOWED_STATUSES = new Set([
  "submitted",
  "screened",
  "flagged",
  "rejected",
  "approved",
  "in_judging",
  "finalist",
  "winner",
  "archived",
]);

function adminToken(password) {
  // Cookie = HMAC-SHA256( NN_AUTH_SECRET, "nn-admin-v1:" + password ).
  // Knowing the password alone isn't enough to forge a cookie — also need
  // the server-side secret. See netlify/edge-functions/auth.ts for the
  // rationale (defense in depth against password-leak cookie forgery).
  const secret = process.env.NN_AUTH_SECRET;
  if (!secret) throw new Error("NN_AUTH_SECRET not configured");
  return createHmac("sha256", secret).update("nn-admin-v1:" + password).digest("hex");
}

function parseCookieValues(cookieHeader, name) {
  // Return EVERY value for `name` in the Cookie header. Browsers usually
  // send one, but RFC 6265 permits multiple, and a hostile party who can
  // plant a cookie via tossing could prepend a junk value. Collect all and
  // let the caller accept any that validates against the expected token.
  if (!cookieHeader) return [];
  const re = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`, "g");
  const out = [];
  let m;
  while ((m = re.exec(cookieHeader)) !== null) {
    if (m[1] && m[1].length > 0) out.push(m[1]);
  }
  return out;
}
// Constant-time: walk all candidates even after a hit so timing reveals
// only the count, not which (or whether) one matched.
function anyConstantTimeEq(candidates, expected) {
  let found = false;
  for (const c of candidates) {
    if (constantTimeEq(c, expected)) found = true;
  }
  return found;
}

function noStoreHeaders() {
  return {
    "Cache-Control": "private, no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Cookie",
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
  };
}


// Origin/Referer enforcement (defense-in-depth against CSRF).
// SameSite=Strict on the admin cookie should already prevent a cross-site
// browser from sending it, but a belt-and-suspenders Origin check stops
// any request that explicitly declares a foreign origin from reaching the
// service-role mutation path. Missing both headers is allowed — that's
// the curl/server-to-server case which still has to clear the cookie check.
const ALLOWED_ORIGIN = "https://america250cfc.org";
function originAllowed(event) {
  const headers = event.headers || {};
  const origin = headers.origin || headers.Origin || "";
  const referer = headers.referer || headers.Referer || "";
  if (origin) return origin === ALLOWED_ORIGIN;
  if (referer) return referer === ALLOWED_ORIGIN || referer.startsWith(ALLOWED_ORIGIN + "/");
  return true; // no Origin & no Referer → not a browser request, cookie check still gates
}

export const handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: noStoreHeaders(), body: JSON.stringify({ error: "method not allowed" }) };
  }
  if (!SUPABASE_SERVICE_ROLE_KEY) return { statusCode: 500, body: "Missing SUPABASE_SERVICE_ROLE_KEY" };
  if (!ADMIN_PASSWORD) return { statusCode: 500, body: "Missing ADMIN_PASSWORD" };

  const candidates = parseCookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyConstantTimeEq(candidates, adminToken(ADMIN_PASSWORD))) {
    return { statusCode: 401, headers: noStoreHeaders(), body: JSON.stringify({ error: "unauthorized" }) };
  }
  if (!originAllowed(event)) {
    return { statusCode: 403, headers: noStoreHeaders(), body: JSON.stringify({ error: "forbidden_origin" }) };
  }

  let payload;
  try { payload = JSON.parse(event.body || "{}"); }
  catch { return { statusCode: 400, headers: noStoreHeaders(), body: JSON.stringify({ error: "invalid json" }) }; }
  // Reject anything that isn't a plain object so we can safely destructure.
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return { statusCode: 400, headers: noStoreHeaders(), body: JSON.stringify({ error: "invalid payload" }) };
  }

  const { id, status } = payload;
  if (!id || typeof id !== "string" || !UUID_RE.test(id)) {
    return { statusCode: 400, headers: noStoreHeaders(), body: JSON.stringify({ error: "invalid id" }) };
  }
  if (!ALLOWED_STATUSES.has(status)) {
    return { statusCode: 400, headers: noStoreHeaders(), body: JSON.stringify({ error: "invalid status" }) };
  }

  // Fetch the old status so we can record it in audit_log
  let oldStatus = null;
  try {
    const lookup = await fetch(
      `${SUPABASE_URL}/rest/v1/applications?id=eq.${encodeURIComponent(id)}&select=status`,
      { headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` } },
    );
    if (lookup.ok) {
      const rows = await lookup.json();
      oldStatus = rows[0]?.status ?? null;
    }
  } catch (_) { /* non-fatal */ }

  const res = await fetch(`${SUPABASE_URL}/rest/v1/applications?id=eq.${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify({ status }),
  });

  if (!res.ok) {
    const errText = await res.text();
    console.error("Supabase update failed:", res.status, errText);
    return { statusCode: 502, headers: noStoreHeaders(), body: JSON.stringify({ error: "update failed", detail: errText }) };
  }

  // Audit log — every status override is recorded.
  fetch(`${SUPABASE_URL}/rest/v1/audit_log`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify({
      actor: "admin",
      action: "status_override",
      target_table: "applications",
      target_id: id,
      before_data: oldStatus ? { status: oldStatus } : null,
      after_data: { status },
    }),
  }).catch((err) => console.error("audit_log insert failed (non-fatal):", err));

  return { statusCode: 200, headers: noStoreHeaders(), body: JSON.stringify({ ok: true, id, status }) };
};
