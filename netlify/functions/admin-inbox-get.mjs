// ============================================================
// America250 CFC — Admin: get one inbox email (full body)
// GET ?id=<uuid>
// Returns the full inbound row + any outbound replies linked to it.
// Cookie-gated by admin password.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function constantTimeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
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
function jsonResponse(s, b) {
  return { statusCode: s, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }, body: JSON.stringify(b) };
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
  if (!SUPABASE_SERVICE_ROLE_KEY) return jsonResponse(500, { error: "config" });
  if (!ADMIN_PASSWORD) return jsonResponse(500, { error: "config" });

  const candidates = parseCookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyConstantTimeEq(candidates, adminToken(ADMIN_PASSWORD))) {
    return jsonResponse(401, { error: "unauthorized" });
  }
  if (!originAllowed(event)) {
    return jsonResponse(403, { error: "forbidden_origin" });
  }

  const id = (event.queryStringParameters || {}).id || "";
  if (!UUID_RE.test(id)) return jsonResponse(400, { error: "invalid_id" });

  const sbHeaders = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
  };

  const [emailRes, repliesRes] = await Promise.all([
    fetch(`${SUPABASE_URL}/rest/v1/inbound_emails?id=eq.${encodeURIComponent(id)}&select=*`, { headers: sbHeaders }),
    fetch(`${SUPABASE_URL}/rest/v1/outbound_replies?in_reply_to_id=eq.${encodeURIComponent(id)}&select=*&order=sent_at.asc`, { headers: sbHeaders }),
  ]);

  if (!emailRes.ok) return jsonResponse(502, { error: "fetch_failed" });
  const email = (await emailRes.json())[0];
  if (!email) return jsonResponse(404, { error: "not_found" });
  const replies = repliesRes.ok ? await repliesRes.json() : [];

  // Don't ship raw_payload back to the client — it's debugging-only and bulky.
  delete email.raw_payload;

  return jsonResponse(200, { email, replies });
};
