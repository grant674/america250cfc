// ============================================================
// America250 CFC — Admin: update inbox row state
// POST { id, action: 'mark_read' | 'mark_unread' | 'archive' | 'unarchive' | 'mark_spam' }
// Verifies admin cookie. PATCHes inbound_emails via service_role.
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

const ACTIONS = {
  mark_read:   () => ({ status: "read",     read_at: new Date().toISOString() }),
  mark_unread: () => ({ status: "unread",   read_at: null }),
  archive:     () => ({ status: "archived", archived_at: new Date().toISOString() }),
  unarchive:   () => ({ status: "unread",   archived_at: null }),
  mark_spam:   () => ({ status: "spam" }),
};


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
  if (event.httpMethod !== "POST") return jsonResponse(405, { error: "method_not_allowed" });

  const candidates = parseCookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyConstantTimeEq(candidates, adminToken(ADMIN_PASSWORD))) {
    return jsonResponse(401, { error: "unauthorized" });
  }
  if (!originAllowed(event)) {
    return jsonResponse(403, { error: "forbidden_origin" });
  }

  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return jsonResponse(400, { error: "invalid_json" }); }
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse(400, { error: "invalid_payload" });
  }

  const id = String(body.id || "");
  if (!UUID_RE.test(id)) return jsonResponse(400, { error: "invalid_id" });

  const action = String(body.action || "");
  const builder = ACTIONS[action];
  if (!builder) return jsonResponse(400, { error: "invalid_action" });

  const patch = builder();
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/inbound_emails?id=eq.${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify(patch),
    }
  );
  if (!res.ok) {
    const t = await res.text();
    return jsonResponse(502, { error: "update_failed", detail: t });
  }
  return jsonResponse(200, { ok: true, id, action });
};
