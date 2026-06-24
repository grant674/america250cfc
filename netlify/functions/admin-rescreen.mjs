// ============================================================
// America250 CFC — Admin: re-run AI screening for one application
// Admin-cookie gated. Re-triggers screen-application for an app that is
// still in an early state (so a manual status decision is never clobbered).
// Useful when initial screening was skipped (rate cap) or errored.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const WEBHOOK_SECRET = process.env.SCREENING_WEBHOOK_SECRET;
const ALLOWED_ORIGIN = "https://america250cfc.org";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Only re-screen apps that haven't been manually advanced through the workflow.
const RESCREENABLE = new Set(["submitted", "screened", "flagged", "rejected"]);

function constantTimeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a, "utf8"), bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
function adminToken(password) {
  const secret = process.env.NN_AUTH_SECRET;
  if (!secret) throw new Error("NN_AUTH_SECRET not configured");
  return createHmac("sha256", secret).update("nn-admin-v1:" + password).digest("hex");
}
function cookieValues(header, name) {
  if (!header) return [];
  const re = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`, "g");
  const out = []; let m;
  while ((m = re.exec(header)) !== null) if (m[1]) out.push(m[1]);
  return out;
}
function anyEq(cands, expected) {
  let found = false;
  for (const c of cands) if (constantTimeEq(c, expected)) found = true;
  return found;
}
const noStore = {
  "Content-Type": "application/json",
  "Cache-Control": "private, no-store, no-cache, must-revalidate, max-age=0",
  "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
};

export const handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: noStore, body: JSON.stringify({ error: "method_not_allowed" }) };
  if (!SUPABASE_SERVICE_ROLE_KEY || !ADMIN_PASSWORD || !WEBHOOK_SECRET)
    return { statusCode: 500, headers: noStore, body: JSON.stringify({ error: "not_configured" }) };

  // Admin cookie
  const cands = cookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyEq(cands, adminToken(ADMIN_PASSWORD)))
    return { statusCode: 401, headers: noStore, body: JSON.stringify({ error: "unauthorized" }) };
  // CSRF: reject a declared foreign origin
  const origin = event.headers.origin || event.headers.Origin || "";
  if (origin && origin !== ALLOWED_ORIGIN)
    return { statusCode: 403, headers: noStore, body: JSON.stringify({ error: "forbidden_origin" }) };

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "bad_json" }) }; }
  const id = typeof body.id === "string" ? body.id : "";
  if (!UUID_RE.test(id)) return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "invalid_id" }) };

  const sb = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` };
  const rowRes = await fetch(`${SUPABASE_URL}/rest/v1/applications?id=eq.${encodeURIComponent(id)}&select=*`, { headers: sb });
  if (!rowRes.ok) return { statusCode: 502, headers: noStore, body: JSON.stringify({ error: "fetch_failed" }) };
  const rows = await rowRes.json();
  const row = Array.isArray(rows) ? rows[0] : null;
  if (!row) return { statusCode: 404, headers: noStore, body: JSON.stringify({ error: "not_found" }) };
  if (!RESCREENABLE.has(row.status))
    return { statusCode: 409, headers: noStore, body: JSON.stringify({ error: "already_advanced", status: row.status }) };

  // Re-trigger the normal screening path (updates ai_screening_* + status by verdict).
  const res = await fetch(`${ALLOWED_ORIGIN}/.netlify/functions/screen-application`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-webhook-secret": WEBHOOK_SECRET },
    body: JSON.stringify({ type: "INSERT", table: "applications", record: row, suppressEmail: true }),
  });
  const detail = await res.text();
  if (!res.ok) {
    console.error("re-screen failed:", res.status, detail);
    return { statusCode: 502, headers: noStore, body: JSON.stringify({ error: "rescreen_failed", status: res.status }) };
  }
  return { statusCode: 200, headers: noStore, body: JSON.stringify({ ok: true }) };
};
