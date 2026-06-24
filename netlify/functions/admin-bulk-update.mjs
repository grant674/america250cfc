// ============================================================
// America250 CFC — Admin: bulk status update
// Admin-cookie gated. POST { ids: [uuid...], status }.
// Updates many applications' status in one call. The BEFORE/AFTER UPDATE
// trigger on `applications` records each status change in audit_log.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ALLOWED_ORIGIN = "https://america250cfc.org";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ALLOWED_STATUSES = new Set(["submitted", "screened", "flagged", "rejected", "approved", "in_judging", "finalist", "winner", "archived"]);
const MAX_IDS = 500;

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
function anyEq(c, e) { let f = false; for (const x of c) if (constantTimeEq(x, e)) f = true; return f; }
const noStore = { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY" };

export const handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: noStore, body: JSON.stringify({ error: "method_not_allowed" }) };
  if (!SUPABASE_SERVICE_ROLE_KEY || !ADMIN_PASSWORD) return { statusCode: 500, headers: noStore, body: JSON.stringify({ error: "not_configured" }) };

  const cands = cookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyEq(cands, adminToken(ADMIN_PASSWORD))) return { statusCode: 401, headers: noStore, body: JSON.stringify({ error: "unauthorized" }) };
  const origin = event.headers.origin || event.headers.Origin || "";
  if (origin && origin !== ALLOWED_ORIGIN) return { statusCode: 403, headers: noStore, body: JSON.stringify({ error: "forbidden_origin" }) };

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "bad_json" }) }; }
  const status = body.status;
  const ids = Array.isArray(body.ids) ? body.ids : [];
  if (!ALLOWED_STATUSES.has(status)) return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "invalid_status" }) };
  // De-dupe + validate every id is a UUID. Reject the whole batch on any bad id.
  const clean = [...new Set(ids)];
  if (clean.length === 0) return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "no_ids" }) };
  if (clean.length > MAX_IDS) return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "too_many", max: MAX_IDS }) };
  if (!clean.every((id) => typeof id === "string" && UUID_RE.test(id))) return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "invalid_id" }) };

  const inList = clean.map((id) => `"${id}"`).join(",");
  const res = await fetch(`${SUPABASE_URL}/rest/v1/applications?id=in.(${inList})`, {
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
    console.error("bulk update failed:", res.status, await res.text());
    return { statusCode: 502, headers: noStore, body: JSON.stringify({ error: "update_failed" }) };
  }
  return { statusCode: 200, headers: noStore, body: JSON.stringify({ ok: true, updated: clean.length, status }) };
};
