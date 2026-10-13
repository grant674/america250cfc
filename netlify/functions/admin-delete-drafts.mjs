// ============================================================
// America250 CFC — Admin: permanently delete unsubmitted application drafts
// Admin-cookie gated. POST { tokens: [uuid...] }.
// Hard-deletes rows from `application_drafts` by token. Nothing else
// references application_drafts (verified: no FK points at it), so this
// is a clean delete with no cascade concerns.
//
// This is irreversible — there is no undo. Meant for clearing out old or
// abandoned drafts. The client should make the user confirm before
// calling this.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ALLOWED_ORIGIN = "https://america250cfc.org";
const TOKEN_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_TOKENS = 500;

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
  const tokens = Array.isArray(body.tokens) ? body.tokens : [];
  const clean = [...new Set(tokens)];
  if (clean.length === 0) return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "no_tokens" }) };
  if (clean.length > MAX_TOKENS) return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "too_many", max: MAX_TOKENS }) };
  if (!clean.every((t) => typeof t === "string" && TOKEN_RE.test(t))) return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "invalid_token" }) };

  const inList = clean.map((t) => `"${t}"`).join(",");
  const res = await fetch(`${SUPABASE_URL}/rest/v1/application_drafts?token=in.(${inList})`, {
    method: "DELETE",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      Prefer: "return=representation",
    },
  });
  if (!res.ok) {
    console.error("delete drafts failed:", res.status, await res.text());
    return { statusCode: 502, headers: noStore, body: JSON.stringify({ error: "delete_failed" }) };
  }
  const deletedRows = await res.json().catch(() => []);
  return { statusCode: 200, headers: noStore, body: JSON.stringify({ ok: true, deleted: Array.isArray(deletedRows) ? deletedRows.length : clean.length }) };
};
