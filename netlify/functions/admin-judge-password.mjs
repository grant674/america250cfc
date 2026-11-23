// ============================================================
// America250 CFC — Admin: set or reset a judge's portal password
// Admin-cookie gated. POST { judge_id, password }
//
// Lets a judge sign in at /judge/ with email + password instead of
// waiting for an emailed link: the admin sets a starting password (or
// resets a forgotten one) and passes it to the judge, who can change it
// in the portal. Also confirms the judge's email on the sign-in account,
// so a judge who never opened their invitation email can still sign in.
//
// The password is never stored or logged here; audit_log records only
// that it was set.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ALLOWED_ORIGIN = "https://america250cfc.org";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
const reply = (statusCode, obj) => ({ statusCode, headers: noStore, body: JSON.stringify(obj) });

const MIN_LEN = 10, MAX_LEN = 72;   // 72 = bcrypt's limit in the auth service

export const handler = async (event) => {
  if (event.httpMethod !== "POST") return reply(405, { error: "method_not_allowed" });
  if (!SUPABASE_SERVICE_ROLE_KEY || !ADMIN_PASSWORD) return reply(500, { error: "not_configured" });

  const cands = cookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyEq(cands, adminToken(ADMIN_PASSWORD))) return reply(401, { error: "unauthorized" });
  const origin = event.headers.origin || event.headers.Origin || "";
  if (origin && origin !== ALLOWED_ORIGIN) return reply(403, { error: "forbidden_origin" });

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { return reply(400, { error: "bad_json" }); }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return reply(400, { error: "bad_json" });
  const judgeId = String(body.judge_id || "").toLowerCase();
  if (!UUID_RE.test(judgeId)) return reply(400, { error: "invalid_id" });
  const password = body.password;
  if (typeof password !== "string" || password.length < MIN_LEN) return reply(400, { error: "password_too_short", min: MIN_LEN });
  if (password.length > MAX_LEN) return reply(400, { error: "password_too_long", max: MAX_LEN });

  const sb = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
  };

  // Only ever touch the sign-in account of an active judge.
  const jRes = await fetch(`${SUPABASE_URL}/rest/v1/judges?select=id,name,email&active=eq.true&id=eq.${judgeId}`, { headers: sb });
  if (!jRes.ok) return reply(502, { error: "lookup_failed" });
  const judge = (await jRes.json())[0];
  if (!judge) return reply(404, { error: "judge_not_found" });

  const upRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${judgeId}`, {
    method: "PUT",
    headers: sb,
    body: JSON.stringify({ password, email_confirm: true }),
  });
  if (!upRes.ok) {
    const detail = await upRes.text();
    console.error("set judge password failed:", upRes.status, detail.slice(0, 300));
    const weak = upRes.status === 422 || /weak_password/.test(detail);
    return reply(weak ? 400 : 502, { error: weak ? "password_rejected" : "set_failed" });
  }

  await fetch(`${SUPABASE_URL}/rest/v1/audit_log`, {
    method: "POST",
    headers: { ...sb, Prefer: "return=minimal" },
    body: JSON.stringify({
      actor: "admin",
      action: "judge_password_set",
      target_table: "judges",
      target_id: judgeId,
      after_data: { name: judge.name, email: judge.email },
    }),
  }).catch((err) => console.error("audit_log insert failed:", err));

  return reply(200, { ok: true, name: judge.name, email: judge.email });
};
