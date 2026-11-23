// ============================================================
// America250 CFC — Admin: remove a judge
// Admin-cookie gated. POST { judge_id, delete_scores?: boolean }
//
// Removing a judge:
//   1. marks them inactive  → RLS immediately blocks all their access
//      (the judge page shows "Not on the judge list"), and they drop out
//      of the admin's judging panel;
//   2. deletes their assignments;
//   3. keeps their scores by default (submitted scores still count in the
//      results), or, with delete_scores: true, permanently deletes them.
//
// The sign-in account itself is kept, so inviting the same email again
// restores the judge (their kept scores come back with them).
// Recorded in audit_log.
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
  const deleteScores = body.delete_scores === true;

  const sb = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
  };

  const jRes = await fetch(`${SUPABASE_URL}/rest/v1/judges?select=id,name,email,affiliation,active&id=eq.${judgeId}`, { headers: sb });
  if (!jRes.ok) return reply(502, { error: "lookup_failed" });
  const judge = (await jRes.json())[0];
  if (!judge) return reply(404, { error: "judge_not_found" });

  // 1) Revoke access first: if a later step fails, the judge is still locked out.
  const offRes = await fetch(`${SUPABASE_URL}/rest/v1/judges?id=eq.${judgeId}`, {
    method: "PATCH",
    headers: { ...sb, Prefer: "return=minimal" },
    body: JSON.stringify({ active: false }),
  });
  if (!offRes.ok) {
    console.error("deactivate judge failed:", offRes.status, await offRes.text());
    return reply(502, { error: "remove_failed" });
  }

  // 2) Assignments, 3) optionally scores. Count what goes, for the audit trail.
  const del = async (table) => {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}?judge_id=eq.${judgeId}`, {
      method: "DELETE",
      headers: { ...sb, Prefer: "return=representation" },
    });
    if (!res.ok) { console.error(`delete ${table} failed:`, res.status, await res.text()); return null; }
    return (await res.json()).length;
  };
  const assignmentsRemoved = await del("judge_assignments");
  const scoresDeleted = deleteScores ? await del("scores") : 0;
  const partial = assignmentsRemoved === null || scoresDeleted === null;

  await fetch(`${SUPABASE_URL}/rest/v1/audit_log`, {
    method: "POST",
    headers: { ...sb, Prefer: "return=minimal" },
    body: JSON.stringify({
      actor: "admin",
      action: "judge_removed",
      target_table: "judges",
      target_id: judgeId,
      before_data: { name: judge.name, email: judge.email, affiliation: judge.affiliation, active: judge.active },
      after_data: { active: false, assignments_removed: assignmentsRemoved, scores_deleted: deleteScores ? scoresDeleted : "kept" },
    }),
  }).catch((err) => console.error("audit_log insert failed:", err));

  // Access is revoked either way; report a clean-up step that did not finish.
  if (partial) return reply(502, { error: "cleanup_incomplete", removed: true });
  return reply(200, { ok: true, name: judge.name, assignments_removed: assignmentsRemoved, scores_deleted: scoresDeleted });
};
