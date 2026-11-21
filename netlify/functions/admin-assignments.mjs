// ============================================================
// America250 CFC — Admin: assign applications to judges
// Admin-cookie gated. POST { assign: [[judge_id, application_id], ...],
//                            unassign: [[judge_id, application_id], ...] }
// Writes public.judge_assignments with the service-role key. RLS on
// `applications` / `scores` lets a judge read and score only the
// applications assigned to them (db/migrations/2026-11-21-judge-assignments.sql).
//
// Only applications already in the judging pool (in_judging / finalist /
// winner) can be assigned, and only to active judges. Unassigning never
// deletes a score the judge already entered — it just hides the application
// from their queue. One audit_log row is written per judge touched.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ALLOWED_ORIGIN = "https://america250cfc.org";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const POOL_STATUSES = ["in_judging", "finalist", "winner"];
const MAX_PAIRS = 5000;

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

// Validate + de-dupe a list of [judge_id, application_id] pairs.
// Returns null if anything in it is malformed.
function cleanPairs(input) {
  if (input == null) return [];
  if (!Array.isArray(input)) return null;
  const seen = new Set();
  const out = [];
  for (const p of input) {
    if (!Array.isArray(p) || p.length !== 2) return null;
    const [j, a] = p;
    if (typeof j !== "string" || typeof a !== "string" || !UUID_RE.test(j) || !UUID_RE.test(a)) return null;
    const key = j.toLowerCase() + "|" + a.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push([j.toLowerCase(), a.toLowerCase()]);
  }
  return out;
}
function groupByJudge(pairs) {
  const m = new Map();
  for (const [j, a] of pairs) {
    if (!m.has(j)) m.set(j, []);
    m.get(j).push(a);
  }
  return m;
}

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

  const assign = cleanPairs(body.assign);
  const unassign = cleanPairs(body.unassign);
  if (!assign || !unassign) return reply(400, { error: "invalid_pairs" });
  if (assign.length + unassign.length === 0) return reply(400, { error: "no_changes" });
  if (assign.length + unassign.length > MAX_PAIRS) return reply(400, { error: "too_many", max: MAX_PAIRS });
  const assignKeys = new Set(assign.map((p) => p.join("|")));
  if (unassign.some((p) => assignKeys.has(p.join("|")))) return reply(400, { error: "conflicting_pairs" });

  const sb = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
  };

  // New assignments must point at an active judge and an application that is
  // actually in the judging pool. (Unassigning is always allowed.)
  if (assign.length) {
    const judgeIds = [...new Set(assign.map((p) => p[0]))];
    const appIds = [...new Set(assign.map((p) => p[1]))];
    const [jRes, aRes] = await Promise.all([
      fetch(`${SUPABASE_URL}/rest/v1/judges?select=id&active=eq.true&id=in.(${judgeIds.join(",")})`, { headers: sb }),
      fetch(`${SUPABASE_URL}/rest/v1/applications?select=id&status=in.(${POOL_STATUSES.join(",")})&id=in.(${appIds.join(",")})`, { headers: sb }),
    ]);
    if (!jRes.ok || !aRes.ok) {
      console.error("assignment validation fetch failed:", jRes.status, aRes.status);
      return reply(502, { error: "lookup_failed" });
    }
    const okJudges = new Set((await jRes.json()).map((r) => r.id));
    const okApps = new Set((await aRes.json()).map((r) => r.id));
    if (judgeIds.some((id) => !okJudges.has(id))) return reply(400, { error: "unknown_or_inactive_judge" });
    if (appIds.some((id) => !okApps.has(id))) return reply(400, { error: "application_not_in_judging_pool" });
  }

  // ----- Assign (idempotent upsert) -----
  if (assign.length) {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/judge_assignments?on_conflict=judge_id,application_id`, {
      method: "POST",
      headers: { ...sb, Prefer: "resolution=ignore-duplicates,return=minimal" },
      body: JSON.stringify(assign.map(([judge_id, application_id]) => ({ judge_id, application_id }))),
    });
    if (!res.ok) {
      const detail = await res.text();
      console.error("assign failed:", res.status, detail);
      // 404 / PGRST205 = the judge_assignments table isn't there yet.
      const missing = res.status === 404 || /PGRST205|judge_assignments/.test(detail) && /find the table|does not exist/i.test(detail);
      return reply(502, { error: missing ? "migration_not_applied" : "assign_failed" });
    }
  }

  // ----- Unassign (one DELETE per judge keeps URLs short) -----
  const unByJudge = groupByJudge(unassign);
  const delResults = await Promise.all([...unByJudge.entries()].map(([judgeId, appIds]) =>
    fetch(`${SUPABASE_URL}/rest/v1/judge_assignments?judge_id=eq.${judgeId}&application_id=in.(${appIds.join(",")})`, {
      method: "DELETE",
      headers: { ...sb, Prefer: "return=minimal" },
    }).then((r) => r.ok).catch(() => false)
  ));
  if (delResults.some((ok) => !ok)) {
    console.error("one or more unassign deletes failed");
    return reply(502, { error: "unassign_failed" });
  }

  // ----- Audit log: one row per judge touched -----
  const asByJudge = groupByJudge(assign);
  const touched = new Set([...asByJudge.keys(), ...unByJudge.keys()]);
  const auditRows = [...touched].map((judgeId) => ({
    actor: "admin",
    action: "judge_assignments_changed",
    target_table: "judges",
    target_id: judgeId,
    after_data: {
      assigned: asByJudge.get(judgeId) || [],
      unassigned: unByJudge.get(judgeId) || [],
    },
  }));
  await fetch(`${SUPABASE_URL}/rest/v1/audit_log`, {
    method: "POST",
    headers: { ...sb, Prefer: "return=minimal" },
    body: JSON.stringify(auditRows),
  }).catch((err) => console.error("audit_log insert failed:", err));

  return reply(200, { ok: true, assigned: assign.length, unassigned: unassign.length });
};
