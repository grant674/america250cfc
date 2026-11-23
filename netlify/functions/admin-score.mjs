// ============================================================
// America250 CFC — Admin: enter or edit a judge's score
// Admin-cookie gated. For judges who cannot use the judge portal (the
// admin keys in the scores they send by email / paper / phone), and for
// reopening a score a judge submitted by mistake.
//
// GET  ?judge_id=&application_id=   → { score } (the full row incl. comments, or null)
// POST { judge_id, application_id,
//        dims:     { dim_community, dim_feasibility, dim_innovation,
//                    dim_sustainability, dim_founder_team }   each 0-10 or null
//        comments: { community, feasibility, innovation, sustainability, founder_team }
//        status:   "draft" | "submitted" | "recused" }
//
// Rules: the application must be assigned to that (active) judge;
// "submitted" needs all five scores; "recused" clears the scores.
// `scores.total` is a generated column and is never written here.
// Every change is recorded in audit_log with before / after, marked as
// entered by the admin on the judge's behalf.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ALLOWED_ORIGIN = "https://america250cfc.org";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DIM_COLS = ["dim_community", "dim_feasibility", "dim_innovation", "dim_sustainability", "dim_founder_team"];
const COMMENT_KEYS = ["community", "feasibility", "innovation", "sustainability", "founder_team"];
const STATUSES = new Set(["draft", "submitted", "recused"]);
const SCORE_FIELDS = "id,judge_id,application_id," + DIM_COLS.join(",") + ",total,comments,status,submitted_at,updated_at";

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
  if (event.httpMethod !== "GET" && event.httpMethod !== "POST") return reply(405, { error: "method_not_allowed" });
  if (!SUPABASE_SERVICE_ROLE_KEY || !ADMIN_PASSWORD) return reply(500, { error: "not_configured" });

  const cands = cookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyEq(cands, adminToken(ADMIN_PASSWORD))) return reply(401, { error: "unauthorized" });
  const origin = event.headers.origin || event.headers.Origin || "";
  if (origin && origin !== ALLOWED_ORIGIN) return reply(403, { error: "forbidden_origin" });

  const sb = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
  };
  const scoreUrl = (judgeId, appId) =>
    `${SUPABASE_URL}/rest/v1/scores?judge_id=eq.${judgeId}&application_id=eq.${appId}&select=${SCORE_FIELDS}`;

  // ----- GET: load the current score (with comments) for the editor -----
  if (event.httpMethod === "GET") {
    const q = event.queryStringParameters || {};
    if (!UUID_RE.test(q.judge_id || "") || !UUID_RE.test(q.application_id || "")) return reply(400, { error: "invalid_id" });
    const res = await fetch(scoreUrl(q.judge_id, q.application_id), { headers: sb });
    if (!res.ok) return reply(502, { error: "lookup_failed" });
    const rows = await res.json();
    return reply(200, { score: rows[0] || null });
  }

  // ----- POST: validate -----
  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { return reply(400, { error: "bad_json" }); }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return reply(400, { error: "bad_json" });

  const judgeId = String(body.judge_id || "").toLowerCase();
  const appId = String(body.application_id || "").toLowerCase();
  if (!UUID_RE.test(judgeId) || !UUID_RE.test(appId)) return reply(400, { error: "invalid_id" });
  const status = body.status;
  if (!STATUSES.has(status)) return reply(400, { error: "invalid_status" });

  const dimsIn = body.dims && typeof body.dims === "object" && !Array.isArray(body.dims) ? body.dims : {};
  const dims = {};
  for (const col of DIM_COLS) {
    const v = dimsIn[col];
    if (v === null || v === undefined || v === "") { dims[col] = null; continue; }
    if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 10) return reply(400, { error: "invalid_score", field: col });
    dims[col] = v;
  }
  const commentsIn = body.comments && typeof body.comments === "object" && !Array.isArray(body.comments) ? body.comments : {};
  const comments = {};
  for (const key of COMMENT_KEYS) {
    const c = commentsIn[key];
    if (typeof c === "string" && c.trim()) comments[key] = c.trim().slice(0, 1000);
  }

  if (status === "submitted" && DIM_COLS.some((c) => dims[c] === null)) return reply(400, { error: "incomplete_scores" });
  if (status === "recused") for (const col of DIM_COLS) dims[col] = null;

  // The pair must be a real assignment to an active judge.
  const [jRes, aRes, curRes] = await Promise.all([
    fetch(`${SUPABASE_URL}/rest/v1/judges?select=id,name&active=eq.true&id=eq.${judgeId}`, { headers: sb }),
    fetch(`${SUPABASE_URL}/rest/v1/judge_assignments?select=judge_id&judge_id=eq.${judgeId}&application_id=eq.${appId}`, { headers: sb }),
    fetch(scoreUrl(judgeId, appId), { headers: sb }),
  ]);
  if (!jRes.ok || !aRes.ok || !curRes.ok) {
    console.error("admin-score lookups failed:", jRes.status, aRes.status, curRes.status);
    return reply(502, { error: "lookup_failed" });
  }
  if ((await jRes.json()).length === 0) return reply(400, { error: "unknown_or_inactive_judge" });
  if ((await aRes.json()).length === 0) return reply(400, { error: "not_assigned" });
  const before = (await curRes.json())[0] || null;

  // Keep the original submission time if it was already final and stays final.
  const wasFinal = before && (before.status === "submitted" || before.status === "recused");
  const submittedAt = status === "draft" ? null
    : (wasFinal && before.status === status && before.submitted_at ? before.submitted_at : new Date().toISOString());

  const row = { judge_id: judgeId, application_id: appId, ...dims, comments, status, submitted_at: submittedAt };
  const upRes = await fetch(`${SUPABASE_URL}/rest/v1/scores?on_conflict=judge_id,application_id&select=${SCORE_FIELDS}`, {
    method: "POST",
    headers: { ...sb, Prefer: "resolution=merge-duplicates,return=representation" },
    body: JSON.stringify(row),
  });
  if (!upRes.ok) {
    console.error("admin-score upsert failed:", upRes.status, await upRes.text());
    return reply(502, { error: "save_failed" });
  }
  const saved = (await upRes.json())[0] || null;

  const pick = (s) => s && Object.fromEntries([...DIM_COLS, "comments", "status", "submitted_at"].map((k) => [k, s[k]]));
  await fetch(`${SUPABASE_URL}/rest/v1/audit_log`, {
    method: "POST",
    headers: { ...sb, Prefer: "return=minimal" },
    body: JSON.stringify({
      actor: "admin",
      action: "score_edited_by_admin",
      target_table: "scores",
      target_id: saved ? saved.id : null,
      before_data: pick(before),
      after_data: { ...pick(saved), judge_id: judgeId, application_id: appId },
      notes: "Entered by the admin on the judge's behalf",
    }),
  }).catch((err) => console.error("audit_log insert failed:", err));

  return reply(200, { ok: true, score: saved });
};
