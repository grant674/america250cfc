// ============================================================
// America250 CFC — Admin: list unsubmitted application drafts
// Admin-cookie gated. Reads application_drafts (saved by apply-draft.mjs
// as the public apply form auto-saves in-progress work) so admins can see
// who started an application but never submitted it, and reach out to
// the ones who got far enough to leave an email address.
//
// Drafts whose email matches a submitted application are left out: that
// person already applied, so a "finish your application" reminder would
// only invite a duplicate. (New submissions delete their own draft in
// submit-application.mjs; this also covers older drafts and anyone who
// started a second draft on another device.)
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

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
function normEmail(e) { return typeof e === "string" ? e.trim().toLowerCase() : ""; }
function draftEmail(d) {
  const f = (d.data && d.data.fields) || {};
  return normEmail(d.email) || normEmail(f.lead_email);
}
const noStore = { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY" };

export const handler = async (event) => {
  if (!SUPABASE_SERVICE_ROLE_KEY) return { statusCode: 500, headers: noStore, body: JSON.stringify({ error: "not_configured" }) };
  if (!ADMIN_PASSWORD) return { statusCode: 500, headers: noStore, body: JSON.stringify({ error: "not_configured" }) };

  const cands = cookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyEq(cands, adminToken(ADMIN_PASSWORD))) return { statusCode: 401, headers: noStore, body: JSON.stringify({ error: "unauthorized" }) };

  const url = new URL(`${SUPABASE_URL}/rest/v1/application_drafts`);
  url.searchParams.set("select", "token,email,data,created_at,updated_at");
  url.searchParams.set("order", "updated_at.desc");
  url.searchParams.set("limit", "1000");

  const sb = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` };
  const appsUrl = new URL(`${SUPABASE_URL}/rest/v1/applications`);
  appsUrl.searchParams.set("select", "lead_email");
  appsUrl.searchParams.set("lead_email", "not.is.null");
  appsUrl.searchParams.set("limit", "10000");

  const [res, appsRes] = await Promise.all([fetch(url, { headers: sb }), fetch(appsUrl, { headers: sb })]);
  if (!res.ok || !appsRes.ok) return { statusCode: 502, headers: noStore, body: JSON.stringify({ error: "fetch_failed" }) };
  const rows = await res.json();
  const submitted = new Set((await appsRes.json()).map((a) => normEmail(a.lead_email)).filter(Boolean));

  const drafts = rows.filter((d) => !submitted.has(draftEmail(d)));
  return {
    statusCode: 200,
    headers: noStore,
    body: JSON.stringify({ drafts, hidden_submitted: rows.length - drafts.length }),
  };
};
