// ============================================================
// America250 CFC — Admin: scoring matrix CSV export
// Returns a CSV with one row per application × judge score.
// Verifies admin cookie. Uses service-role to read scores+judges+
// applications and joins them into a flat table.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

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

// RFC 4180-ish quoting + CSV formula-injection mitigation.
// Cells that start with =, +, -, @, \t, or \r are interpreted as formulas
// by Excel / Google Sheets / LibreOffice — opening such a CSV could execute
// the formula and leak data or run shell commands. We prefix any such cell
// with a single quote (the standard CSV-injection mitigation, per OWASP),
// then apply normal RFC 4180 quoting.
function csvCell(v) {
  if (v == null) return "";
  let s = String(v);
  if (s.length > 0 && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
  if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
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
  if (!SUPABASE_SERVICE_ROLE_KEY) return { statusCode: 500, body: "Missing SUPABASE_SERVICE_ROLE_KEY" };
  if (!ADMIN_PASSWORD) return { statusCode: 500, body: "Missing ADMIN_PASSWORD" };

  const candidates = parseCookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyConstantTimeEq(candidates, adminToken(ADMIN_PASSWORD))) {
    return { statusCode: 401, body: "unauthorized" };
  }
  if (!originAllowed(event)) {
    return { statusCode: 403, body: "forbidden_origin" };
  }

  const sbHeaders = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
  };

  const [scoresRes, judgesRes, appsRes] = await Promise.all([
    fetch(`${SUPABASE_URL}/rest/v1/scores?select=id,judge_id,application_id,dim_community,dim_innovation,dim_feasibility,dim_sustainability,dim_founder_team,total,status,submitted_at,comments,created_at,updated_at`, { headers: sbHeaders }),
    fetch(`${SUPABASE_URL}/rest/v1/judges?select=id,name,email,affiliation`, { headers: sbHeaders }),
    fetch(`${SUPABASE_URL}/rest/v1/applications?select=id,proj_title,lead_name,org_name,proj_category,proj_city,proj_state,status,ai_screening_result`, { headers: sbHeaders }),
  ]);

  if (!scoresRes.ok || !judgesRes.ok || !appsRes.ok) {
    return { statusCode: 502, body: "fetch failed" };
  }
  const [scores, judges, apps] = await Promise.all([scoresRes.json(), judgesRes.json(), appsRes.json()]);

  const judgeById = Object.fromEntries(judges.map(j => [j.id, j]));
  const appById = Object.fromEntries(apps.map(a => [a.id, a]));

  // Header row
  const header = [
    "application_id", "application_title", "lead_name", "org_name",
    "proj_category", "proj_city", "proj_state",
    "app_status", "ai_result",
    "judge_id", "judge_name", "judge_email", "judge_affiliation",
    "score_status",
    "dim_community", "dim_innovation", "dim_feasibility", "dim_sustainability", "dim_founder_team",
    "total",
    "comment_community", "comment_innovation", "comment_feasibility", "comment_sustainability", "comment_founder_team",
    "submitted_at", "created_at", "updated_at",
  ];
  const lines = [header.join(",")];

  for (const s of scores) {
    const a = appById[s.application_id] || {};
    const j = judgeById[s.judge_id] || {};
    const c = s.comments || {};
    lines.push([
      s.application_id,
      a.proj_title, a.lead_name, a.org_name,
      a.proj_category, a.proj_city, a.proj_state,
      a.status, a.ai_screening_result,
      s.judge_id, j.name, j.email, j.affiliation,
      s.status,
      s.dim_community, s.dim_innovation, s.dim_feasibility, s.dim_sustainability, s.dim_founder_team,
      s.total,
      c.community, c.innovation, c.feasibility, c.sustainability, c.founder_team,
      s.submitted_at, s.created_at, s.updated_at,
    ].map(csvCell).join(","));
  }

  const csv = lines.join("\n") + "\n";
  const filename = `america250cfc-scores-${new Date().toISOString().slice(0, 10)}.csv`;

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff",
    },
    body: csv,
  };
};
