// ============================================================
// America250 CFC — Admin: applications CSV export
// Returns a CSV with one row per application (the full intake record).
// This is distinct from admin-export-scores.mjs, which exports the
// judge-scoring matrix (one row per application × judge score) and is
// empty until judging actually starts. Verifies admin cookie.
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
  const secret = process.env.NN_AUTH_SECRET;
  if (!secret) throw new Error("NN_AUTH_SECRET not configured");
  return createHmac("sha256", secret).update("nn-admin-v1:" + password).digest("hex");
}
function parseCookieValues(cookieHeader, name) {
  if (!cookieHeader) return [];
  const re = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`, "g");
  const out = [];
  let m;
  while ((m = re.exec(cookieHeader)) !== null) {
    if (m[1] && m[1].length > 0) out.push(m[1]);
  }
  return out;
}
function anyConstantTimeEq(candidates, expected) {
  let found = false;
  for (const c of candidates) {
    if (constantTimeEq(c, expected)) found = true;
  }
  return found;
}

// RFC 4180-ish quoting + CSV formula-injection mitigation (OWASP): a cell
// starting with =, +, -, @, tab, or CR is treated as a formula by Excel /
// Sheets / LibreOffice, so prefix it with a quote before normal quoting.
function csvCell(v) {
  if (v == null) return "";
  let s = String(v);
  if (s.length > 0 && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
  if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}

const ALLOWED_ORIGIN = "https://america250cfc.org";
function originAllowed(event) {
  const headers = event.headers || {};
  const origin = headers.origin || headers.Origin || "";
  const referer = headers.referer || headers.Referer || "";
  if (origin) return origin === ALLOWED_ORIGIN;
  if (referer) return referer === ALLOWED_ORIGIN || referer.startsWith(ALLOWED_ORIGIN + "/");
  return true;
}

// Same field list admin-list.mjs uses for the dashboard table, so the
// export matches what the admin already sees on screen.
const FIELDS = [
  "id", "created_at", "updated_at",
  "lead_name", "lead_role", "lead_email",
  "org_name", "org_url", "org_type", "org_ein", "team_desc",
  "proj_title", "proj_summary", "proj_category", "proj_phase",
  "proj_city", "proj_state", "proj_communities",
  "proj_budget_total", "proj_budget_raised", "proj_use_of_funds", "proj_video_url",
  "impact_community", "impact_innovation", "impact_feasibility",
  "impact_sustainability", "impact_founder_team",
  "elig_age", "elig_audience", "elig_phase", "elig_scope", "elig_coi", "elig_nonprofit",
  "legal_terms", "legal_attribution",
  "status", "ai_screening_result", "ai_screening_reasons", "ai_screening_at",
  "submission_source", "user_agent",
];

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

  const url = new URL(`${SUPABASE_URL}/rest/v1/applications`);
  url.searchParams.set("select", FIELDS.join(","));
  url.searchParams.set("order", "created_at.desc");
  url.searchParams.set("limit", "2000");

  const res = await fetch(url, {
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    },
  });
  if (!res.ok) return { statusCode: 502, body: "fetch failed" };
  const apps = await res.json();

  const lines = [FIELDS.join(",")];
  for (const a of apps) {
    const reasons = Array.isArray(a.ai_screening_reasons)
      ? a.ai_screening_reasons.join("; ")
      : a.ai_screening_reasons;
    lines.push(FIELDS.map((f) => (f === "ai_screening_reasons" ? reasons : a[f])).map(csvCell).join(","));
  }

  const csv = lines.join("\n") + "\n";
  const filename = `america250cfc-applications-${new Date().toISOString().slice(0, 10)}.csv`;

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
