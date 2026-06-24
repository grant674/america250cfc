// ============================================================
// America250 CFC — Admin: list applications
// Verifies the admin cookie, then fetches applications using
// the Supabase service-role key (bypasses RLS). Also fetches
// the scores table + judges table to compute per-application
// score aggregates (mean / median / std-dev / per-judge) and
// per-judge progress for the admin dashboard.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

function constantTimeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

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

function noStoreHeaders() {
  return {
    "Cache-Control": "private, no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
    "Vary": "Cookie",
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
  };
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

  // Verify admin cookie
  const candidates = parseCookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  const expected = adminToken(ADMIN_PASSWORD);
  if (!anyConstantTimeEq(candidates, expected)) {
    return { statusCode: 401, headers: noStoreHeaders(), body: JSON.stringify({ error: "unauthorized" }) };
  }
  if (!originAllowed(event)) {
    return { statusCode: 403, headers: noStoreHeaders(), body: JSON.stringify({ error: "forbidden_origin" }) };
  }

  // Fetch applications
  const fields = [
    "id", "created_at", "updated_at",
    "lead_name", "lead_role", "lead_email",
    "org_name", "org_url", "org_type", "org_has_entity", "team_desc",
    "proj_title", "proj_summary", "proj_category", "proj_phase",
    "proj_city", "proj_state", "proj_communities",
    "proj_budget_total", "proj_budget_raised", "proj_use_of_funds", "proj_video_url",
    "impact_community", "impact_innovation", "impact_feasibility",
    "impact_sustainability", "impact_founder_team",
    "elig_age", "elig_audience", "elig_phase", "elig_scope", "elig_coi",
    "legal_terms", "legal_attribution",
    "status", "ai_screening_result", "ai_screening_reasons", "ai_screening_at",
    "submission_source", "user_agent",
  ].join(",");

  const url = new URL(`${SUPABASE_URL}/rest/v1/applications`);
  url.searchParams.set("select", fields);
  url.searchParams.set("order", "created_at.desc");
  url.searchParams.set("limit", "500");

  const res = await fetch(url, {
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    },
  });

  if (!res.ok) {
    const errText = await res.text();
    console.error("Supabase fetch failed:", res.status, errText);
    return { statusCode: 502, headers: noStoreHeaders(), body: JSON.stringify({ error: "fetch failed", detail: errText }) };
  }

  const rows = await res.json();

  // Compute aggregate stats server-side
  const stats = {
    total: rows.length,
    by_status: {},
    by_ai: {},
    by_category: {},
    by_state: {},
  };
  for (const r of rows) {
    stats.by_status[r.status] = (stats.by_status[r.status] || 0) + 1;
    if (r.ai_screening_result) {
      stats.by_ai[r.ai_screening_result] = (stats.by_ai[r.ai_screening_result] || 0) + 1;
    } else {
      stats.by_ai["pending"] = (stats.by_ai["pending"] || 0) + 1;
    }
    if (r.proj_category) {
      stats.by_category[r.proj_category] = (stats.by_category[r.proj_category] || 0) + 1;
    }
    if (r.proj_state) {
      stats.by_state[r.proj_state] = (stats.by_state[r.proj_state] || 0) + 1;
    }
  }

  // #9 Duplicate-submission detection (non-blocking): flag rows that share a
  // normalized lead_email or org_name with another submission, so the admin
  // can spot repeat/duplicate entries. Detection only — nothing is rejected.
  const emailCounts = {};
  const orgCounts = {};
  for (const r of rows) {
    const e = (r.lead_email || "").trim().toLowerCase();
    const o = (r.org_name || "").trim().toLowerCase();
    if (e) emailCounts[e] = (emailCounts[e] || 0) + 1;
    if (o) orgCounts[o] = (orgCounts[o] || 0) + 1;
  }
  for (const r of rows) {
    const e = (r.lead_email || "").trim().toLowerCase();
    const o = (r.org_name || "").trim().toLowerCase();
    r.dup_email = !!(e && emailCounts[e] > 1);
    r.dup_org = !!(o && orgCounts[o] > 1);
  }

  // ----- Scoring data — fetched server-side via service_role -----
  // Failure here is non-fatal: dashboard still renders applications,
  // just without score aggregates.
  let scoresRows = [];
  let judgesRows = [];
  let inboxRows = [];
  let outboundRows = [];
  let auditRows = [];
  try {
    const sbHeaders = {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    };
    // Inbox: skip the heavy raw_payload + html_body in the list payload —
    // they're refetched per-row when the admin opens detail (admin-inbox-get).
    const inboxFields = "id,received_at,to_alias,to_address,from_address,from_name,subject,snippet,status,read_at,replied_at,attachments,message_id";
    const [scoresRes, judgesRes, inboxRes, outboundRes, auditRes] = await Promise.all([
      fetch(`${SUPABASE_URL}/rest/v1/scores?select=id,judge_id,application_id,dim_community,dim_innovation,dim_feasibility,dim_sustainability,dim_founder_team,total,status,submitted_at`, { headers: sbHeaders }),
      fetch(`${SUPABASE_URL}/rest/v1/judges?select=id,name,email,affiliation,active&order=name.asc`, { headers: sbHeaders }),
      fetch(`${SUPABASE_URL}/rest/v1/inbound_emails?select=${inboxFields}&status=neq.archived&order=received_at.desc&limit=300`, { headers: sbHeaders }),
      fetch(`${SUPABASE_URL}/rest/v1/outbound_replies?select=id,in_reply_to_id,from_alias,to_address,subject,sent_at,status&order=sent_at.desc&limit=300`, { headers: sbHeaders }),
      fetch(`${SUPABASE_URL}/rest/v1/audit_log?select=id,at,actor,action,target_table,target_id,before_data,after_data,notes&order=at.desc&limit=100`, { headers: sbHeaders }),
    ]);
    if (scoresRes.ok)   scoresRows   = await scoresRes.json();
    if (judgesRes.ok)   judgesRows   = await judgesRes.json();
    if (inboxRes.ok)    inboxRows    = await inboxRes.json();
    if (outboundRes.ok) outboundRows = await outboundRes.json();
    if (auditRes.ok)    auditRows    = await auditRes.json();
  } catch (err) {
    console.warn("Scores/judges/inbox fetch failed (non-fatal):", err?.message || err);
  }

  // Group scores by application
  const scoresByApp = {};
  for (const s of scoresRows) {
    if (!scoresByApp[s.application_id]) scoresByApp[s.application_id] = [];
    scoresByApp[s.application_id].push(s);
  }

  // Attach score aggregate to each application row (only counts 'submitted')
  function median(arr) {
    if (!arr.length) return null;
    const s = arr.slice().sort((a, b) => a - b);
    const m = Math.floor(s.length / 2);
    return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) * 50) / 100;
  }
  function stddev(arr, mean) {
    if (arr.length < 2) return 0;
    const v = arr.reduce((acc, x) => acc + (x - mean) ** 2, 0) / (arr.length - 1);
    return Math.round(Math.sqrt(v) * 100) / 100;
  }
  for (const r of rows) {
    const all = scoresByApp[r.id] || [];
    const submitted = all.filter(s => s.status === "submitted" && s.total != null);
    const recused = all.filter(s => s.status === "recused").length;
    const inProgress = all.filter(s => s.status === "draft").length;
    if (submitted.length === 0) {
      r.scoring = {
        n_submitted: 0,
        n_in_progress: inProgress,
        n_recused: recused,
        mean: null, median: null, stddev: null,
        per_dim: null, per_judge: null,
      };
      continue;
    }
    const totals = submitted.map(s => s.total);
    const meanVal = Math.round((totals.reduce((a, b) => a + b, 0) / totals.length) * 100) / 100;
    const perDim = {};
    ["dim_community", "dim_innovation", "dim_feasibility", "dim_sustainability", "dim_founder_team"].forEach((k) => {
      const arr = submitted.map(s => s[k]).filter(v => v != null);
      if (arr.length) {
        const m = Math.round((arr.reduce((a, b) => a + b, 0) / arr.length) * 100) / 100;
        perDim[k] = { mean: m, n: arr.length };
      }
    });
    const perJudge = submitted.map(s => ({
      judge_id: s.judge_id,
      total: s.total,
      submitted_at: s.submitted_at,
    }));
    r.scoring = {
      n_submitted: submitted.length,
      n_in_progress: inProgress,
      n_recused: recused,
      mean: meanVal,
      median: median(totals),
      stddev: stddev(totals, meanVal),
      per_dim: perDim,
      per_judge: perJudge,
    };
  }

  // Per-judge progress (across applications currently in any scoring phase)
  const inJudgingIds = new Set(rows
    .filter(r => ["approved", "in_judging", "finalist", "winner"].includes(r.status))
    .map(r => r.id));
  const judgesProgress = judgesRows
    .filter(j => j.active)
    .map((j) => {
      const myScores = scoresRows.filter(s => s.judge_id === j.id && inJudgingIds.has(s.application_id));
      const submittedCount = myScores.filter(s => s.status === "submitted").length;
      const draftCount = myScores.filter(s => s.status === "draft").length;
      const recusedCount = myScores.filter(s => s.status === "recused").length;
      return {
        judge_id: j.id,
        name: j.name,
        email: j.email,
        affiliation: j.affiliation,
        total: inJudgingIds.size,
        submitted: submittedCount,
        draft: draftCount,
        recused: recusedCount,
      };
    });

  // Inbox stats — by-alias + by-status counts for the new admin section.
  const inboxStats = { total: inboxRows.length, by_alias: {}, by_status: {} };
  for (const m of inboxRows) {
    inboxStats.by_alias[m.to_alias]  = (inboxStats.by_alias[m.to_alias]  || 0) + 1;
    inboxStats.by_status[m.status]   = (inboxStats.by_status[m.status]   || 0) + 1;
  }

  return {
    statusCode: 200,
    headers: noStoreHeaders(),
    body: JSON.stringify({
      rows,
      stats,
      judges_progress: judgesProgress,
      inbox: inboxRows,
      inbox_stats: inboxStats,
      outbound_replies: outboundRows,
      audit: auditRows,
      fetched_at: new Date().toISOString(),
    }),
  };
};
