// ============================================================
// America250 CFC — Application submission gateway
// The public apply form POSTs { payload, token } here. We verify the
// Cloudflare Turnstile token, then insert the application via the
// service-role key with a strict column allow-list (status is forced;
// AI-screening / timestamp columns can never be set by the client).
//
// Direct anonymous inserts into `applications` are revoked at the DB,
// so this Turnstile-gated path is the ONLY way to create an application —
// stopping bot spam before it can trigger a Claude screening or an email.
// ============================================================

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;
const ALLOWED_ORIGIN = "https://america250cfc.org";
// Turnstile tokens must come from our own host(s) (the widget is registered for
// america250cfc.org). Cloudflare returns the solving page's hostname in siteverify.
const ALLOWED_HOSTS = new Set(["america250cfc.org", "www.america250cfc.org"]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Applicant-fillable columns only. status is forced; ai_screening_*,
// created_at, updated_at are intentionally absent (server/DB owns them).
const TEXT_FIELDS = [
  "elig_age", "elig_audience", "elig_phase", "elig_scope", "elig_coi",
  "lead_name", "lead_role", "lead_email",
  "org_name", "org_url", "org_type", "org_has_entity", "team_desc",
  "proj_title", "proj_summary", "proj_category", "proj_phase",
  "proj_city", "proj_state", "proj_communities",
  "proj_use_of_funds", "proj_video_url",
  "impact_community", "impact_innovation", "impact_feasibility",
  "impact_sustainability", "impact_founder_team",
  "user_agent", "submission_source",
];
const INT_FIELDS = ["proj_budget_total", "proj_budget_raised"];
const BOOL_FIELDS = ["legal_terms", "legal_attribution"];
const MAX_TEXT = 5000; // generous ceiling above the form's per-field maxlengths

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
    body: JSON.stringify(body),
  };
}

async function verifyTurnstile(token, ip) {
  const form = new URLSearchParams();
  form.set("secret", TURNSTILE_SECRET_KEY);
  form.set("response", token);
  if (ip) form.set("remoteip", ip);
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    const data = await res.json();
    if (!data || data.success !== true) return false;
    // Bind the token to this widget + host: the apply widget sets action="apply",
    // and tokens must originate from our own domain. Rejects tokens minted by a
    // Turnstile widget on some other site/action even if the sitekey leaked.
    if (data.action && data.action !== "apply") return false;
    if (data.hostname && !ALLOWED_HOSTS.has(String(data.hostname).toLowerCase())) return false;
    return true;
  } catch (err) {
    console.error("Turnstile verify error:", err?.message || err);
    return false;
  }
}

export const handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "method_not_allowed" });
  if (!SUPABASE_SERVICE_ROLE_KEY || !TURNSTILE_SECRET_KEY) return json(500, { error: "not_configured" });

  const h = event.headers || {};
  const origin = h.origin || h.Origin || "";
  if (origin && origin !== ALLOWED_ORIGIN) return json(403, { error: "forbidden_origin" });

  let parsed;
  try { parsed = JSON.parse(event.body || "{}"); }
  catch { return json(400, { error: "bad_json" }); }

  const token = typeof parsed.token === "string" ? parsed.token : "";
  if (!token) return json(400, { error: "missing_token" });

  const ip = h["x-nf-client-connection-ip"] || (h["x-forwarded-for"] || "").split(",")[0].trim() || "";
  const ok = await verifyTurnstile(token, ip);
  if (!ok) return json(403, { error: "verification_failed" });

  // ---- Build a clean, allow-listed row ----
  const src = parsed.payload && typeof parsed.payload === "object" ? parsed.payload : {};
  const row = {};
  for (const k of TEXT_FIELDS) {
    if (src[k] != null && src[k] !== "") row[k] = String(src[k]).slice(0, MAX_TEXT);
  }
  for (const k of INT_FIELDS) {
    const n = parseInt(src[k], 10);
    if (Number.isFinite(n)) row[k] = n;
  }
  for (const k of BOOL_FIELDS) row[k] = src[k] === true;
  row.status = "submitted"; // forced — never trust the client
  if (typeof src.id === "string" && UUID_RE.test(src.id)) row.id = src.id;

  const res = await fetch(`${SUPABASE_URL}/rest/v1/applications`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: JSON.stringify(row),
  });

  if (!res.ok) {
    const detail = await res.text();
    console.error("Application insert failed:", res.status, detail);
    return json(502, { error: "insert_failed" });
  }
  const inserted = await res.json();
  const id = Array.isArray(inserted) && inserted[0] ? inserted[0].id : row.id;
  return json(200, { ok: true, id });
};
