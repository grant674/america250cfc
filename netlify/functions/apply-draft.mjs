// ============================================================
// America250 CFC — Save-and-resume drafts (#8)
// Public, token-gated (the token is an unguessable UUID held only by the
// applicant). Server copy of the in-progress application so it can be resumed
// on another device via /apply/?resume=<token>.
//   POST { token, data, base?, force? } -> upsert the draft -> { ok, updated_at }
//   GET  ?token=<token>                  -> { data, updated_at } (or 404)
// `base` is the updated_at the page last loaded or saved (null = it saw no
// server copy). When the stored draft is newer than `base`, someone else
// saved it in the meantime (another device, or a helper using the resume
// link) and the save is refused with 409 rather than overwriting their
// answers; `force` (the page's "Keep my version") overrides. Requests with
// no `base` key at all come from pages loaded before this check and are
// saved as before.
// No email is sent from here (avoids being an open mail relay); the applicant
// copies their own resume link.
// ============================================================

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ALLOWED_ORIGIN = "https://america250cfc.org";
const TOKEN_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_DATA_BYTES = 60000;

function json(statusCode, body) {
  return { statusCode, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }, body: JSON.stringify(body) };
}

export const handler = async (event) => {
  if (!SUPABASE_SERVICE_ROLE_KEY) return json(500, { error: "not_configured" });
  const sb = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` };

  // ---- Load ----
  if (event.httpMethod === "GET") {
    const token = (event.queryStringParameters && event.queryStringParameters.token) || "";
    if (!TOKEN_RE.test(token)) return json(400, { error: "invalid_token" });
    const res = await fetch(`${SUPABASE_URL}/rest/v1/application_drafts?token=eq.${encodeURIComponent(token)}&select=data,updated_at`, { headers: sb });
    if (!res.ok) return json(502, { error: "fetch_failed" });
    const rows = await res.json();
    if (!rows.length) return json(404, { error: "not_found" });
    return json(200, { data: rows[0].data, updated_at: rows[0].updated_at });
  }

  // ---- Save (upsert) ----
  if (event.httpMethod === "POST") {
    const origin = (event.headers || {}).origin || (event.headers || {}).Origin || "";
    if (origin && origin !== ALLOWED_ORIGIN) return json(403, { error: "forbidden_origin" });
    let body;
    try { body = JSON.parse(event.body || "{}"); } catch { return json(400, { error: "bad_json" }); }
    const token = typeof body.token === "string" ? body.token : "";
    if (!TOKEN_RE.test(token)) return json(400, { error: "invalid_token" });
    const data = body.data && typeof body.data === "object" ? body.data : null;
    if (!data) return json(400, { error: "no_data" });
    const serialized = JSON.stringify(data);
    if (serialized.length > MAX_DATA_BYTES) return json(413, { error: "too_large" });
    // Best-effort email tag (helps an admin recognize an abandoned draft).
    const email = data.fields && typeof data.fields.lead_email === "string" ? data.fields.lead_email.slice(0, 254) : null;

    if ("base" in body && body.force !== true) {
      const base = typeof body.base === "string" ? Date.parse(body.base) : null;
      const cur = await fetch(`${SUPABASE_URL}/rest/v1/application_drafts?token=eq.${encodeURIComponent(token)}&select=updated_at`, { headers: sb });
      if (!cur.ok) return json(502, { error: "fetch_failed" });
      const rows = await cur.json();
      const stored = rows.length ? Date.parse(rows[0].updated_at) : null;
      if (stored !== null && (base === null || Number.isNaN(base) || stored > base)) {
        return json(409, { error: "conflict", updated_at: rows[0].updated_at });
      }
    }

    const res = await fetch(`${SUPABASE_URL}/rest/v1/application_drafts?on_conflict=token&select=updated_at`, {
      method: "POST",
      headers: { ...sb, "Content-Type": "application/json", Prefer: "resolution=merge-duplicates,return=representation" },
      body: JSON.stringify({ token, email, data, updated_at: new Date().toISOString() }),
    });
    if (!res.ok) {
      console.error("draft save failed:", res.status, await res.text());
      return json(502, { error: "save_failed" });
    }
    const saved = await res.json().catch(() => []);
    return json(200, { ok: true, updated_at: Array.isArray(saved) && saved[0] ? saved[0].updated_at : null });
  }

  return json(405, { error: "method_not_allowed" });
};
