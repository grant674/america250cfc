// ============================================================
// America250 CFC — "Notify me when applications open" capture
// The homepage launch form and the /closed/ next-year form POST here; we store the email in
// Supabase (notify_signups) using the service-role key. Server-
// side so the public table is never exposed to the anon client.
// ============================================================

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALLOWED_ORIGIN = "https://america250cfc.org";
// Which list a signup joins. The client may name one of these; anything else
// falls back to the original homepage launch-interest list.
const DEFAULT_SOURCE = "homepage_notify";
const NEXT_CYCLE_SOURCE = "next_cycle_2027"; // /closed/ — "tell me about next year"
const SOURCES = new Set([DEFAULT_SOURCE, NEXT_CYCLE_SOURCE]);

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
    body: JSON.stringify(body),
  };
}

export const handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "method_not_allowed" });
  if (!SUPABASE_SERVICE_ROLE_KEY) return json(500, { error: "not_configured" });

  // Same-origin guard (defense in depth; SameSite isn't relevant here but a
  // foreign Origin declaring itself is rejected). Missing Origin is allowed
  // (non-browser callers still only get to write a single validated email).
  const h = event.headers || {};
  const origin = h.origin || h.Origin || "";
  if (origin && origin !== ALLOWED_ORIGIN) return json(403, { error: "forbidden_origin" });

  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return json(400, { error: "bad_json" }); }

  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  if (!EMAIL_RE.test(email) || email.length > 254) return json(400, { error: "invalid_email" });

  const source = SOURCES.has(body.source) ? body.source : DEFAULT_SOURCE;
  const serviceHeaders = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
    Prefer: "return=minimal",
  };

  const res = await fetch(`${SUPABASE_URL}/rest/v1/notify_signups`, {
    method: "POST",
    headers: serviceHeaders,
    body: JSON.stringify({
      email,
      source,
      user_agent: String(h["user-agent"] || h["User-Agent"] || "").slice(0, 400),
    }),
  });

  // 201 = created. 409 = duplicate email (already on the list) — treat as success
  // so we never reveal whether an address was already captured.
  if (res.ok) return json(200, { ok: true });
  if (res.status === 409) {
    // The address is unique, so someone who joined the 2026 launch list and now
    // asks about next year would otherwise stay filed under the old list only.
    // Re-tag the existing row so the next-year list is complete.
    if (source === NEXT_CYCLE_SOURCE) {
      const upd = await fetch(
        `${SUPABASE_URL}/rest/v1/notify_signups?email=eq.${encodeURIComponent(email)}`,
        { method: "PATCH", headers: serviceHeaders, body: JSON.stringify({ source }) },
      );
      if (!upd.ok) console.error("notify-signup re-tag failed:", upd.status, await upd.text());
    }
    return json(200, { ok: true });
  }

  const detail = await res.text();
  console.error("notify-signup insert failed:", res.status, detail);
  return json(502, { error: "save_failed" });
};
