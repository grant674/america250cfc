// ============================================================
// America250 CFC — Resend Inbound webhook receiver
//
// Resend delivers parsed inbound emails to this endpoint with Svix
// signature headers. We:
//   1. Verify the Svix signature (HMAC-SHA256) using
//      RESEND_INBOUND_SIGNING_SECRET so spoofed POSTs are rejected.
//   2. Parse the email envelope (to/from/subject/etc). The webhook body
//      itself carries no text/html — it's a notification only — so when
//      the envelope has no inline body we fetch the full parsed email
//      from Resend's API using the envelope's email_id.
//   3. Dedupe by message_id (Svix retries until 2xx).
//   4. Insert into public.inbound_emails via service_role.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const RESEND_INBOUND_SIGNING_SECRET = process.env.RESEND_INBOUND_SIGNING_SECRET;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ALLOWED_DOMAIN = "america250cfc.org";
const ALLOWED_ALIASES = new Set([
  "hello", "apply", "press", "partnerships",
  "privacy", "legal", "support", "security",
]);

function jsonResponse(statusCode, body) {
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

// Svix signature format: header svix-signature contains one or more
// space-separated "v1,<base64-hmac>" entries. The signed payload is
// `${svix-id}.${svix-timestamp}.${body}`.
function verifySvix(headers, rawBody, secret) {
  const id = headers["svix-id"] || headers["Svix-Id"];
  const ts = headers["svix-timestamp"] || headers["Svix-Timestamp"];
  const sigHeader = headers["svix-signature"] || headers["Svix-Signature"];
  if (!id || !ts || !sigHeader) return { ok: false, reason: "missing_signature_headers" };

  // Reject replays older than 5 minutes.
  const tsNum = parseInt(ts, 10);
  if (!tsNum || Math.abs(Date.now() / 1000 - tsNum) > 300) {
    return { ok: false, reason: "stale_or_invalid_timestamp" };
  }

  // Svix secrets are stored as "whsec_<base64>". Decode the base64 part.
  let keyBytes;
  try {
    const b64 = secret.startsWith("whsec_") ? secret.slice(6) : secret;
    keyBytes = Buffer.from(b64, "base64");
  } catch {
    return { ok: false, reason: "secret_decode_failed" };
  }

  const expected = createHmac("sha256", keyBytes)
    .update(`${id}.${ts}.${rawBody}`)
    .digest("base64");

  // Header carries multiple "v1,<sig>" pairs separated by space.
  const candidates = sigHeader.split(" ")
    .map(s => s.split(",")[1])
    .filter(Boolean);

  for (const got of candidates) {
    try {
      const a = Buffer.from(got);
      const b = Buffer.from(expected);
      if (a.length === b.length && timingSafeEqual(a, b)) return { ok: true };
    } catch { /* try next */ }
  }
  return { ok: false, reason: "signature_mismatch" };
}

// Resend's webhook payload for inbound emails — best-effort extraction.
// The exact shape may evolve; we capture the raw body in raw_payload for
// debugging + future feature work.
function extractEmail(payload) {
  const data = payload.data || payload;

  // "to" can be a string, an array of strings, or an array of {address,name} objects.
  let toRaw = data.to;
  if (!toRaw && data.envelope) toRaw = data.envelope.to;
  let toAddress = "";
  if (typeof toRaw === "string") {
    toAddress = toRaw;
  } else if (Array.isArray(toRaw) && toRaw.length) {
    const first = toRaw[0];
    toAddress = typeof first === "string" ? first : (first.address || first.email || "");
  }
  toAddress = String(toAddress).toLowerCase().trim();

  // from — same shape variations
  let fromRaw = data.from;
  if (!fromRaw && data.envelope) fromRaw = data.envelope.from;
  let fromAddress = "";
  let fromName = null;
  if (typeof fromRaw === "string") {
    const trimmed = fromRaw.trim();
    // Only treat this as "Name <addr>" when a genuine <...> is present —
    // trying to infer a name from a bare address (the common case) via a
    // single do-it-all regex is what caused the previous parser to chop
    // the first character off bare addresses (e.g. "grant@x.com" -> name
    // "g", address "rant@x.com"). Bare addresses now skip name-parsing
    // entirely.
    const angleMatch = trimmed.match(/^(?:"([^"]*)"|([^<]*?))\s*<([^<>\s]+@[^<>\s]+)>$/);
    if (angleMatch) {
      const name = (angleMatch[1] || angleMatch[2] || "").trim();
      fromName = name || null;
      fromAddress = angleMatch[3];
    } else {
      fromAddress = trimmed;
    }
  } else if (fromRaw && typeof fromRaw === "object") {
    fromAddress = fromRaw.address || fromRaw.email || "";
    fromName = fromRaw.name || null;
  }
  fromAddress = String(fromAddress).toLowerCase().trim();

  // Pluck the local-part of the to-address as the alias.
  const [localPart, domain] = toAddress.split("@");
  const toAlias = (localPart || "").toLowerCase();

  const headers = data.headers || {};
  // Header shape varies — sometimes object, sometimes array of {name,value}.
  let hdrMap = {};
  if (Array.isArray(headers)) {
    for (const h of headers) hdrMap[String(h.name || "").toLowerCase()] = h.value;
  } else if (typeof headers === "object") {
    for (const k of Object.keys(headers)) hdrMap[k.toLowerCase()] = headers[k];
  }
  // Resend's own message_id (RFC822 Message-ID header) is separate from
  // its internal email_id — the latter is what the "fetch full email" API
  // call below needs, since the webhook notification carries no body.
  const messageId = data.message_id || data.messageId || hdrMap["message-id"] || null;
  const resendEmailId = data.email_id || data.id || null;
  const inReplyTo = data.in_reply_to || hdrMap["in-reply-to"] || null;
  const refs = data.references || hdrMap["references"] || null;

  const subject = data.subject || hdrMap["subject"] || "";
  const text = data.text || data.text_body || "";
  const html = data.html || data.html_body || "";
  const snippet = (text || html.replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").slice(0, 140).trim();

  const attachments = Array.isArray(data.attachments) ? data.attachments.map(a => ({
    filename: a.filename || a.name || null,
    mime_type: a.contentType || a.content_type || a.mime_type || null,
    size_bytes: a.size || a.size_bytes || null,
    content_id: a.contentId || a.content_id || null,
  })) : [];

  return {
    to_alias: toAlias,
    to_address: toAddress,
    domain,
    from_address: fromAddress,
    from_name: fromName,
    subject,
    text_body: text,
    html_body: html,
    snippet,
    headers: hdrMap,
    attachments,
    message_id: messageId,
    resend_email_id: resendEmailId,
    in_reply_to: inReplyTo,
    email_refs: refs,
  };
}

// The email.received webhook is a notification only — no text/html. Fetch
// the full parsed email from Resend's API using its internal email_id.
// Best-effort: on any failure we log and fall back to storing the email
// with an empty body rather than dropping the row or retrying the webhook.
async function fetchInboundBody(emailId) {
  if (!RESEND_API_KEY || !emailId) return { text: "", html: "" };
  try {
    const res = await fetch(`https://api.resend.com/emails/inbound/${encodeURIComponent(emailId)}`, {
      headers: { Authorization: `Bearer ${RESEND_API_KEY}` },
    });
    if (!res.ok) {
      console.error("Resend inbound fetch failed:", res.status, await res.text().catch(() => ""));
      return { text: "", html: "" };
    }
    const data = await res.json();
    return { text: data.text || "", html: data.html || "" };
  } catch (err) {
    console.error("Resend inbound fetch error:", err);
    return { text: "", html: "" };
  }
}

export const handler = async (event) => {
  if (!SUPABASE_SERVICE_ROLE_KEY) return jsonResponse(500, { error: "config_missing", detail: "SUPABASE_SERVICE_ROLE_KEY" });
  if (!RESEND_INBOUND_SIGNING_SECRET) return jsonResponse(500, { error: "config_missing", detail: "RESEND_INBOUND_SIGNING_SECRET" });
  if (event.httpMethod !== "POST") return jsonResponse(405, { error: "method_not_allowed" });

  const rawBody = event.body || "";
  const headers = event.headers || {};

  // ----- Signature verification -----
  const sig = verifySvix(headers, rawBody, RESEND_INBOUND_SIGNING_SECRET);
  if (!sig.ok) {
    console.warn("Inbound rejected:", sig.reason);
    return jsonResponse(401, { error: "invalid_signature", reason: sig.reason });
  }

  let payload;
  try { payload = JSON.parse(rawBody); }
  catch { return jsonResponse(400, { error: "invalid_json" }); }

  const email = extractEmail(payload);

  // ----- Light hygiene: must be addressed to our domain + a known alias -----
  // (Reject mail to bogus aliases up front — keeps junk out of the table.)
  if (email.domain !== ALLOWED_DOMAIN) {
    console.warn("Inbound dropped (wrong domain):", email.to_address);
    return jsonResponse(200, { ok: true, dropped: "wrong_domain" });  // 200 so Svix doesn't retry
  }
  if (!ALLOWED_ALIASES.has(email.to_alias)) {
    console.warn("Inbound dropped (unknown alias):", email.to_alias);
    return jsonResponse(200, { ok: true, dropped: "unknown_alias" });
  }

  // The webhook envelope carries no body — fetch it from Resend if the
  // envelope didn't already have one inlined (defensive, in case that
  // ever changes).
  if (!email.text_body && !email.html_body && email.resend_email_id) {
    const body = await fetchInboundBody(email.resend_email_id);
    email.text_body = body.text;
    email.html_body = body.html;
    email.snippet = (body.text || body.html.replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").slice(0, 140).trim();
  }

  // ----- Insert (or upsert by message_id) -----
  const row = {
    to_alias: email.to_alias,
    to_address: email.to_address,
    from_address: email.from_address,
    from_name: email.from_name,
    subject: email.subject,
    text_body: email.text_body,
    html_body: email.html_body,
    snippet: email.snippet,
    message_id: email.message_id,
    in_reply_to: email.in_reply_to,
    email_refs: email.email_refs,
    headers: email.headers,
    attachments: email.attachments,
    raw_payload: payload,
    status: "unread",
  };

  // If the email has a message_id, prefer ON CONFLICT (message_id) DO NOTHING
  // so Svix retries don't dup. Otherwise insert blind.
  const useUpsert = !!email.message_id;
  const sbUrl = `${SUPABASE_URL}/rest/v1/inbound_emails`
    + (useUpsert ? "?on_conflict=message_id" : "");
  const prefer = useUpsert
    ? "resolution=ignore-duplicates,return=representation"
    : "return=representation";

  const res = await fetch(sbUrl, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: prefer,
    },
    body: JSON.stringify(row),
  });

  if (!res.ok) {
    const errText = await res.text();
    console.error("inbound_emails insert failed:", res.status, errText);
    return jsonResponse(502, { error: "db_insert_failed", detail: errText });
  }

  const inserted = await res.json();
  const isNew = Array.isArray(inserted) && inserted.length > 0;

  return jsonResponse(200, {
    ok: true,
    inserted: isNew,
    id: isNew ? inserted[0].id : null,
    to_alias: email.to_alias,
  });
};
