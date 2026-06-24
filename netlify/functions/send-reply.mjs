// ============================================================
// America250 CFC — Admin: send a reply from /admin/ inbox
//
// POST { in_reply_to_id, subject, text, html?, cc?, bcc?, to_override? }
// 1. Verify admin cookie.
// 2. Load the inbound row → pick FROM alias from to_alias, recipient
//    from from_address (unless to_override given), threading headers
//    from message_id + email_refs.
// 3. Send via Resend SEND API. The current RESEND_API_KEY is send-only
//    which is exactly what we need here.
// 4. Insert outbound_replies row with the Resend email id.
// 5. Mark inbound_emails.status = 'replied' + replied_at.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const DOMAIN = "america250cfc.org";

const ALIAS_DISPLAY = {
  hello: "America250 CFC",
  apply: "America250 CFC — Applications",
  press: "America250 CFC — Press",
  partnerships: "America250 CFC — Partnerships",
  privacy: "America250 CFC — Privacy",
  legal: "America250 CFC — Legal",
  support: "America250 CFC — Support",
  security: "America250 CFC — Security",
};
const ALLOWED_ALIASES = new Set(Object.keys(ALIAS_DISPLAY));

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
function jsonResponse(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
    },
    body: JSON.stringify(body),
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;


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
  if (!SUPABASE_SERVICE_ROLE_KEY) return jsonResponse(500, { error: "config_missing", detail: "SUPABASE_SERVICE_ROLE_KEY" });
  if (!ADMIN_PASSWORD) return jsonResponse(500, { error: "config_missing", detail: "ADMIN_PASSWORD" });
  if (!RESEND_API_KEY) return jsonResponse(500, { error: "config_missing", detail: "RESEND_API_KEY" });
  if (event.httpMethod !== "POST") return jsonResponse(405, { error: "method_not_allowed" });

  // ----- Auth gate -----
  const candidates = parseCookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyConstantTimeEq(candidates, adminToken(ADMIN_PASSWORD))) {
    return jsonResponse(401, { error: "unauthorized" });
  }
  if (!originAllowed(event)) {
    return jsonResponse(403, { error: "forbidden_origin" });
  }

  // ----- Parse + validate -----
  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return jsonResponse(400, { error: "invalid_json" }); }
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse(400, { error: "invalid_payload" });
  }

  const inReplyToId = String(body.in_reply_to_id || "");
  if (!UUID_RE.test(inReplyToId)) return jsonResponse(400, { error: "invalid_in_reply_to_id" });

  // Subject: strip CR/LF (header-injection defense — Resend also blocks
  // these, but we don't even want them stored in outbound_replies on the
  // failure path).
  const subject = String(body.subject || "")
    .replace(/[\r\n]+/g, " ")
    .trim()
    .slice(0, 500);
  if (!subject) return jsonResponse(400, { error: "missing_subject" });

  const textBody = body.text == null ? "" : String(body.text).slice(0, 50000);
  const htmlBody = body.html == null ? null : String(body.html).slice(0, 200000);
  if (!textBody && !htmlBody) return jsonResponse(400, { error: "missing_body" });

  // Optional cc/bcc/to_override — sanitise
  function cleanList(v) {
    if (!v) return [];
    const arr = Array.isArray(v) ? v : String(v).split(/[;,]/);
    return arr.map(s => String(s).trim().toLowerCase()).filter(s => EMAIL_RE.test(s)).slice(0, 10);
  }
  const cc = cleanList(body.cc);
  const bcc = cleanList(body.bcc);
  const toOverride = body.to_override ? String(body.to_override).trim().toLowerCase() : null;
  if (toOverride && !EMAIL_RE.test(toOverride)) return jsonResponse(400, { error: "invalid_to_override" });

  // ----- Load the inbound row -----
  const fetchInbound = await fetch(
    `${SUPABASE_URL}/rest/v1/inbound_emails?id=eq.${encodeURIComponent(inReplyToId)}&select=*`,
    {
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      },
    }
  );
  if (!fetchInbound.ok) {
    return jsonResponse(502, { error: "inbound_fetch_failed", detail: await fetchInbound.text() });
  }
  const inbound = (await fetchInbound.json())[0];
  if (!inbound) return jsonResponse(404, { error: "inbound_not_found" });

  const fromAlias = inbound.to_alias;
  if (!ALLOWED_ALIASES.has(fromAlias)) {
    return jsonResponse(400, { error: "alias_not_allowed", alias: fromAlias });
  }
  const fromAddress = `${fromAlias}@${DOMAIN}`;
  const fromHeader = `${ALIAS_DISPLAY[fromAlias]} <${fromAddress}>`;
  const recipient = toOverride || inbound.from_address;
  if (!EMAIL_RE.test(recipient)) return jsonResponse(400, { error: "invalid_recipient" });

  // ----- Threading headers -----
  const inReplyTo = inbound.message_id || null;
  const refs = [inbound.email_refs, inbound.message_id].filter(Boolean).join(" ").trim() || null;
  const replyHeaders = {};
  if (inReplyTo) replyHeaders["In-Reply-To"] = inReplyTo;
  if (refs) replyHeaders["References"] = refs;

  // ----- Send via Resend -----
  const resendBody = {
    from: fromHeader,
    to: [recipient],
    subject,
    reply_to: fromAddress,
    text: textBody || undefined,
    html: htmlBody || undefined,
    headers: Object.keys(replyHeaders).length ? replyHeaders : undefined,
    cc: cc.length ? cc : undefined,
    bcc: bcc.length ? bcc : undefined,
    tags: [{ name: "category", value: "admin-reply" }, { name: "alias", value: fromAlias }],
  };
  const resendRes = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(resendBody),
  });
  const resendData = await resendRes.json().catch(() => ({}));
  if (!resendRes.ok) {
    console.error("Resend send failed:", resendRes.status, resendData);
    // Log the failure in outbound_replies for audit.
    await fetch(`${SUPABASE_URL}/rest/v1/outbound_replies`, {
      method: "POST",
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({
        in_reply_to_id: inReplyToId,
        from_alias: fromAlias,
        from_address: fromAddress,
        to_address: recipient,
        cc: cc.length ? cc : null,
        bcc: bcc.length ? bcc : null,
        subject,
        text_body: textBody || null,
        html_body: htmlBody || null,
        in_reply_to: inReplyTo,
        email_refs: refs,
        status: "failed",
        error_message: JSON.stringify(resendData).slice(0, 1000),
      }),
    }).catch(() => {});
    return jsonResponse(502, { error: "resend_failed", detail: resendData });
  }

  // ----- Persist the reply + mark inbound as replied -----
  const sentAt = new Date().toISOString();
  const replyRow = {
    in_reply_to_id: inReplyToId,
    from_alias: fromAlias,
    from_address: fromAddress,
    to_address: recipient,
    cc: cc.length ? cc : null,
    bcc: bcc.length ? bcc : null,
    subject,
    text_body: textBody || null,
    html_body: htmlBody || null,
    in_reply_to: inReplyTo,
    email_refs: refs,
    status: "sent",
    resend_email_id: resendData.id || null,
    sent_at: sentAt,
  };
  await fetch(`${SUPABASE_URL}/rest/v1/outbound_replies`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify(replyRow),
  }).catch(err => console.error("outbound_replies insert error:", err));

  await fetch(`${SUPABASE_URL}/rest/v1/inbound_emails?id=eq.${encodeURIComponent(inReplyToId)}`, {
    method: "PATCH",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify({ status: "replied", replied_at: sentAt }),
  }).catch(err => console.error("inbound_emails patch error:", err));

  return jsonResponse(200, {
    ok: true,
    resend_email_id: resendData.id || null,
    from: fromHeader,
    to: recipient,
  });
};
