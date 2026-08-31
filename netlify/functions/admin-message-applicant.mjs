// ============================================================
// America250 CFC — Admin: message an applicant directly
//
// POST { id (applications.id), subject, text }
// Sends a fresh (not-in-reply-to-anything) email straight to an
// applicant's lead_email, from hello@america250cfc.org with
// Reply-To apply@america250cfc.org — so if they reply, it lands in the
// existing admin inbox (inbound-email.mjs / send-reply.mjs) under the
// "apply" alias like any other inbound thread.
//
// Logged to outbound_replies with in_reply_to_id = null (that column is
// nullable — this send isn't a reply to any inbound_emails row) so it
// still shows up in the same audit trail as inbox replies.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ALLOWED_ORIGIN = "https://america250cfc.org";
const FROM_ALIAS = "hello";
const FROM_ADDRESS = "hello@america250cfc.org";
const FROM_HEADER = "America250 CFC <hello@america250cfc.org>";
const REPLY_TO = "apply@america250cfc.org";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;

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
function anyEq(cands, expected) {
  let found = false;
  for (const c of cands) if (constantTimeEq(c, expected)) found = true;
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

export const handler = async (event) => {
  if (!SUPABASE_SERVICE_ROLE_KEY) return jsonResponse(500, { error: "config_missing", detail: "SUPABASE_SERVICE_ROLE_KEY" });
  if (!ADMIN_PASSWORD) return jsonResponse(500, { error: "config_missing", detail: "ADMIN_PASSWORD" });
  if (!RESEND_API_KEY) return jsonResponse(500, { error: "config_missing", detail: "RESEND_API_KEY" });
  if (event.httpMethod !== "POST") return jsonResponse(405, { error: "method_not_allowed" });

  // Admin cookie
  const cands = cookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyEq(cands, adminToken(ADMIN_PASSWORD))) return jsonResponse(401, { error: "unauthorized" });
  // CSRF: reject a declared foreign origin
  const origin = event.headers.origin || event.headers.Origin || "";
  if (origin && origin !== ALLOWED_ORIGIN) return jsonResponse(403, { error: "forbidden_origin" });

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { return jsonResponse(400, { error: "invalid_json" }); }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return jsonResponse(400, { error: "invalid_payload" });

  const id = typeof body.id === "string" ? body.id : "";
  if (!UUID_RE.test(id)) return jsonResponse(400, { error: "invalid_id" });

  // Header-injection defense — strip CR/LF from the subject.
  const subject = String(body.subject || "").replace(/[\r\n]+/g, " ").trim().slice(0, 500);
  if (!subject) return jsonResponse(400, { error: "missing_subject" });
  const text = String(body.text || "").trim().slice(0, 20000);
  if (!text) return jsonResponse(400, { error: "missing_text" });

  const sb = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` };
  const rowRes = await fetch(`${SUPABASE_URL}/rest/v1/applications?id=eq.${encodeURIComponent(id)}&select=id,lead_email,lead_name,proj_title`, { headers: sb });
  if (!rowRes.ok) return jsonResponse(502, { error: "fetch_failed" });
  const rows = await rowRes.json();
  const row = Array.isArray(rows) ? rows[0] : null;
  if (!row) return jsonResponse(404, { error: "not_found" });

  const recipient = typeof row.lead_email === "string" ? row.lead_email.trim().toLowerCase() : "";
  if (!EMAIL_RE.test(recipient)) return jsonResponse(422, { error: "no_valid_email" });

  const resendRes = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: FROM_HEADER,
      to: [recipient],
      reply_to: REPLY_TO,
      subject,
      text,
      tags: [{ name: "category", value: "admin-direct-message" }],
    }),
  });
  const resendData = await resendRes.json().catch(() => ({}));

  const sentAt = new Date().toISOString();
  const auditRow = {
    in_reply_to_id: null,
    from_alias: FROM_ALIAS,
    from_address: FROM_ADDRESS,
    to_address: recipient,
    subject,
    text_body: text,
    status: resendRes.ok ? "sent" : "failed",
    resend_email_id: resendData.id || null,
    error_message: resendRes.ok ? null : JSON.stringify(resendData).slice(0, 1000),
    sent_at: resendRes.ok ? sentAt : null,
  };
  await fetch(`${SUPABASE_URL}/rest/v1/outbound_replies`, {
    method: "POST",
    headers: { ...sb, "Content-Type": "application/json", Prefer: "return=minimal" },
    body: JSON.stringify(auditRow),
  }).catch((err) => console.error("outbound_replies insert error:", err));

  if (!resendRes.ok) {
    console.error("admin-message-applicant: Resend send failed:", resendRes.status, resendData);
    return jsonResponse(502, { error: "send_failed" });
  }

  return jsonResponse(200, { ok: true, resend_email_id: resendData.id || null, sent_to: recipient });
};
