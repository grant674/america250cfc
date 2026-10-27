// ============================================================
// America250 CFC — Admin: message someone about an unsubmitted draft
//
// POST { token (application_drafts.token), subject, text }
// Same shape as admin-message-applicant.mjs, but sources the recipient
// from application_drafts instead of applications — for nudging someone
// who started the apply form, left an email address, and never finished.
// Sends from hello@america250cfc.org, Reply-To apply@america250cfc.org —
// a reply lands in the existing admin inbox under the "apply" alias.
//
// Always appends a resume link (/apply/?resume=<token>, the same link
// the apply form's own "copy my resume link" button generates) to the
// message server-side, so it's guaranteed to be in every email this
// endpoint sends regardless of what the admin types — not left to the
// admin to remember to paste it in.
//
// Logged to outbound_replies with in_reply_to_id = null (nullable column
// — this isn't a reply to any inbound_emails row) for the same audit
// trail as inbox replies and applicant messages.
//
// Refuses (409 already_submitted) when the recipient already has a
// submitted application, so a reminder — including one from "Remind all"
// working off a stale list — can never prompt a duplicate submission.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ALLOWED_ORIGIN = "https://america250cfc.org";
const SITE_ORIGIN = "https://america250cfc.org";
const FROM_ALIAS = "hello";
const FROM_ADDRESS = "hello@america250cfc.org";
const FROM_HEADER = "America250 CFC <hello@america250cfc.org>";
const REPLY_TO = "apply@america250cfc.org";

const TOKEN_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
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
function anyEq(c, e) { let f = false; for (const x of c) if (constantTimeEq(x, e)) f = true; return f; }
// Escape LIKE wildcards so ilike is a case-insensitive exact match.
function likeEscape(s) { return s.replace(/[\\%_]/g, (c) => "\\" + c); }
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

  const cands = cookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyEq(cands, adminToken(ADMIN_PASSWORD))) return jsonResponse(401, { error: "unauthorized" });
  const origin = event.headers.origin || event.headers.Origin || "";
  if (origin && origin !== ALLOWED_ORIGIN) return jsonResponse(403, { error: "forbidden_origin" });

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { return jsonResponse(400, { error: "invalid_json" }); }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return jsonResponse(400, { error: "invalid_payload" });

  const token = typeof body.token === "string" ? body.token : "";
  if (!TOKEN_RE.test(token)) return jsonResponse(400, { error: "invalid_token" });

  const subject = String(body.subject || "").replace(/[\r\n]+/g, " ").trim().slice(0, 500);
  if (!subject) return jsonResponse(400, { error: "missing_subject" });
  const text = String(body.text || "").trim().slice(0, 20000);
  if (!text) return jsonResponse(400, { error: "missing_text" });

  const sb = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` };
  const rowRes = await fetch(`${SUPABASE_URL}/rest/v1/application_drafts?token=eq.${encodeURIComponent(token)}&select=token,email,data`, { headers: sb });
  if (!rowRes.ok) return jsonResponse(502, { error: "fetch_failed" });
  const rows = await rowRes.json();
  const draft = Array.isArray(rows) ? rows[0] : null;
  if (!draft) return jsonResponse(404, { error: "not_found" });

  const fromDraftField = draft.data && draft.data.fields && typeof draft.data.fields.lead_email === "string"
    ? draft.data.fields.lead_email
    : "";
  const recipient = (draft.email || fromDraftField || "").trim().toLowerCase();
  if (!EMAIL_RE.test(recipient)) return jsonResponse(422, { error: "no_valid_email" });

  const appRes = await fetch(`${SUPABASE_URL}/rest/v1/applications?lead_email=ilike.${encodeURIComponent(likeEscape(recipient))}&select=id&limit=1`, { headers: sb });
  if (!appRes.ok) return jsonResponse(502, { error: "fetch_failed" });
  const apps = await appRes.json();
  if (Array.isArray(apps) && apps.length) return jsonResponse(409, { error: "already_submitted" });

  const resumeUrl = `${SITE_ORIGIN}/apply/?resume=${encodeURIComponent(token)}`;
  const fullText = text + `\n\n— \nPick up right where you left off: ${resumeUrl}`;

  const resendRes = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: FROM_HEADER,
      to: [recipient],
      reply_to: REPLY_TO,
      subject,
      text: fullText,
      tags: [{ name: "category", value: "admin-draft-nudge" }],
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
    text_body: fullText,
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
    console.error("admin-message-draft: Resend send failed:", resendRes.status, resendData);
    return jsonResponse(502, { error: "send_failed" });
  }

  return jsonResponse(200, { ok: true, resend_email_id: resendData.id || null, sent_to: recipient });
};
