// ============================================================
// America250 CFC — Admin: send a finalist / winner notification email
// Admin-cookie gated. POST { id, kind: "finalist" | "winner" }.
// Only sends when the application's status already matches the kind, so a
// notification can't be emailed to someone who isn't actually a finalist/winner.
// Logs the send to audit_log.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = "America250 CFC <hello@america250cfc.org>";
const EMAIL_REPLY_TO = "apply@america250cfc.org";
const ALLOWED_ORIGIN = "https://america250cfc.org";
const SITE_ORIGIN = "https://america250cfc.org";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// One-click unsubscribe link, signed with NN_AUTH_SECRET (same scheme as the
// `unsubscribe` function verifies). Lets recipients opt out of future updates.
function unsubUrlFor(email) {
  const secret = process.env.NN_AUTH_SECRET;
  if (!secret) return null;
  const token = createHmac("sha256", secret).update("nn-unsub-v1:" + email.toLowerCase()).digest("hex");
  return `${SITE_ORIGIN}/.netlify/functions/unsubscribe?e=${encodeURIComponent(email.toLowerCase())}&t=${token}`;
}

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
function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function firstName(full) { return (String(full || "").trim().split(/\s+/)[0]) || "there"; }
const noStore = { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

// ---- Editable templates. Subject + plain text + minimal HTML. ----
function template(kind, first, title) {
  const safeTitle = title || "your project";
  if (kind === "winner") {
    return {
      subject: "You're a winner — America250 Community Futures Challenge",
      text: `Hi ${first},\n\nCongratulations — ${safeTitle} has been selected as one of five winners of the America250 Community Futures Challenge. You'll receive a $50,000 grant to bring it to life.\n\nOur team will be in touch shortly with next steps, grant logistics, and details about the recognition event in Phoenix.\n\nWith admiration,\nThe America250 Community Futures Challenge team\nA program of PMI U.S.`,
      html: `<p>Hi ${esc(first)},</p><p>Congratulations — <strong>${esc(safeTitle)}</strong> has been selected as one of five winners of the America250 Community Futures Challenge. You'll receive a <strong>$50,000 grant</strong> to bring it to life.</p><p>Our team will be in touch shortly with next steps, grant logistics, and details about the recognition event in Phoenix.</p><p>With admiration,<br/>The America250 Community Futures Challenge team<br/>A program of PMI U.S.</p>`,
    };
  }
  return {
    subject: "You're a finalist — America250 Community Futures Challenge",
    text: `Hi ${first},\n\nGreat news — ${safeTitle} has advanced to the finalist round of the America250 Community Futures Challenge. Out of a nationwide field, your work stood out to our independent panel of judges.\n\nWe'll follow up soon with what to expect next. Thank you for the work you're doing for your community.\n\nWarmly,\nThe America250 Community Futures Challenge team\nA program of PMI U.S.`,
    html: `<p>Hi ${esc(first)},</p><p>Great news — <strong>${esc(safeTitle)}</strong> has advanced to the <strong>finalist round</strong> of the America250 Community Futures Challenge. Out of a nationwide field, your work stood out to our independent panel of judges.</p><p>We'll follow up soon with what to expect next. Thank you for the work you're doing for your community.</p><p>Warmly,<br/>The America250 Community Futures Challenge team<br/>A program of PMI U.S.</p>`,
  };
}

export const handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: noStore, body: JSON.stringify({ error: "method_not_allowed" }) };
  if (!SUPABASE_SERVICE_ROLE_KEY || !ADMIN_PASSWORD || !RESEND_API_KEY) return { statusCode: 500, headers: noStore, body: JSON.stringify({ error: "not_configured" }) };

  const cands = cookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  if (!anyEq(cands, adminToken(ADMIN_PASSWORD))) return { statusCode: 401, headers: noStore, body: JSON.stringify({ error: "unauthorized" }) };
  const origin = event.headers.origin || event.headers.Origin || "";
  if (origin && origin !== ALLOWED_ORIGIN) return { statusCode: 403, headers: noStore, body: JSON.stringify({ error: "forbidden_origin" }) };

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "bad_json" }) }; }
  const id = typeof body.id === "string" ? body.id : "";
  const kind = body.kind === "winner" ? "winner" : body.kind === "finalist" ? "finalist" : "";
  if (!UUID_RE.test(id) || !kind) return { statusCode: 400, headers: noStore, body: JSON.stringify({ error: "invalid_params" }) };

  const sb = { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` };
  const rowRes = await fetch(`${SUPABASE_URL}/rest/v1/applications?id=eq.${encodeURIComponent(id)}&select=id,status,lead_name,lead_email,proj_title`, { headers: sb });
  if (!rowRes.ok) return { statusCode: 502, headers: noStore, body: JSON.stringify({ error: "fetch_failed" }) };
  const row = (await rowRes.json())[0];
  if (!row) return { statusCode: 404, headers: noStore, body: JSON.stringify({ error: "not_found" }) };
  // Guard: only notify when status matches the kind (mark status first).
  if (row.status !== kind) return { statusCode: 409, headers: noStore, body: JSON.stringify({ error: "status_mismatch", status: row.status }) };
  if (!EMAIL_RE.test(row.lead_email || "")) return { statusCode: 422, headers: noStore, body: JSON.stringify({ error: "no_valid_email" }) };

  // Has this recipient unsubscribed from program updates? Finalist/winner notices
  // are application-outcome (transactional) and still send, but we surface the
  // opt-out so the admin can follow up another way if they prefer.
  let recipientUnsubscribed = false;
  try {
    const supRes = await fetch(`${SUPABASE_URL}/rest/v1/email_suppressions?email=eq.${encodeURIComponent((row.lead_email || "").toLowerCase())}&select=email`, { headers: sb });
    if (supRes.ok) recipientUnsubscribed = (await supRes.json()).length > 0;
  } catch { /* non-blocking */ }

  const tpl = template(kind, firstName(row.lead_name), row.proj_title);
  const unsubUrl = unsubUrlFor(row.lead_email);
  const htmlBody = tpl.html + (unsubUrl
    ? `<p style="font-size:11px;color:#888;margin-top:24px;">A program of PMI U.S. · <a href="https://america250cfc.org" style="color:#888;">america250cfc.org</a><br/><a href="${unsubUrl}" style="color:#888;">Unsubscribe from program updates</a>.</p>`
    : "");
  const textBody = tpl.text + (unsubUrl
    ? `\n\n—\nA program of PMI U.S. · https://america250cfc.org\nUnsubscribe from program updates: ${unsubUrl}`
    : "");

  const rs = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: EMAIL_FROM, to: [row.lead_email], reply_to: EMAIL_REPLY_TO,
      subject: tpl.subject, text: textBody, html: htmlBody,
      headers: unsubUrl ? {
        "List-Unsubscribe": `<${unsubUrl}>, <mailto:privacy@america250cfc.org?subject=unsubscribe>`,
        "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
      } : undefined,
      tags: [{ name: "category", value: "admin-notify" }, { name: "kind", value: kind }],
    }),
  });
  const rd = await rs.json().catch(() => ({}));
  if (!rs.ok) { console.error("notify send failed:", rs.status, rd); return { statusCode: 502, headers: noStore, body: JSON.stringify({ error: "send_failed" }) }; }

  // Audit log
  await fetch(`${SUPABASE_URL}/rest/v1/audit_log`, {
    method: "POST",
    headers: { ...sb, "Content-Type": "application/json", Prefer: "return=minimal" },
    body: JSON.stringify({ actor: "admin", action: "notify_" + kind, target_table: "applications", target_id: id, notes: "sent to " + row.lead_email + (recipientUnsubscribed ? " (recipient previously unsubscribed)" : "") }),
  }).catch(() => {});

  return { statusCode: 200, headers: noStore, body: JSON.stringify({ ok: true, sent_to: row.lead_email, recipient_unsubscribed: recipientUnsubscribed }) };
};
