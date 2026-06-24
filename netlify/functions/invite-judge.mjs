// ============================================================
// America250 CFC — Admin: invite a judge
// POST { email, name, affiliation? }
// Verifies the admin cookie. Uses Supabase Auth Admin API to
// create the auth.users row + send the magic-link invite email,
// then inserts the matching row into public.judges via the
// service-role key. Records the action in audit_log.
// ============================================================

import { createHmac, timingSafeEqual } from "node:crypto";

const SUPABASE_URL = "https://emhcsinxtxshdgiceofa.supabase.co";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SITE_ORIGIN = "https://america250cfc.org";

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
function noStoreHeaders() {
  return {
    "Cache-Control": "private, no-store, no-cache, must-revalidate, max-age=0",
    "Vary": "Cookie",
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  };
}

function isValidEmail(s) {
  return typeof s === "string" && /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(s) && s.length <= 320;
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
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: noStoreHeaders(), body: JSON.stringify({ error: "method_not_allowed" }) };
  }

  // ----- Auth gate (admin cookie) -----
  const candidates = parseCookieValues(event.headers.cookie || event.headers.Cookie || "", "nn_admin");
  const expected = adminToken(ADMIN_PASSWORD);
  if (!anyConstantTimeEq(candidates, expected)) {
    return { statusCode: 401, headers: noStoreHeaders(), body: JSON.stringify({ error: "unauthorized" }) };
  }
  if (!originAllowed(event)) {
    return { statusCode: 403, headers: noStoreHeaders(), body: JSON.stringify({ error: "forbidden_origin" }) };
  }

  // ----- Parse + validate -----
  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return { statusCode: 400, headers: noStoreHeaders(), body: JSON.stringify({ error: "invalid_json" }) }; }
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return { statusCode: 400, headers: noStoreHeaders(), body: JSON.stringify({ error: "invalid_payload" }) };
  }

  const email = String(body.email || "").trim().toLowerCase();
  const name = String(body.name || "").trim().slice(0, 200);
  const affiliation = body.affiliation ? String(body.affiliation).trim().slice(0, 200) : null;

  if (!isValidEmail(email)) {
    return { statusCode: 400, headers: noStoreHeaders(), body: JSON.stringify({ error: "invalid_email" }) };
  }
  if (!name) {
    return { statusCode: 400, headers: noStoreHeaders(), body: JSON.stringify({ error: "missing_name" }) };
  }

  // ----- 1) Invite the user via Supabase Auth (GoTrue).
  //         POST /auth/v1/invite — creates auth.users + sends magic-link email.
  //         redirect_to goes in the QUERY STRING per GoTrue spec (not the body).
  //         After clicking the link, Supabase bounces to ${SITE_ORIGIN}/judge/
  //         with tokens in the URL hash; /judge/ JS parses the hash + stores
  //         the session.
  const inviteUrl = `${SUPABASE_URL}/auth/v1/invite?redirect_to=${encodeURIComponent(`${SITE_ORIGIN}/judge/`)}`;
  const inviteRes = await fetch(inviteUrl, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      data: { name, affiliation, role: "judge" },
    }),
  });

  if (!inviteRes.ok) {
    const errText = await inviteRes.text();
    // If the user already exists, Supabase returns 422. That's fine — fall
    // through to inserting into public.judges (or re-inviting via OTP later).
    if (inviteRes.status !== 422) {
      console.error("Supabase invite failed:", inviteRes.status, errText);
      return { statusCode: 502, headers: noStoreHeaders(), body: JSON.stringify({ error: "invite_failed", detail: errText }) };
    }
  }

  const inviteData = await (inviteRes.ok ? inviteRes.json() : Promise.resolve(null));

  // If we created a fresh auth.users row, grab the new id. Otherwise look it up.
  let userId = inviteData?.user?.id || inviteData?.id;
  if (!userId) {
    // Look up the existing auth.users row by email.
    const lookupRes = await fetch(
      `${SUPABASE_URL}/auth/v1/admin/users?email=${encodeURIComponent(email)}`,
      {
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        },
      },
    );
    if (!lookupRes.ok) {
      const errText = await lookupRes.text();
      console.error("User lookup failed:", lookupRes.status, errText);
      return { statusCode: 502, headers: noStoreHeaders(), body: JSON.stringify({ error: "lookup_failed" }) };
    }
    const lookupData = await lookupRes.json();
    userId = lookupData?.users?.[0]?.id;
    if (!userId) {
      return { statusCode: 502, headers: noStoreHeaders(), body: JSON.stringify({ error: "user_not_resolved" }) };
    }
  }

  // ----- 2) Upsert public.judges with the matching id.
  const judgeRow = {
    id: userId,
    name,
    email,
    affiliation,
    active: true,
    invited_at: new Date().toISOString(),
  };
  const upsertRes = await fetch(`${SUPABASE_URL}/rest/v1/judges`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "resolution=merge-duplicates,return=minimal",
    },
    body: JSON.stringify(judgeRow),
  });
  if (!upsertRes.ok) {
    const errText = await upsertRes.text();
    console.error("judges upsert failed:", upsertRes.status, errText);
    return { statusCode: 502, headers: noStoreHeaders(), body: JSON.stringify({ error: "judges_insert_failed", detail: errText }) };
  }

  // ----- 3) Audit log.
  await fetch(`${SUPABASE_URL}/rest/v1/audit_log`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify({
      actor: "admin",
      action: "judge_invited",
      target_table: "judges",
      target_id: userId,
      after_data: { email, name, affiliation },
    }),
  }).catch((err) => console.error("audit_log insert failed:", err));

  return {
    statusCode: 200,
    headers: noStoreHeaders(),
    body: JSON.stringify({ ok: true, judge_id: userId, email, name }),
  };
};
