/* ============================================================
   America250 CFC — Judge portal: shared sign-in session
   Used by /judge/ and /judge/score/. Keeps the Supabase session in
   localStorage and renews it with the refresh token shortly before the
   access token expires (about hourly), so a judge stays signed in while
   they work instead of being bounced to the sign-in page mid-scoring.
   ============================================================ */

window.CFCJudgeSession = (function () {
  'use strict';
  var LS_KEY = 'nn_judge_session';   // { access_token, refresh_token, expires_at, user_id }
  var RENEW_EARLY_S = 90;            // renew this long before expiry

  function now() { return Date.now() / 1000; }
  function read() {
    try {
      var s = JSON.parse(localStorage.getItem(LS_KEY) || 'null');
      return s && s.access_token ? s : null;
    } catch (_) { return null; }
  }
  function write(s) {
    try {
      if (s) localStorage.setItem(LS_KEY, JSON.stringify(s));
      else localStorage.removeItem(LS_KEY);
    } catch (_) {}
  }
  // Build a session from a /auth/v1/token response (password or refresh grant).
  function fromTokenResponse(d, prev) {
    return {
      access_token: d.access_token,
      refresh_token: d.refresh_token || (prev && prev.refresh_token) || null,
      expires_at: Math.floor(now()) + (parseInt(d.expires_in, 10) || 3600),
      user_id: (d.user && d.user.id) || (prev && prev.user_id) || null,
    };
  }
  function usable(s) { return !!s && (!s.expires_at || now() < s.expires_at + 30); }

  var inflight = null;
  // Returns a session that is good to use right now, renewing it first if it
  // is about to expire, or null if there is none / it can no longer be renewed.
  // cfg = { url: SUPABASE_URL, key: SUPABASE_ANON_KEY }
  function fresh(cfg) {
    var s = read();
    if (!s) return Promise.resolve(null);
    if (!s.expires_at || now() < s.expires_at - RENEW_EARLY_S) return Promise.resolve(s);
    if (!s.refresh_token || !cfg || !cfg.url) return Promise.resolve(usable(s) ? s : null);
    if (!inflight) {
      inflight = (async function () {
        // Another tab (queue + scoring page open together) may have renewed
        // already; refresh tokens are single-use, so use its result.
        var latest = read() || s;
        if (latest.expires_at && now() < latest.expires_at - RENEW_EARLY_S) return latest;
        try {
          var res = await fetch(cfg.url + '/auth/v1/token?grant_type=refresh_token', {
            method: 'POST',
            headers: { apikey: cfg.key, 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: latest.refresh_token }),
          });
          if (res.ok) {
            var renewed = fromTokenResponse(await res.json(), latest);
            write(renewed);
            return renewed;
          }
          if (res.status === 400 || res.status === 401) {
            // Refused. If another tab won the race its session is now stored;
            // otherwise the sign-in really is over.
            var other = read();
            if (other && other.access_token !== latest.access_token && usable(other)) return other;
            if (!usable(latest)) write(null);
            return usable(latest) ? latest : null;
          }
          return usable(latest) ? latest : null;   // server hiccup: keep going while the token lasts
        } catch (_) {
          return usable(latest) ? latest : null;   // offline: same
        }
      })().finally(function () { inflight = null; });
    }
    return inflight;
  }

  return { read: read, write: write, fresh: fresh, fromTokenResponse: fromTokenResponse };
})();
