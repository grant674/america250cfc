/* ============================================================
   America250 CFC — Judge portal
   Magic-link auth via Supabase Auth, queue rendering with RLS.
   All Supabase calls use raw fetch + JWT — no SDK dependency, no
   CSP-relaxation required.
   ============================================================ */

(function () {
  'use strict';

  // ---- Config (anon key loaded from /netlify/functions/judge-config) ----
  var SUPABASE_URL = '';
  var SUPABASE_ANON_KEY = '';

  // ---- LocalStorage keys ----
  var LS_SESSION = 'nn_judge_session';   // { access_token, refresh_token, expires_at, user_id }

  // ---- DOM ----
  var $loading  = document.getElementById('judge-loading');
  var $signin   = document.getElementById('judge-signin');
  var $sent     = document.getElementById('judge-sent');
  var $denied   = document.getElementById('judge-denied');
  var $queue    = document.getElementById('judge-queue');
  var $errorPan = document.getElementById('judge-error');
  var $who      = document.getElementById('judge-who');
  var $signoutBtn = document.getElementById('btn-signout');

  var screens = { loading: $loading, signin: $signin, sent: $sent, denied: $denied, queue: $queue, error: $errorPan };
  function show(name) {
    Object.keys(screens).forEach(function (k) { screens[k].hidden = (k !== name); });
  }

  function escHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ---- State ----
  var state = {
    session: null,         // current Supabase session
    judge: null,           // judges row
    applications: [],      // applications I can see
    scores: [],            // my scores (by judge_id RLS)
    queueFilter: 'todo',
  };

  // ---- Session storage ----
  function loadSession() {
    try {
      var raw = localStorage.getItem(LS_SESSION);
      if (!raw) return null;
      var sess = JSON.parse(raw);
      if (!sess || !sess.access_token) return null;
      // Tokens expire after ~1h. If expired, drop.
      if (sess.expires_at && Date.now() / 1000 > sess.expires_at + 30) return null;
      return sess;
    } catch (_) { return null; }
  }
  function saveSession(sess) {
    if (sess) localStorage.setItem(LS_SESSION, JSON.stringify(sess));
    else localStorage.removeItem(LS_SESSION);
  }

  // ---- Supabase REST helpers ----
  function sbFetch(path, opts) {
    opts = opts || {};
    var url = SUPABASE_URL + path;
    var headers = Object.assign({
      apikey: SUPABASE_ANON_KEY,
      'Content-Type': 'application/json',
    }, opts.headers || {});
    if (state.session && state.session.access_token) {
      headers.Authorization = 'Bearer ' + state.session.access_token;
    }
    return fetch(url, Object.assign({}, opts, { headers: headers }));
  }

  // ---- Auth flow ----
  async function sendMagicLink(email) {
    var res = await fetch(SUPABASE_URL + '/auth/v1/otp', {
      method: 'POST',
      headers: { apikey: SUPABASE_ANON_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: email,
        options: {
          shouldCreateUser: false,
          emailRedirectTo: window.location.origin + '/judge/',
        },
      }),
    });
    if (!res.ok) {
      var err = await res.text();
      throw new Error(err || 'Could not send link.');
    }
    // Supabase responds 200 whether or not the user exists (no enumeration).
    return true;
  }

  function parseHashFragment() {
    // Magic-link callback: URL becomes /judge/#access_token=...&refresh_token=...&expires_in=3600&token_type=bearer
    if (!window.location.hash || window.location.hash.length < 2) return null;
    var params = new URLSearchParams(window.location.hash.slice(1));
    var access = params.get('access_token');
    if (!access) return null;
    var refresh = params.get('refresh_token');
    var expiresIn = parseInt(params.get('expires_in') || '3600', 10);
    return {
      access_token: access,
      refresh_token: refresh,
      expires_at: Math.floor(Date.now() / 1000) + expiresIn,
      type: params.get('type') || null,  // 'magiclink', 'invite', etc.
    };
  }

  async function fetchUserFromAccessToken() {
    var res = await fetch(SUPABASE_URL + '/auth/v1/user', {
      headers: {
        apikey: SUPABASE_ANON_KEY,
        Authorization: 'Bearer ' + state.session.access_token,
      },
    });
    if (!res.ok) throw new Error('Session expired.');
    return await res.json();
  }

  async function signOut() {
    if (state.session) {
      // Best-effort logout call; ignore errors.
      try {
        await fetch(SUPABASE_URL + '/auth/v1/logout', {
          method: 'POST',
          headers: {
            apikey: SUPABASE_ANON_KEY,
            Authorization: 'Bearer ' + state.session.access_token,
          },
        });
      } catch (_) {}
    }
    saveSession(null);
    state.session = null;
    state.judge = null;
    state.applications = [];
    state.scores = [];
    $who.hidden = true;
    $signoutBtn.hidden = true;
    show('signin');
  }

  // ---- Data fetch ----
  async function fetchJudgeRow(userId) {
    var res = await sbFetch('/rest/v1/judges?id=eq.' + encodeURIComponent(userId) + '&select=id,name,email,affiliation,active');
    if (!res.ok) throw new Error('Could not load judge profile.');
    var rows = await res.json();
    return rows[0] || null;
  }

  async function fetchApplications() {
    // Blind review (#6): no applicant/org identity columns — the queue
    // identifies applications by project title only.
    var fields = [
      'id', 'created_at', 'status',
      'proj_title', 'proj_summary', 'proj_category', 'proj_phase',
      'proj_city', 'proj_state', 'proj_communities',
      'proj_budget_total', 'proj_budget_raised', 'proj_use_of_funds', 'proj_video_url',
      'impact_community', 'impact_innovation', 'impact_feasibility',
      'impact_sustainability', 'impact_founder_team',
    ].join(',');
    var res = await sbFetch(
      '/rest/v1/applications?status=in.(in_judging,approved,finalist,winner)' +
      '&select=' + fields +
      '&order=created_at.asc'
    );
    if (!res.ok) throw new Error('Could not load applications.');
    return await res.json();
  }

  async function fetchOwnScores() {
    var res = await sbFetch(
      '/rest/v1/scores?judge_id=eq.' + encodeURIComponent(state.session.user_id) +
      '&select=id,application_id,dim_community,dim_innovation,dim_feasibility,dim_sustainability,dim_founder_team,total,status,submitted_at,updated_at'
    );
    if (!res.ok) throw new Error('Could not load scores.');
    return await res.json();
  }

  // ---- Render ----
  function progressOf(score) {
    if (!score) return { done: 0, total: 5 };
    var done = ['dim_community','dim_innovation','dim_feasibility','dim_sustainability','dim_founder_team']
      .filter(function (k) { return score[k] != null; }).length;
    return { done: done, total: 5 };
  }

  function statusForApp(score) {
    if (!score) return 'todo';
    if (score.status === 'submitted') return 'submitted';
    if (score.status === 'recused')   return 'recused';
    return 'draft';
  }

  function renderQueue() {
    var byApp = {};
    state.scores.forEach(function (s) { byApp[s.application_id] = s; });

    var rows = state.applications.map(function (app) {
      var score = byApp[app.id];
      return { app: app, score: score, status: statusForApp(score) };
    });

    // Filter
    var filter = state.queueFilter;
    var filtered = rows.filter(function (r) {
      if (filter === 'all') return true;
      return r.status === filter;
    });

    // Sort: not-started first, then in-progress, submitted last
    var ord = { todo: 0, draft: 1, submitted: 2, recused: 3 };
    filtered.sort(function (a, b) {
      var d = (ord[a.status] || 0) - (ord[b.status] || 0);
      if (d !== 0) return d;
      return (a.app.created_at < b.app.created_at) ? -1 : 1;
    });

    // Counts
    var counts = { todo: 0, draft: 0, submitted: 0, recused: 0, all: rows.length };
    rows.forEach(function (r) { counts[r.status] = (counts[r.status] || 0) + 1; });
    document.getElementById('cnt-todo').textContent      = counts.todo      || 0;
    document.getElementById('cnt-draft').textContent     = counts.draft     || 0;
    document.getElementById('cnt-submitted').textContent = counts.submitted || 0;
    document.getElementById('cnt-recused').textContent   = counts.recused   || 0;
    document.getElementById('cnt-all').textContent       = counts.all       || 0;

    // Progress card (counts only "submitted" toward done)
    document.getElementById('progress-done').textContent  = counts.submitted;
    document.getElementById('progress-total').textContent = counts.all;
    var pct = counts.all ? Math.round(100 * counts.submitted / counts.all) : 0;
    document.getElementById('progress-fill').style.width = pct + '%';

    // Lede line
    var lede = counts.all + ' application' + (counts.all === 1 ? '' : 's') + ' in the scoring queue. ' +
               counts.todo + ' not started, ' +
               counts.draft + ' in progress, ' +
               counts.submitted + ' submitted.';
    document.getElementById('queue-lede').textContent = lede;

    // Render list
    var list = document.getElementById('queue-list');
    if (filtered.length === 0) {
      list.innerHTML = '';
      document.getElementById('queue-empty').hidden = false;
      return;
    }
    document.getElementById('queue-empty').hidden = true;

    var html = filtered.map(function (r) {
      var prog = progressOf(r.score);
      var pct = prog.total ? Math.round(100 * prog.done / prog.total) : 0;
      var loc = (r.app.proj_city || '') + (r.app.proj_state ? ', ' + r.app.proj_state : '');
      var badge = '';
      if (r.status === 'todo')      badge = '<span class="q-badge q-badge--todo">Not started</span>';
      if (r.status === 'draft')     badge = '<span class="q-badge q-badge--draft">In progress</span>';
      if (r.status === 'submitted') badge = '<span class="q-badge q-badge--submitted">Submitted</span>';
      if (r.status === 'recused')   badge = '<span class="q-badge q-badge--recused">Recused</span>';

      var cta = r.status === 'submitted' || r.status === 'recused'
        ? 'View your scores'
        : (r.status === 'draft' ? 'Continue scoring' : 'Start scoring');

      return [
        '<li>',
          '<a class="queue-card" href="/judge/score/?id=', escHtml(r.app.id), '">',
            '<div>',
              '<div class="queue-card__meta">',
                escHtml((r.app.proj_category || '').replace(/-/g, ' ')),
                ' &nbsp;·&nbsp; ',
                escHtml(loc),
                badge,
              '</div>',
              '<h3 class="queue-card__title">', escHtml(r.app.proj_title || '—'), '</h3>',
              '<p class="queue-card__sub">', escHtml(r.app.proj_summary || ''), '</p>',
            '</div>',
            '<div class="queue-card__progress">',
              '<span>', String(prog.done), ' of ', String(prog.total), ' dimensions</span>',
              '<div class="queue-card__progress-bar"><div class="queue-card__progress-fill" style="width:', String(pct), '%"></div></div>',
            '</div>',
            '<span class="queue-card__cta">', cta, ' <span class="arr">→</span></span>',
          '</a>',
        '</li>',
      ].join('');
    }).join('');
    list.innerHTML = html;
  }

  // ---- Bootstrap ----
  async function loadConfig() {
    var res = await fetch('/.netlify/functions/judge-config', { credentials: 'omit' });
    if (!res.ok) throw new Error('Config endpoint failed.');
    var data = await res.json();
    SUPABASE_URL = data.supabase_url;
    SUPABASE_ANON_KEY = data.supabase_anon_key;
  }

  async function loadAuthedQueue() {
    show('loading');
    state.judge = await fetchJudgeRow(state.session.user_id);
    if (!state.judge || !state.judge.active) {
      show('denied');
      return;
    }
    $who.textContent = state.judge.name;
    $who.hidden = false;
    $signoutBtn.hidden = false;

    var results = await Promise.all([fetchApplications(), fetchOwnScores()]);
    state.applications = results[0] || [];
    state.scores = results[1] || [];

    renderQueue();
    show('queue');
  }

  async function bootstrap() {
    try {
      await loadConfig();

      // 1) Magic-link callback?
      var hashSess = parseHashFragment();
      if (hashSess) {
        state.session = hashSess;
        // Get the user id so we can scope follow-up queries.
        try {
          var user = await fetchUserFromAccessToken();
          state.session.user_id = user.id;
          saveSession(state.session);
        } catch (e) {
          show('signin');
          return;
        }
        // Clean the hash from the URL so a refresh doesn't re-process.
        history.replaceState(null, '', window.location.pathname);
      } else {
        // 2) Existing session?
        state.session = loadSession();
        if (!state.session) {
          show('signin');
          return;
        }
        // If we don't have user_id (older session shape), fetch it.
        if (!state.session.user_id) {
          try {
            var u = await fetchUserFromAccessToken();
            state.session.user_id = u.id;
            saveSession(state.session);
          } catch (_) {
            saveSession(null);
            state.session = null;
            show('signin');
            return;
          }
        }
      }

      await loadAuthedQueue();
    } catch (err) {
      console.error('Bootstrap error:', err);
      document.getElementById('error-msg').textContent = err.message || 'Unknown error.';
      show('error');
    }
  }

  // ---- Event wiring ----
  document.getElementById('judge-signin-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var email = document.getElementById('signin-email').value.trim().toLowerCase();
    var err = document.getElementById('signin-err');
    var btn = document.getElementById('signin-submit');
    err.hidden = true;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      err.textContent = 'Please enter a valid email address.';
      err.hidden = false;
      return;
    }
    btn.disabled = true;
    var prev = btn.innerHTML;
    btn.innerHTML = 'Sending…';
    try {
      await sendMagicLink(email);
      document.getElementById('sent-email').textContent = email;
      show('sent');
    } catch (e2) {
      err.textContent = 'Could not send the link. Please try again or write apply@america250cfc.org.';
      err.hidden = false;
    } finally {
      btn.disabled = false;
      btn.innerHTML = prev;
    }
  });

  document.getElementById('btn-back-signin').addEventListener('click', function () {
    show('signin');
  });
  document.getElementById('btn-denied-signout').addEventListener('click', signOut);
  document.getElementById('btn-signout').addEventListener('click', signOut);
  document.getElementById('btn-retry').addEventListener('click', function () {
    bootstrap();
  });

  document.querySelectorAll('[data-queue-filter]').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('[data-queue-filter]').forEach(function (x) { x.classList.remove('is-active'); });
      b.classList.add('is-active');
      state.queueFilter = b.getAttribute('data-queue-filter');
      renderQueue();
    });
  });

  bootstrap();
})();
