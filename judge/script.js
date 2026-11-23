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
    // Raw GoTrue REST shape (NOT the supabase-js `options` shape, which the
    // REST endpoint silently ignores): the return address goes in the
    // `redirect_to` query parameter and "don't create accounts" is
    // `create_user: false`. Without redirect_to the emailed link lands on the
    // site home page instead of /judge/ and the sign-in is lost.
    var res = await fetch(
      SUPABASE_URL + '/auth/v1/otp?redirect_to=' + encodeURIComponent(window.location.origin + '/judge/'),
      {
        method: 'POST',
        headers: { apikey: SUPABASE_ANON_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, create_user: false }),
      }
    );
    if (res.status === 429) {
      var limited = new Error('rate_limited');
      limited.rateLimited = true;
      throw limited;
    }
    // Not on the judge list: answer exactly like success (no enumeration).
    if (res.status === 400 || res.status === 422) return true;
    if (!res.ok) {
      var err = await res.text();
      throw new Error(err || 'Could not send link.');
    }
    // Supabase responds 200 whether or not the user exists (no enumeration).
    return true;
  }

  // A failed emailed link comes back as /judge/#error=access_denied&error_code=otp_expired&...
  // (already used, expired, or opened twice). Returns a message to show, or null.
  function parseHashError() {
    if (!window.location.hash || window.location.hash.length < 2) return null;
    var params = new URLSearchParams(window.location.hash.slice(1));
    if (!params.get('error') && !params.get('error_code')) return null;
    history.replaceState(null, '', window.location.pathname);
    return 'That sign-in link has expired or was already used. Each link works once. Enter your email to get a new one.';
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
    // RLS returns only the applications the admin ASSIGNED to this judge
    // (judge_assignments), so no assignment filter is needed here.
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
    var lede = counts.all + ' application' + (counts.all === 1 ? '' : 's') + ' assigned to you. ' +
               counts.todo + ' not started, ' +
               counts.draft + ' in progress, ' +
               counts.submitted + ' submitted.';
    document.getElementById('queue-lede').textContent = lede;

    // PDF packet button: only when there is something assigned.
    document.getElementById('queue-tools').hidden = counts.all === 0;

    // Render list
    var list = document.getElementById('queue-list');
    if (filtered.length === 0) {
      list.innerHTML = '';
      // Nothing assigned at all vs. nothing under this filter.
      document.getElementById('queue-empty-h').textContent =
        counts.all === 0 ? 'No applications assigned to you yet.' : 'Nothing under this filter.';
      document.getElementById('queue-empty-p').textContent =
        counts.all === 0
          ? 'The program team assigns finalists to each judge. Yours will appear here as soon as they are assigned.'
          : 'Choose another filter above to see the rest of your assigned applications.';
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
              '<span>', String(prog.done), ' of ', String(prog.total), ' dimensions',
                (r.score && r.score.total != null ? ' · total ' + escHtml(String(Number(r.score.total))) + ' / 100' : ''), '</span>',
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

    // Arrived from the "Upload scores to the portal" button inside a PDF:
    // point at the upload button (a browser will not open the file chooser
    // without a click).
    if (window.location.hash === '#upload' && state.applications.length) {
      history.replaceState(null, '', window.location.pathname);
      var up = document.getElementById('btn-pdf-upload');
      up.classList.add('is-highlight');
      up.focus();
      var hint = document.getElementById('pdf-all-note');
      hint.textContent = 'Choose "Upload filled-in PDF" and pick the score sheet you saved.';
    }
  }

  async function bootstrap() {
    try {
      await loadConfig();

      // 0) Came back from a dead emailed link? If a session from an earlier
      // click is still valid just carry on; otherwise explain and offer a new link.
      var linkError = parseHashError();
      if (linkError && !loadSession()) {
        var le = document.getElementById('signin-err');
        le.textContent = linkError;
        le.hidden = false;
        show('signin');
        return;
      }

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
      err.textContent = e2 && e2.rateLimited
        ? 'A link was sent a moment ago. Check your inbox (and spam), or wait a minute and try again.'
        : 'Could not send the link. Please try again or write apply@america250cfc.org.';
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

  // ---- Download every assigned application + score sheet as one PDF ----
  // Fetches the full application text (the queue only loads a summary) and
  // this judge's scores with comments, so anything already entered in the
  // portal is pre-filled. RLS limits both to this judge's assignments.
  var PDF_NOTE = document.getElementById('pdf-all-note').textContent;
  document.getElementById('btn-pdf-all').addEventListener('click', async function () {
    var btn = this, note = document.getElementById('pdf-all-note');
    if (!window.CFCJudgePdf) return;
    var label = btn.textContent;
    btn.disabled = true; btn.textContent = 'Preparing PDF…';
    note.textContent = PDF_NOTE; note.className = 'queue-tools__note';
    try {
      var results = await Promise.all([
        sbFetch('/rest/v1/applications?status=in.(in_judging,approved,finalist,winner)' +
          '&select=' + window.CFCJudgePdf.FIELDS + '&order=created_at.asc,id.asc'),
        sbFetch('/rest/v1/scores?judge_id=eq.' + encodeURIComponent(state.session.user_id) +
          '&select=application_id,dim_community,dim_innovation,dim_feasibility,dim_sustainability,dim_founder_team,total,comments,status'),
      ]);
      if (!results[0].ok || !results[1].ok) throw new Error('Could not load applications.');
      var apps = await results[0].json();
      var byApp = {};
      (await results[1].json()).forEach(function (s) { byApp[s.application_id] = s; });
      if (!apps.length) throw new Error('No applications assigned.');
      await window.CFCJudgePdf.downloadPacket(apps, byApp, state.judge && state.judge.name);
    } catch (err) {
      console.error('PDF error:', err);
      note.textContent = 'Could not create the PDF. Please try again.';
      note.className = 'queue-tools__note is-err';
    } finally {
      btn.disabled = false; btn.textContent = label;
    }
  });

  // ---- Upload a filled-in score-sheet PDF ----
  // The PDF is read here in the browser (never sent anywhere as a file). The
  // judge sees exactly what will change and confirms before anything is
  // saved; saving uses the judge's own session, so RLS still limits it to
  // their assigned applications and their own draft scores.
  var DIM_COLS = ['dim_community', 'dim_feasibility', 'dim_innovation', 'dim_sustainability', 'dim_founder_team'];
  var DIM_KEYS = ['community', 'feasibility', 'innovation', 'sustainability', 'founder_team'];
  var DIM_SHORT = ['Community', 'Feasibility', 'Innovation', 'Sustainability', 'Founder & team'];
  var uploadPlan = null;   // rows from the last reviewed PDF
  var $review = document.getElementById('upload-review');
  var $uploadMsg = document.getElementById('upload-msg');
  var $uploadInput = document.getElementById('pdf-upload-input');
  function setUploadMsg(t, cls) { $uploadMsg.textContent = t || ''; $uploadMsg.className = 'upload-review__msg' + (cls ? ' ' + cls : ''); }

  async function fetchScoresFull() {
    var res = await sbFetch('/rest/v1/scores?judge_id=eq.' + encodeURIComponent(state.session.user_id) +
      '&select=id,application_id,dim_community,dim_innovation,dim_feasibility,dim_sustainability,dim_founder_team,total,comments,status');
    if (!res.ok) throw new Error('Could not load your current scores.');
    return await res.json();
  }

  // Work out, per application in the PDF, what would be saved. Blank boxes in
  // the PDF never erase a score or note already in the portal.
  function planUpload(sheets, existing) {
    var apps = {}, byApp = {};
    state.applications.forEach(function (a) { apps[a.id] = a; });
    existing.forEach(function (s) { byApp[s.application_id] = s; });
    return sheets.map(function (sh) {
      var app = apps[sh.appId], cur = byApp[sh.appId] || null;
      var row = { sheet: sh, app: app, cur: cur, skip: null, changes: {}, merged: {}, comments: null, nNotes: Object.keys(sh.comments).length };
      DIM_COLS.forEach(function (c) {
        var v = sh.dims[c];
        row.merged[c] = v != null ? v : (cur ? cur[c] : null);
        if (v != null && (!cur || cur[c] !== v)) row.changes[c] = v;
      });
      var mergedComments = Object.assign({}, (cur && cur.comments) || {});
      var notesChanged = false;
      Object.keys(sh.comments).forEach(function (k) {
        if (mergedComments[k] !== sh.comments[k]) { mergedComments[k] = sh.comments[k]; notesChanged = true; }
      });
      if (notesChanged) row.comments = mergedComments;
      row.complete = DIM_COLS.every(function (c) { return row.merged[c] != null; });
      if (!app) row.skip = 'Not one of your assigned applications';
      else if (cur && cur.status === 'submitted') row.skip = 'Already submitted as final in the portal (locked)';
      else if (cur && cur.status === 'recused') row.skip = 'You recused yourself from this application';
      else if (!Object.keys(sh.dims).length && !row.nNotes) row.skip = 'Nothing filled in on this sheet';
      else if (!Object.keys(row.changes).length && !row.comments) row.same = true;
      return row;
    });
  }

  function renderUploadReview(fileName) {
    var plan = uploadPlan;
    var toSave = plan.filter(function (r) { return !r.skip; });
    document.getElementById('upload-review-h').textContent = 'Review before saving';
    document.getElementById('upload-review-sub').textContent =
      fileName + ': ' + plan.length + ' score sheet' + (plan.length === 1 ? '' : 's') + ' found, ' +
      toSave.length + ' can be saved. Nothing is saved until you choose Save to portal. ' +
      'Boxes left blank in the PDF do not erase anything already in the portal.';
    var head = '<thead><tr><th class="ut-app" scope="col">Application</th>' +
      DIM_SHORT.map(function (n) { return '<th scope="col">' + escHtml(n) + '</th>'; }).join('') +
      '<th scope="col">Total</th><th scope="col" style="text-align:left">What will happen</th></tr></thead>';
    var body = plan.map(function (r) {
      // Skipped rows show what is in the portal now, not the PDF's values.
      var shown = r.skip ? (r.cur || {}) : r.merged;
      var cells = DIM_COLS.map(function (c) {
        var v = shown[c];
        if (v == null) return '<td>—</td>';
        return '<td' + (r.changes[c] != null && !r.skip ? ' class="ut-new"' : '') + '>' + v + '</td>';
      }).join('');
      var total = '—';
      if (DIM_COLS.every(function (c) { return shown[c] != null; })) {
        var w = [25, 20, 20, 20, 15], sum = 0;
        DIM_COLS.forEach(function (c, i) { sum += shown[c] * w[i]; });
        total = String(sum / 10);
      }
      var what;
      if (r.skip) what = 'Skipped: ' + escHtml(r.skip);
      else if (r.same) what = 'No change (matches the portal)';
      else {
        var bits = [];
        var n = Object.keys(r.changes).length;
        if (n) bits.push(n + ' score' + (n === 1 ? '' : 's'));
        if (r.comments) bits.push('notes');
        what = (r.cur ? 'Update ' : 'Save ') + bits.join(' and ') + (r.complete ? '' : ' (still incomplete)');
      }
      var warn = r.sheet.problems.map(function (p) { return '<span class="ut-warn">Ignored — ' + escHtml(p) + '</span>'; }).join('');
      var title = r.app ? r.app.proj_title || 'Untitled application' : 'Unknown application';
      return '<tr' + (r.skip ? ' class="is-skip"' : '') + '><td class="ut-app"><strong>' + escHtml(title) + '</strong>' +
        (r.nNotes ? '<span class="ut-notes">' + r.nNotes + ' note' + (r.nNotes === 1 ? '' : 's') + ' in the PDF</span>' : '') +
        '</td>' + cells + '<td>' + total + '</td><td class="ut-what">' + what + warn + '</td></tr>';
    }).join('');
    document.getElementById('upload-table').innerHTML = head + '<tbody>' + body + '</tbody>';
    var actionable = toSave.filter(function (r) { return !r.same || r.complete; }).length;
    document.getElementById('upload-save').disabled = actionable === 0;
    document.getElementById('upload-submit-wrap').hidden = !toSave.some(function (r) { return r.complete; });
    document.getElementById('upload-submit-final').checked = false;
    setUploadMsg(actionable === 0 ? 'Nothing to save from this PDF.' : '');
    $review.hidden = false;
    $review.scrollIntoView({ block: 'nearest' });
  }

  document.getElementById('btn-pdf-upload').addEventListener('click', function () {
    this.classList.remove('is-highlight');
    $uploadInput.value = '';
    $uploadInput.click();
  });
  $uploadInput.addEventListener('change', async function () {
    var file = $uploadInput.files && $uploadInput.files[0];
    if (!file) return;
    var note = document.getElementById('pdf-all-note');
    note.textContent = 'Reading ' + file.name + '…'; note.className = 'queue-tools__note';
    $review.hidden = true; uploadPlan = null;
    try {
      if (file.size > 40 * 1024 * 1024) throw new Error('That file is too large to be a score sheet.');
      var bytes = new Uint8Array(await file.arrayBuffer());
      var results = await Promise.all([window.CFCJudgePdf.readScores(bytes), fetchScoresFull()]);
      uploadPlan = planUpload(results[0], results[1]);
      note.textContent = PDF_NOTE;
      renderUploadReview(file.name);
    } catch (err) {
      console.error('Upload read error:', err);
      note.textContent = err.message || 'Could not read that PDF.';
      note.className = 'queue-tools__note is-err';
    }
  });
  document.getElementById('upload-cancel').addEventListener('click', function () {
    uploadPlan = null; $review.hidden = true;
  });
  document.getElementById('upload-save').addEventListener('click', async function () {
    if (!uploadPlan) return;
    var btn = this;
    var submitFinal = document.getElementById('upload-submit-final').checked;
    var rows = uploadPlan.filter(function (r) { return !r.skip && (!r.same || (submitFinal && r.complete)); });
    if (!rows.length) { setUploadMsg('Nothing to save. Tick "submit as final" or upload a different PDF.', 'is-err'); return; }
    var nFinal = submitFinal ? rows.filter(function (r) { return r.complete; }).length : 0;
    if (nFinal && !window.confirm('Submit ' + nFinal + ' application' + (nFinal === 1 ? '' : 's') +
      ' as final?\n\nFinal scores are locked and visible to the admin. You will not be able to edit them without admin override.')) return;
    btn.disabled = true;
    setUploadMsg('Saving…');
    var saved = 0, finals = 0, failed = [];
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var body = Object.assign({}, r.changes);
      if (r.comments) body.comments = r.comments;
      var makeFinal = submitFinal && r.complete;
      if (makeFinal) { body.status = 'submitted'; body.submitted_at = new Date().toISOString(); }
      try {
        var res;
        if (r.cur && r.cur.id) {
          res = await sbFetch('/rest/v1/scores?id=eq.' + encodeURIComponent(r.cur.id), {
            method: 'PATCH', headers: { Prefer: 'return=representation' }, body: JSON.stringify(body),
          });
        } else {
          res = await sbFetch('/rest/v1/scores', {
            method: 'POST', headers: { Prefer: 'return=representation' },
            body: JSON.stringify(Object.assign({ judge_id: state.session.user_id, application_id: r.sheet.appId }, body)),
          });
        }
        var out = res.ok ? await res.json() : [];
        if (!res.ok || !out.length) throw new Error('HTTP ' + res.status);
        saved++; if (makeFinal) finals++;
      } catch (err) {
        console.error('Upload save error:', err);
        failed.push(r.app ? r.app.proj_title || 'Untitled application' : r.sheet.appId);
      }
    }
    try { state.scores = await fetchOwnScores(); renderQueue(); } catch (_) {}
    btn.disabled = false;
    if (failed.length) {
      setUploadMsg('Saved ' + saved + ', but ' + failed.length + ' could not be saved: ' + failed.join('; ') + '. Try again, or enter those in the portal.', 'is-err');
      return;
    }
    uploadPlan = null;
    document.getElementById('upload-table').innerHTML = '';
    document.getElementById('upload-save').disabled = true;
    document.getElementById('upload-submit-wrap').hidden = true;
    document.getElementById('upload-review-h').textContent = 'Saved';
    document.getElementById('upload-review-sub').textContent = '';
    setUploadMsg('Saved ' + saved + ' application' + (saved === 1 ? '' : 's') + ' to the portal' +
      (finals ? ', ' + finals + ' submitted as final.' : ' as drafts. Open each one to review and submit it as final.'), 'is-ok');
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
