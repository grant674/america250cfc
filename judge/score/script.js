/* ============================================================
   America250 CFC — Judge scoring page
   Two-pane scoring UI. Auto-saves to scores table on each
   change (debounced). Submit + lock at the end. Recuse path.
   ============================================================ */

(function () {
  'use strict';

  // ---- Config (loaded from /netlify/functions/judge-config) ----
  var SUPABASE_URL = '';
  var SUPABASE_ANON_KEY = '';

  // ---- LocalStorage keys ----
  var LS_SESSION = 'nn_judge_session';

  // ---- The 5 dimensions, in display order ----
  // Each criterion is scored 0..10. The weighted total is
  //   (community*25 + feasibility*20 + innovation*20 + sustainability*20 + founder_team*15) / 10
  // Range: 0.0–100.0 in 0.5 increments. Server's `scores.total` generated column
  // computes the same value; client mirrors it for live UI feedback.
  var DIMS = [
    { key: 'community',      col: 'dim_community',      name: 'Community impact', weight: 25, hint: 'Does this innovation meaningfully improve conditions for real people in a real community?' },
    { key: 'feasibility',    col: 'dim_feasibility',    name: 'Feasibility',      weight: 20, hint: 'Is there a credible, executable plan? Does the team have the capacity to deliver?' },
    { key: 'innovation',     col: 'dim_innovation',     name: 'Innovation',       weight: 20, hint: 'Is this a genuinely new approach, or a meaningful improvement on an existing one?' },
    { key: 'sustainability', col: 'dim_sustainability', name: 'Sustainability',   weight: 20, hint: 'Can this grow beyond its initial community? Is there a replication model?' },
    { key: 'founder_team',   col: 'dim_founder_team',   name: 'Founder & team',   weight: 15, hint: 'Does the person or team behind this have the drive, background, and community connection to execute?' },
  ];
  var MAX_PER_DIM = 10;

  // ---- DOM ----
  var $loading = document.getElementById('judge-loading');
  var $error   = document.getElementById('judge-error');
  var $noauth  = document.getElementById('judge-noauth');
  var $view    = document.getElementById('score-view');
  var $who     = document.getElementById('judge-who');
  var $signoutBtn = document.getElementById('btn-signout');
  var screens = { loading: $loading, error: $error, noauth: $noauth, view: $view };
  function show(name) {
    Object.keys(screens).forEach(function (k) { screens[k].hidden = (k !== name); });
  }

  function escHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function fmtMoney(v) {
    if (v == null || v === '') return '—';
    var n = parseInt(v, 10);
    if (isNaN(n)) return v;
    return '$' + n.toLocaleString('en-US');
  }
  function fmtDateLong(v) {
    if (!v) return '—';
    var d = new Date(v);
    if (isNaN(d)) return v;
    return d.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  }

  // ---- State ----
  var state = {
    session: null,
    appId: null,
    app: null,
    score: null,        // current scores row (null if none yet)
    saveTimer: null,
    saveInFlight: false,
    pendingChanges: false,
  };

  // ---- Session ----
  function loadSession() {
    try {
      var raw = localStorage.getItem(LS_SESSION);
      if (!raw) return null;
      var s = JSON.parse(raw);
      if (!s || !s.access_token) return null;
      if (s.expires_at && Date.now() / 1000 > s.expires_at + 30) return null;
      return s;
    } catch (_) { return null; }
  }
  function saveSessionToLs(s) {
    if (s) localStorage.setItem(LS_SESSION, JSON.stringify(s));
    else localStorage.removeItem(LS_SESSION);
  }

  function sbFetch(path, opts) {
    opts = opts || {};
    var headers = Object.assign({
      apikey: SUPABASE_ANON_KEY,
      'Content-Type': 'application/json',
    }, opts.headers || {});
    if (state.session && state.session.access_token) {
      headers.Authorization = 'Bearer ' + state.session.access_token;
    }
    return fetch(SUPABASE_URL + path, Object.assign({}, opts, { headers: headers }));
  }

  // ---- Data ----
  async function fetchApp() {
    // Blind review (#6): identity columns (lead_name/email/phone, org_name/url)
    // are intentionally NOT requested — and are also REVOKED from the judge
    // (authenticated) role at the DB, so they can't be fetched directly either.
    var fields = [
      'id','created_at','status',
      'lead_role','org_type','team_desc',
      'proj_title','proj_summary','proj_category','proj_phase',
      'proj_city','proj_state','proj_communities',
      'proj_budget_total','proj_budget_raised','proj_use_of_funds','proj_video_url',
      'impact_community','impact_innovation','impact_feasibility','impact_sustainability','impact_founder_team',
      'elig_age','elig_audience','elig_phase','elig_scope','elig_coi',
    ].join(',');
    var res = await sbFetch(
      '/rest/v1/applications?id=eq.' + encodeURIComponent(state.appId) + '&select=' + fields
    );
    if (!res.ok) throw new Error('Could not load application.');
    var rows = await res.json();
    return rows[0] || null;
  }

  async function fetchScore() {
    var res = await sbFetch(
      '/rest/v1/scores?application_id=eq.' + encodeURIComponent(state.appId) +
      '&judge_id=eq.' + encodeURIComponent(state.session.user_id) +
      '&select=*'
    );
    if (!res.ok) throw new Error('Could not load score row.');
    var rows = await res.json();
    return rows[0] || null;
  }

  // Insert if no row yet; PATCH otherwise. Returns the resulting row.
  async function persistScore(changes) {
    if (state.score && state.score.id) {
      // PATCH (RLS gates: only own draft rows updatable).
      var res = await sbFetch(
        '/rest/v1/scores?id=eq.' + encodeURIComponent(state.score.id),
        {
          method: 'PATCH',
          headers: { Prefer: 'return=representation' },
          body: JSON.stringify(changes),
        }
      );
      if (!res.ok) throw new Error('Save failed (HTTP ' + res.status + ').');
      var arr = await res.json();
      return arr[0] || null;
    } else {
      // INSERT — must include judge_id + application_id for RLS WITH CHECK.
      var body = Object.assign({
        judge_id: state.session.user_id,
        application_id: state.appId,
      }, changes);
      var ires = await sbFetch('/rest/v1/scores', {
        method: 'POST',
        headers: { Prefer: 'return=representation' },
        body: JSON.stringify(body),
      });
      if (!ires.ok) {
        var t = await ires.text();
        throw new Error('Create failed: ' + t);
      }
      var arr2 = await ires.json();
      return arr2[0] || null;
    }
  }

  // ---- Render: application read view ----
  function renderRead() {
    var a = state.app;
    var rows = function (pairs) {
      return pairs.map(function (p) {
        var val = p[1];
        var empty = (val == null || val === '');
        var disp = empty ? '—' : escHtml(String(val));
        return '<div class="score-read__row"><dt>' + escHtml(p[0]) + '</dt>' +
               '<dd' + (empty ? ' class="empty"' : '') + '>' + disp + '</dd></div>';
      }).join('');
    };

    var dimHtml = DIMS.map(function (d) {
      var text = a['impact_' + d.key];
      var hasText = text && String(text).trim();
      return [
        '<div class="score-read__dim">',
          '<div class="score-read__dim-h">',
            '<span class="score-read__dim-name">', escHtml(d.name), '</span>',
            '<span class="score-read__dim-pts">', d.weight, '% · 0–', MAX_PER_DIM, '</span>',
          '</div>',
          '<div class="score-read__dim-body', hasText ? '' : ' empty', '">',
            hasText ? escHtml(text) : '(no response)',
          '</div>',
        '</div>',
      ].join('');
    }).join('');

    var loc = (a.proj_city || '') + (a.proj_state ? ', ' + a.proj_state : '');
    // Only render http(s) video URLs as live links. proj_video_url is
    // applicant-controlled (and attacker-controllable via the anon insert), so
    // a "javascript:"/"data:" scheme must never become a clickable href —
    // render those as plain escaped text. (CSP also blocks execution; this is
    // defense in depth so a future CSP relaxation can't turn it into XSS.)
    var videoCell = (a.proj_video_url && /^https?:\/\//i.test(a.proj_video_url))
      ? '<a href="' + escHtml(a.proj_video_url) + '" target="_blank" rel="noopener">' + escHtml(a.proj_video_url) + '</a>'
      : (a.proj_video_url ? escHtml(a.proj_video_url) : '—');

    var html = [
      '<section class="score-read__sec">',
        '<h3 class="score-read__sec-h">Project</h3>',
        '<dl>',
          rows([
            ['Title', a.proj_title],
            ['Summary', a.proj_summary],
            ['Category', (a.proj_category || '').replace(/-/g,' ')],
            ['Phase', a.proj_phase],
            ['Location', loc || '—'],
            ['Communities served', a.proj_communities],
            ['Total budget', fmtMoney(a.proj_budget_total)],
            ['Already raised', fmtMoney(a.proj_budget_raised)],
            ['Use of $50K', a.proj_use_of_funds],
          ]),
          '<div class="score-read__row"><dt>Video</dt><dd' + (a.proj_video_url ? '' : ' class="empty"') + '>' + videoCell + '</dd></div>',
        '</dl>',
      '</section>',

      '<section class="score-read__sec">',
        '<h3 class="score-read__sec-h">Impact &amp; approach</h3>',
        dimHtml,
      '</section>',

      '<section class="score-read__sec">',
        '<h3 class="score-read__sec-h">Team &amp; organization</h3>',
        '<p class="score-read__blind-note">Applicant and organization names are removed for impartial review. Please score on the project\'s merits — if a narrative happens to mention specific people or organizations, disregard their identity.</p>',
        '<dl>',
          rows([
            ['Lead role', a.lead_role],
            ['Tax status', a.org_type],
            ['Team', a.team_desc],
          ]),
        '</dl>',
      '</section>',

      '<section class="score-read__sec">',
        '<h3 class="score-read__sec-h">Eligibility self-attest</h3>',
        '<dl>',
          rows([
            ['Lead applicant 21+', a.elig_age],
            ['Serves U.S. adults 21+', a.elig_audience],
            ['Early/pilot/scaling phase', a.elig_phase],
            ['Not lobbying / partisan / cash aid', a.elig_scope],
            ['No COI with partners', a.elig_coi],
          ]),
        '</dl>',
      '</section>',

      '<section class="score-read__sec">',
        '<h3 class="score-read__sec-h">Submitted</h3>',
        '<dl>',
          rows([
            ['Submitted at', fmtDateLong(a.created_at)],
            ['Application ID', a.id],
          ]),
        '</dl>',
      '</section>',
    ].join('');
    document.getElementById('score-read').innerHTML = html;
  }

  // ---- Render: header ----
  function renderHead() {
    var a = state.app;
    document.getElementById('app-id-short').textContent = a.id.slice(0, 8) + '…' + a.id.slice(-4);
    document.getElementById('app-title').textContent = a.proj_title || '—';
    var loc = (a.proj_city || '') + (a.proj_state ? ', ' + a.proj_state : '');
    // Blind review: identify by category + location, not applicant/org name.
    document.getElementById('app-sub').textContent =
      (a.proj_category || '—') + ' · ' + (a.proj_phase || '—') + ' · ' + (loc || '—') +
      ' · submitted ' + fmtDateLong(a.created_at);

    var pill = document.getElementById('score-status-pill');
    pill.className = 'score-head__status';
    if (!state.score) {
      pill.textContent = 'Not started';
    } else if (state.score.status === 'submitted') {
      pill.textContent = 'Submitted'; pill.classList.add('is-submitted');
    } else if (state.score.status === 'recused') {
      pill.textContent = 'Recused'; pill.classList.add('is-recused');
    } else {
      pill.textContent = 'In progress'; pill.classList.add('is-draft');
    }
  }

  // ---- Render: scoring panel ----
  function renderPanel() {
    var locked = state.score && (state.score.status === 'submitted' || state.score.status === 'recused');
    var panel = document.getElementById('score-panel');
    panel.classList.toggle('is-locked', !!locked);

    var body = document.getElementById('dims-body');
    var rows = DIMS.map(function (d) {
      var value = state.score && state.score[d.col] != null ? state.score[d.col] : '';
      var comment = state.score && state.score.comments && state.score.comments[d.key] ? state.score.comments[d.key] : '';
      var hasComment = !!comment;
      return [
        '<div class="dim-row" data-dim="', d.key, '">',
          '<div class="dim-row__top">',
            '<span class="dim-row__name">', escHtml(d.name), '</span>',
            '<span class="dim-row__range">', d.weight, '% &middot; 0–', MAX_PER_DIM, '</span>',
          '</div>',
          '<div class="dim-row__inputs">',
            '<input class="dim-row__slider" type="range" min="0" max="', MAX_PER_DIM, '" step="1" ',
              'value="', value === '' ? 0 : value, '" data-dim-input="', d.key, '" ',
              'aria-label="', escHtml(d.name), ' score (0 to ', MAX_PER_DIM, ')" ',
              locked ? 'disabled' : '',
              ' />',
            '<input class="dim-row__num" type="number" min="0" max="', MAX_PER_DIM, '" step="1" ',
              'value="', value, '" data-dim-num="', d.key, '" ',
              'aria-label="', escHtml(d.name), ' score (number)" ',
              locked ? 'disabled' : '',
              ' />',
          '</div>',
          '<button type="button" class="dim-row__comment-toggle" data-dim-toggle="', d.key, '">',
            hasComment || value !== '' ? '— Comment' : '+ Comment',
          '</button>',
          '<textarea class="dim-row__comment" data-dim-comment="', d.key, '" rows="2" ',
            'placeholder="Optional — what stood out, what was thin." ',
            hasComment ? '' : 'hidden ',
            locked ? 'disabled' : '',
          '>', escHtml(comment), '</textarea>',
        '</div>',
      ].join('');
    }).join('');
    body.innerHTML = rows;

    // Wire events
    DIMS.forEach(function (d) {
      var slider = body.querySelector('[data-dim-input="' + d.key + '"]');
      var num = body.querySelector('[data-dim-num="' + d.key + '"]');
      var commentToggle = body.querySelector('[data-dim-toggle="' + d.key + '"]');
      var comment = body.querySelector('[data-dim-comment="' + d.key + '"]');

      function syncFrom(src) {
        var v = parseInt(src.value, 10);
        if (isNaN(v)) v = 0;
        v = Math.max(0, Math.min(MAX_PER_DIM, v));
        slider.value = v;
        num.value = String(v);
        scheduleSave();
      }
      slider.addEventListener('input', function () { syncFrom(slider); });
      num.addEventListener('input', function () { syncFrom(num); });
      num.addEventListener('blur', function () {
        if (num.value === '') { num.value = '0'; syncFrom(num); }
      });
      commentToggle.addEventListener('click', function () {
        var visible = !comment.hasAttribute('hidden');
        if (visible) {
          comment.setAttribute('hidden', '');
          commentToggle.textContent = '+ Comment';
        } else {
          comment.removeAttribute('hidden');
          commentToggle.textContent = '— Comment';
          comment.focus();
        }
      });
      comment.addEventListener('input', scheduleSave);
    });

    updateTotal();
    renderLockedOverlay();
  }

  function readPanelValues() {
    var dims = {};
    var comments = {};
    DIMS.forEach(function (d) {
      var num = document.querySelector('[data-dim-num="' + d.key + '"]');
      var comment = document.querySelector('[data-dim-comment="' + d.key + '"]');
      if (num) {
        var v = num.value === '' ? null : Math.max(0, Math.min(MAX_PER_DIM, parseInt(num.value, 10) || 0));
        dims[d.col] = v;
      }
      if (comment) {
        var c = comment.value.trim();
        if (c) comments[d.key] = c.slice(0, 1000);
      }
    });
    return { dims: dims, comments: comments };
  }

  // Weighted total — matches the server's generated column exactly.
  //   total = (c*25 + f*20 + i*20 + s*20 + ft*15) / 10
  // Result is 0.0–100.0 in 0.5 increments; we keep one decimal if non-integer.
  function fmtTotal(n) {
    if (n == null) return '—';
    return (n === Math.floor(n)) ? String(n) : n.toFixed(1);
  }
  function updateTotal() {
    var vals = readPanelValues();
    var allFilled = DIMS.every(function (d) { return vals.dims[d.col] != null; });
    if (!allFilled) {
      document.getElementById('total-num').textContent = '—';
      return;
    }
    var weighted = 0;
    DIMS.forEach(function (d) { weighted += (vals.dims[d.col] || 0) * d.weight; });
    document.getElementById('total-num').textContent = fmtTotal(weighted / 10);
  }

  function setSaveStatus(state, msg) {
    var el = document.getElementById('save-status');
    el.className = 'score-panel__save';
    if (state === 'saving') { el.classList.add('is-saving'); el.textContent = 'Saving…'; }
    else if (state === 'saved') { el.classList.add('is-saved'); el.textContent = 'Saved'; }
    else if (state === 'error') { el.classList.add('is-error'); el.textContent = msg || 'Save failed.'; }
    else el.textContent = 'Auto-saves as you go';
  }

  function scheduleSave() {
    updateTotal();
    state.pendingChanges = true;
    clearTimeout(state.saveTimer);
    setSaveStatus('saving');
    state.saveTimer = setTimeout(doSave, 700);
  }

  async function doSave() {
    if (state.saveInFlight) {
      state.pendingChanges = true;
      return;
    }
    if (!state.pendingChanges) return;
    state.pendingChanges = false;
    state.saveInFlight = true;
    setSaveStatus('saving');
    try {
      var vals = readPanelValues();
      var body = Object.assign({}, vals.dims, { comments: vals.comments });
      var row = await persistScore(body);
      state.score = row;
      setSaveStatus('saved');
      // If more changes happened during save, kick another one
      if (state.pendingChanges) doSave();
    } catch (err) {
      console.error('Save error:', err);
      setSaveStatus('error', 'Save failed — retrying…');
      setTimeout(function () { scheduleSave(); }, 2000);
    } finally {
      state.saveInFlight = false;
    }
  }

  function renderLockedOverlay() {
    var locked = state.score && (state.score.status === 'submitted' || state.score.status === 'recused');
    var el = document.getElementById('score-locked');
    if (!locked) { el.hidden = true; return; }
    el.hidden = false;
    if (state.score.status === 'submitted') {
      document.getElementById('locked-h').textContent = 'Submitted';
      document.getElementById('locked-p').textContent =
        'Your scores are submitted and locked' +
        (state.score.submitted_at ? ' (' + fmtDateLong(state.score.submitted_at) + ')' : '') +
        '. Contact the admin if you need to change them.';
    } else if (state.score.status === 'recused') {
      document.getElementById('locked-h').textContent = 'Recused';
      document.getElementById('locked-p').textContent = 'You have recused yourself from scoring this application. No total recorded.';
    }
  }

  // ---- Confirm modal helper ----
  var confirmModal = document.getElementById('confirm-modal');
  var confirmGo = document.getElementById('confirm-go');
  var confirmResolveFn = null;
  function showConfirm(opts) {
    document.getElementById('confirm-title').textContent = opts.title;
    document.getElementById('confirm-body').textContent = opts.body;
    confirmGo.textContent = opts.confirmLabel || 'Confirm';
    confirmGo.className = 'btn btn--blue';
    if (opts.danger) confirmGo.className = 'btn btn--red';
    confirmModal.setAttribute('aria-hidden', 'false');
    return new Promise(function (resolve) {
      confirmResolveFn = resolve;
    });
  }
  document.querySelectorAll('[data-confirm-close]').forEach(function (el) {
    el.addEventListener('click', function () {
      confirmModal.setAttribute('aria-hidden', 'true');
      if (confirmResolveFn) { confirmResolveFn(false); confirmResolveFn = null; }
    });
  });
  confirmGo.addEventListener('click', function () {
    confirmModal.setAttribute('aria-hidden', 'true');
    if (confirmResolveFn) { confirmResolveFn(true); confirmResolveFn = null; }
  });

  // ---- Submit + Recuse ----
  document.getElementById('btn-submit').addEventListener('click', async function () {
    // First, flush any pending save.
    if (state.pendingChanges || state.saveInFlight) {
      await new Promise(function (r) { setTimeout(r, 800); });
    }
    var vals = readPanelValues();
    var allFilled = DIMS.every(function (d) { return vals.dims[d.col] != null; });
    if (!allFilled) {
      alert('All five dimensions need a score before you can submit.');
      return;
    }
    var ok = await showConfirm({
      title: 'Submit final score?',
      body: 'Once submitted, your score is locked and visible to the admin. You won\'t be able to edit it without admin override.',
      confirmLabel: 'Yes — submit',
    });
    if (!ok) return;
    setSaveStatus('saving');
    try {
      var row = await persistScore({
        status: 'submitted',
        submitted_at: new Date().toISOString(),
      });
      state.score = row;
      renderHead();
      renderPanel();
      setSaveStatus('saved');
    } catch (err) {
      setSaveStatus('error', 'Submit failed.');
      alert('Submit failed: ' + err.message);
    }
  });

  document.getElementById('btn-recuse').addEventListener('click', async function () {
    var ok = await showConfirm({
      title: 'Recuse yourself?',
      body: 'You\'ll be removed from scoring this application. No points will be recorded. You can\'t undo this without admin override.',
      confirmLabel: 'Yes — recuse',
      danger: true,
    });
    if (!ok) return;
    setSaveStatus('saving');
    try {
      // If no row yet, persistScore will INSERT with status='recused'.
      var row = await persistScore({
        // Clear any partial points so totals don't include them.
        dim_community: null, dim_innovation: null, dim_feasibility: null,
        dim_sustainability: null, dim_founder_team: null,
        status: 'recused',
        submitted_at: new Date().toISOString(),
      });
      state.score = row;
      renderHead();
      renderPanel();
      setSaveStatus('saved');
    } catch (err) {
      setSaveStatus('error', 'Recuse failed.');
      alert('Recuse failed: ' + err.message);
    }
  });

  // ---- Sign out (bar) ----
  document.getElementById('btn-signout').addEventListener('click', function () {
    saveSessionToLs(null);
    window.location.href = '/judge/';
  });

  // ---- Bootstrap ----
  async function loadConfig() {
    var res = await fetch('/.netlify/functions/judge-config', { credentials: 'omit' });
    if (!res.ok) throw new Error('Config endpoint failed.');
    var data = await res.json();
    SUPABASE_URL = data.supabase_url;
    SUPABASE_ANON_KEY = data.supabase_anon_key;
  }

  function readAppIdFromUrl() {
    var p = new URLSearchParams(window.location.search);
    var id = p.get('id') || '';
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return null;
    return id;
  }

  async function bootstrap() {
    state.appId = readAppIdFromUrl();
    if (!state.appId) {
      document.getElementById('error-msg').textContent = 'Missing or invalid application ID.';
      show('error');
      return;
    }
    state.session = loadSession();
    if (!state.session || !state.session.user_id) {
      show('noauth');
      return;
    }

    try {
      await loadConfig();

      var results = await Promise.all([fetchApp(), fetchScore()]);
      state.app = results[0];
      state.score = results[1];

      if (!state.app) {
        document.getElementById('error-msg').textContent =
          'This application is not visible to you. It may not yet be in the scoring phase.';
        show('error');
        return;
      }

      // Show "who" pill in the top bar
      $who.textContent = '';
      $who.hidden = true;
      $signoutBtn.hidden = false;

      renderHead();
      renderRead();
      renderPanel();
      show('view');
    } catch (err) {
      console.error('Bootstrap error:', err);
      document.getElementById('error-msg').textContent = err.message || 'Unknown error.';
      show('error');
    }
  }

  bootstrap();
})();
