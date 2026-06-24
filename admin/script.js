/* ============================================================
   America250 CFC — Admin dashboard
   Fetches /.netlify/functions/admin-list every 10s, renders the
   stats + filterable table + detail drawer + status overrides.
   ============================================================ */

(function () {
  'use strict';

  var POLL_INTERVAL_MS = 10000;
  var LIST_ENDPOINT = '/.netlify/functions/admin-list';
  var UPDATE_ENDPOINT = '/.netlify/functions/admin-update';

  // ---------- DOM ----------
  var statusDot = document.getElementById('status-dot');
  var statusText = document.getElementById('status-text');
  var updatedAt = document.getElementById('updated-at');
  var btnRefresh = document.getElementById('btn-refresh');
  var tbody = document.getElementById('admin-tbody');
  var emptyMsg = document.getElementById('admin-empty');
  var pillsEl = document.getElementById('filter-pills');
  var searchInput = document.getElementById('search-input');
  var statsSummary = document.getElementById('stats-summary');
  var drawer = document.getElementById('drawer');
  var drawerScrim = document.getElementById('drawer-scrim');
  var drawerClose = document.getElementById('drawer-close');
  var drawerId = document.getElementById('drawer-id');
  var drawerTitle = document.getElementById('drawer-title');
  var drawerSub = document.getElementById('drawer-sub');
  var drawerBody = document.getElementById('drawer-body');
  var drawerFoot = document.getElementById('drawer-foot');

  // ---------- State ----------
  var state = {
    rows: [],
    stats: null,
    filter: 'all',
    search: '',
    activeRow: null,
    fetchInFlight: false,
    pollTimer: null,
    judgesProgress: [],
    inbox: [],
    inboxAlias: 'all',
    inboxStatus: 'all',
    inboxActive: null,    // current open inbox message
    audit: [],
  };
  var selectedIds = new Set(); // #10 bulk-selection of application ids

  // ---------- Helpers ----------
  function fmtMoney(v) {
    if (v == null || v === '') return '—';
    var n = parseInt(v, 10);
    if (isNaN(n)) return v;
    return '$' + n.toLocaleString('en-US');
  }
  function fmtDate(v) {
    if (!v) return '—';
    var d = new Date(v);
    if (isNaN(d)) return v;
    var now = new Date();
    var sameDay = d.toDateString() === now.toDateString();
    if (sameDay) {
      return d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
    }
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) +
      ' · ' + d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
  }
  function fmtDateLong(v) {
    if (!v) return '—';
    var d = new Date(v);
    if (isNaN(d)) return v;
    return d.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  }
  function escHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function setStatusPill(state) {
    statusDot.className = 'admin-bar__dot';
    if (state === 'live')    { statusDot.classList.add('is-live');    statusText.textContent = 'Live'; }
    if (state === 'loading') { statusDot.classList.add('is-loading'); statusText.textContent = 'Refreshing…'; }
    if (state === 'error')   { statusDot.classList.add('is-error');   statusText.textContent = 'Connection error'; }
  }

  function statusBadge(s) {
    return '<span class="badge badge--' + escHtml(s || 'submitted') + '">' + escHtml(s || 'submitted') + '</span>';
  }
  function aiBadge(s) {
    if (!s) return '<span class="badge badge--pending">pending</span>';
    return '<span class="badge badge--' + escHtml(s) + '">' + escHtml(s) + '</span>';
  }

  // ---------- Filtering ----------
  function applyFilters() {
    var q = state.search.trim().toLowerCase();
    var f = state.filter;
    return state.rows.filter(function (r) {
      if (f !== 'all' && r.status !== f) return false;
      if (!q) return true;
      var hay = [
        r.id, r.lead_name, r.lead_email, r.org_name, r.proj_title,
        r.proj_summary, r.proj_city, r.proj_state, r.proj_category,
      ].filter(Boolean).join(' ').toLowerCase();
      return hay.indexOf(q) !== -1;
    });
  }

  // ---------- Render: judges progress ----------
  function renderJudgesProgress(judgesProgress) {
    var sec = document.getElementById('admin-judging');
    if (!judgesProgress || judgesProgress.length === 0) {
      sec.hidden = true;
      return;
    }
    sec.hidden = false;
    var totalApps = judgesProgress[0] ? judgesProgress[0].total : 0;
    var fullySubmitted = judgesProgress.filter(function (j) { return j.submitted >= j.total && j.total > 0; }).length;
    document.getElementById('judging-sub').textContent =
      judgesProgress.length + ' active judge' + (judgesProgress.length === 1 ? '' : 's') +
      ' · ' + totalApps + ' application' + (totalApps === 1 ? '' : 's') + ' in scoring' +
      (fullySubmitted ? ' · ' + fullySubmitted + ' judge' + (fullySubmitted === 1 ? '' : 's') + ' complete' : '');

    var html = judgesProgress.map(function (j) {
      var pct = j.total ? Math.round(100 * j.submitted / j.total) : 0;
      var complete = j.total > 0 && j.submitted >= j.total;
      return [
        '<div class="judge-progress', complete ? ' is-complete' : '', '">',
          '<div class="judge-progress__name">', escHtml(j.name), '</div>',
          '<div class="judge-progress__email">', escHtml(j.email || ''), '</div>',
          '<div class="judge-progress__bar"><div class="judge-progress__fill" style="width:', String(pct), '%"></div></div>',
          '<div class="judge-progress__meta">',
            '<span><strong>', String(j.submitted), '</strong> of ', String(j.total), ' submitted</span>',
            '<span>', String(pct), '%</span>',
          '</div>',
          (j.draft || j.recused
            ? '<div class="judge-progress__meta" style="margin-top:4px;">' +
              (j.draft ? '<span>' + j.draft + ' in progress</span>' : '<span></span>') +
              (j.recused ? '<span>' + j.recused + ' recused</span>' : '<span></span>') +
              '</div>'
            : ''),
        '</div>',
      ].join('');
    }).join('');
    document.getElementById('judging-grid').innerHTML = html;
  }

  // ---------- Render ----------
  function render() {
    // Drop any selected ids that are no longer in the dataset (e.g. after a
    // polling refresh) so a stale selection can't target vanished rows.
    if (selectedIds.size) {
      var present = {};
      (state.rows || []).forEach(function (r) { present[r.id] = true; });
      Array.from(selectedIds).forEach(function (id) { if (!present[id]) selectedIds.delete(id); });
    }
    if (state.stats) {
      var stats = state.stats;
      // Top cards
      var setStat = function (k, v) {
        var el = document.querySelector('[data-stat="' + k + '"]');
        if (el) el.textContent = String(v == null ? 0 : v);
      };
      setStat('total', stats.total);
      setStat('screened', stats.by_status.screened || stats.by_status.approved || 0);
      setStat('flagged',  stats.by_status.flagged  || 0);
      setStat('rejected', stats.by_status.rejected || 0);
      setStat('pending',  (stats.by_status.submitted || 0));

      // Pill counts
      var counts = stats.by_status;
      Object.keys(counts).forEach(function (k) {
        var el = document.querySelector('[data-count="' + k + '"]');
        if (el) el.textContent = String(counts[k]);
      });
      var allEl = document.querySelector('[data-count="all"]');
      if (allEl) allEl.textContent = String(stats.total);

      // Summary line
      var passed = stats.by_status.screened || 0;
      var flagged = stats.by_status.flagged || 0;
      var rejected = stats.by_status.rejected || 0;
      var pending = stats.by_status.submitted || 0;
      var summary = stats.total + ' total · ' + passed + ' screened · ' + flagged + ' flagged · ' +
                    rejected + ' rejected' + (pending ? ' · ' + pending + ' awaiting AI' : '');
      statsSummary.textContent = summary;
    }

    // Table
    var rows = applyFilters();
    if (rows.length === 0) {
      tbody.innerHTML = '';
      emptyMsg.hidden = false;
      return;
    }
    emptyMsg.hidden = true;
    var html = rows.map(function (r) {
      var loc = (r.proj_city || '—') + (r.proj_state ? ', ' + r.proj_state : '');
      return [
        '<tr data-id="', escHtml(r.id), '">',
        '<td class="col-check"><input type="checkbox" class="row-cb" data-cb-id="', escHtml(r.id), '" aria-label="Select"', (selectedIds.has(r.id) ? ' checked' : ''), ' /></td>',
        '<td><span class="cell-when">', escHtml(fmtDate(r.created_at)), '</span></td>',
        '<td>',
          '<span class="cell-lead">', escHtml(r.lead_name || '—'),
            (r.dup_email || r.dup_org ? ' <span class="dup-badge" title="Possible duplicate — shares an email or organization with another submission">DUP</span>' : ''),
          '</span>',
          '<span class="cell-lead-org">', escHtml(r.org_name || ''), '</span>',
        '</td>',
        '<td>',
          '<span class="cell-proj">', escHtml(r.proj_title || '—'), '</span>',
          '<span class="cell-proj-cat">', escHtml(r.proj_category || ''), ' · ', escHtml(r.proj_phase || ''), '</span>',
        '</td>',
        '<td><span class="cell-where">', escHtml(loc), '</span></td>',
        '<td><span class="cell-budget">', escHtml(fmtMoney(r.proj_budget_total)), '</span></td>',
        '<td>', aiBadge(r.ai_screening_result), '</td>',
        '<td>', statusBadge(r.status), '</td>',
        '<td>›</td>',
        '</tr>',
      ].join('');
    }).join('');
    tbody.innerHTML = html;

    // Re-attach row click handlers (ignore clicks on the select checkbox cell)
    Array.prototype.forEach.call(tbody.querySelectorAll('tr[data-id]'), function (tr) {
      tr.addEventListener('click', function (e) {
        if (e.target.closest('.col-check')) return;
        openDrawer(tr.getAttribute('data-id'));
      });
    });
    syncSelectAll();
  }

  // ---------- Drawer ----------
  function openDrawer(id) {
    var row = state.rows.find(function (r) { return r.id === id; });
    if (!row) return;
    state.activeRow = row;

    drawerId.textContent = row.id;
    drawerTitle.textContent = row.proj_title || '—';
    drawerSub.textContent = (row.lead_name || '—') + ' · ' + (row.org_name || '—') + ' · ' +
                            (row.proj_city || '') + (row.proj_state ? ', ' + row.proj_state : '') +
                            ' · submitted ' + fmtDateLong(row.created_at);

    // Render the body
    drawerBody.innerHTML = renderDrawerBody(row);

    // Highlight current status in the override row
    drawerFoot.querySelectorAll('.btn-mini').forEach(function (b) {
      b.classList.toggle('is-current', b.getAttribute('data-set-status') === row.status);
    });

    drawer.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  }
  function closeDrawer() {
    drawer.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    state.activeRow = null;
  }
  drawerScrim.addEventListener('click', closeDrawer);
  drawerClose.addEventListener('click', closeDrawer);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && drawer.getAttribute('aria-hidden') === 'false') closeDrawer();
  });

  // Only http(s) and mailto: are rendered as live links; anything else
  // (javascript:, data:, file:, vbscript:, jar:, etc.) is rendered as
  // plain text. Defense-in-depth — CSP also blocks `javascript:` URIs
  // because `script-src` doesn't include `'unsafe-inline'`, but we
  // belt-and-suspenders this here.
  function safeUrl(s) {
    if (typeof s !== 'string') return null;
    try {
      var u = new URL(s, window.location.href);
      var proto = (u.protocol || '').toLowerCase();
      if (proto === 'http:' || proto === 'https:' || proto === 'mailto:') return u.href;
    } catch (_) { /* fall through */ }
    return null;
  }
  function row(label, value, opts) {
    opts = opts || {};
    var dispVal = (value == null || value === '') ? '—' : String(value);
    var emptyClass = (value == null || value === '') ? ' empty' : '';
    if (opts.link && value) {
      var url = safeUrl(value);
      dispVal = url
        ? '<a href="' + escHtml(url) + '" target="_blank" rel="noopener noreferrer">' + escHtml(value) + '</a>'
        : escHtml(value);
    } else {
      dispVal = escHtml(dispVal);
    }
    return '<div class="drawer__row"><dt>' + escHtml(label) + '</dt>' +
           '<dd class="' + emptyClass + '">' + dispVal + '</dd></div>';
  }
  function renderDrawerBody(r) {
    var ai = r.ai_screening_reasons || {};
    var aiCard = '';
    if (r.ai_screening_result) {
      var elig = ai.eligibility_reasons && ai.eligibility_reasons.length
        ? '<div class="group"><dt>Reasons</dt><dd><ul>' +
            ai.eligibility_reasons.map(function (x) { return '<li>' + escHtml(x) + '</li>'; }).join('') +
          '</ul></dd></div>'
        : '';
      var qNotes = ai.quality_notes && ai.quality_notes.length
        ? '<div class="group"><dt>Notes</dt><dd><ul>' +
            ai.quality_notes.map(function (x) { return '<li>' + escHtml(x) + '</li>'; }).join('') +
          '</ul></dd></div>'
        : '';
      aiCard = [
        '<div class="ai-card">',
          '<div class="ai-card__head">',
            '<h4>AI screening verdict</h4>',
            aiBadge(r.ai_screening_result),
          '</div>',
          ai.summary ? '<div class="ai-card__summary">"' + escHtml(ai.summary) + '"</div>' : '',
          '<div class="group"><dt>Eligibility</dt><dd>' + escHtml(ai.eligibility || '—') + '</dd></div>',
          '<div class="group"><dt>Quality</dt><dd>' + escHtml(ai.quality || '—') + '</dd></div>',
          elig,
          qNotes,
          r.ai_screening_at ? '<div class="ai-card__head" style="margin-top:14px;margin-bottom:0;border-top:1px solid var(--line);padding-top:12px;"><span class="ai-time">Screened ' + escHtml(fmtDateLong(r.ai_screening_at)) + '</span></div>' : '',
        '</div>',
      ].join('');
    } else {
      aiCard = '<div class="ai-card">' +
                 '<div class="ai-card__head"><h4>AI screening verdict</h4>' + aiBadge(null) + '</div>' +
                 '<p style="font-size:13.5px;color:var(--fg-65);margin:0;">' +
                   'Awaiting AI screening — usually completes within a few seconds of submission.' +
                 '</p>' +
               '</div>';
    }

    return [
      aiCard,
      renderScoringSummary(r),

      '<section class="drawer__section">',
        '<h3>Lead applicant</h3>',
        '<dl>',
          row('Name', r.lead_name),
          row('Role', r.lead_role),
          row('Email', '<a href="mailto:' + escHtml(r.lead_email || '') + '">' + escHtml(r.lead_email || '—') + '</a>'),
        '</dl>',
      '</section>',

      '<section class="drawer__section">',
        '<h3>Organization</h3>',
        '<dl>',
          row('Name', r.org_name),
          row('Website', r.org_url, { link: true }),
          row('Type', r.org_type),
          row('Registered entity', r.org_has_entity),
          row('Team', r.team_desc),
        '</dl>',
      '</section>',

      '<section class="drawer__section">',
        '<h3>Project</h3>',
        '<dl>',
          row('Title', r.proj_title),
          row('Summary', r.proj_summary),
          row('Category', r.proj_category),
          row('Phase', r.proj_phase),
          row('Location', (r.proj_city || '') + (r.proj_state ? ', ' + r.proj_state : '')),
          row('Communities', r.proj_communities),
          row('Budget total', fmtMoney(r.proj_budget_total)),
          row('Already raised', fmtMoney(r.proj_budget_raised)),
          row('Use of $50K', r.proj_use_of_funds),
          row('Video', r.proj_video_url, { link: true }),
        '</dl>',
      '</section>',

      '<section class="drawer__section">',
        '<h3>Impact &amp; approach</h3>',
        '<dl>',
          row('Community impact (25%)', r.impact_community),
          row('Feasibility (20%)',      r.impact_feasibility),
          row('Innovation (20%)',       r.impact_innovation),
          row('Sustainability (20%)',   r.impact_sustainability),
          row('Founder & team (15%)',   r.impact_founder_team),
        '</dl>',
      '</section>',

      '<section class="drawer__section">',
        '<h3>Eligibility self-attest</h3>',
        '<dl>',
          row('Lead 21+', r.elig_age),
          row('Serves U.S. adults 21+', r.elig_audience),
          row('Phase OK', r.elig_phase),
          row('Not lobbying / partisan / cash aid', r.elig_scope),
          row('No COI with partners', r.elig_coi),
        '</dl>',
      '</section>',

      '<section class="drawer__section">',
        '<h3>Audit</h3>',
        '<dl>',
          row('Application ID', r.id),
          row('Submitted at', fmtDateLong(r.created_at)),
          row('Last updated', fmtDateLong(r.updated_at)),
          row('Submission source', r.submission_source),
          row('User agent', r.user_agent),
          row('Legal terms accepted', r.legal_terms ? 'yes' : 'no'),
          row('Attribution accepted', r.legal_attribution ? 'yes' : 'no'),
        '</dl>',
      '</section>',
    ].join('');
  }

  function renderScoringSummary(r) {
    var sc = r.scoring;
    if (!sc) return '';
    var inScoringPhase = ['approved','in_judging','finalist','winner'].indexOf(r.status) !== -1;
    if (!inScoringPhase && sc.n_submitted === 0) return '';

    var DIM_LABELS = {
      dim_community: 'Community',
      dim_feasibility: 'Feasibility',
      dim_innovation: 'Innovation',
      dim_sustainability: 'Sustainability',
      dim_founder_team: 'Founder/Team',
    };
    var DIM_MAXES = { dim_community: 10, dim_innovation: 10, dim_feasibility: 10, dim_sustainability: 10, dim_founder_team: 10 };
    var DIM_WEIGHTS = { dim_community: 25, dim_feasibility: 20, dim_innovation: 20, dim_sustainability: 20, dim_founder_team: 15 };

    var inner = '';
    if (sc.n_submitted === 0) {
      inner = '<p class="scoring-summary__empty">No scores submitted yet — ' +
              sc.n_in_progress + ' in progress' +
              (sc.n_recused ? ', ' + sc.n_recused + ' recused' : '') + '.</p>';
    } else {
      var perDim = '';
      Object.keys(DIM_LABELS).forEach(function (k) {
        var stats = sc.per_dim && sc.per_dim[k];
        if (stats) {
          perDim += '<span class="lab">' + DIM_LABELS[k] + '</span>' +
                    '<span class="val">' + stats.mean + ' / ' + DIM_MAXES[k] + '</span>';
        }
      });
      var perJudge = (sc.per_judge || []).map(function (pj) {
        return '<div class="scoring-summary__judges-row">' +
                 '<span class="judge-name">judge ' + escHtml(String(pj.judge_id).slice(0, 8)) + '…</span>' +
                 '<span class="judge-total">' + pj.total + ' / 100</span>' +
               '</div>';
      }).join('');

      inner = [
        '<div class="scoring-summary__stats">',
          '<div class="scoring-stat"><div class="scoring-stat__lab">Mean</div><div class="scoring-stat__num">', sc.mean, '</div></div>',
          '<div class="scoring-stat"><div class="scoring-stat__lab">Median</div><div class="scoring-stat__num">', sc.median, '</div></div>',
          '<div class="scoring-stat"><div class="scoring-stat__lab">σ (sd)</div><div class="scoring-stat__num">', sc.stddev, '</div></div>',
        '</div>',
        '<div class="scoring-summary__dims">', perDim, '</div>',
        '<div class="scoring-summary__judges">',
          '<h4 class="scoring-summary__judges-h">Per-judge totals</h4>',
          perJudge,
        '</div>',
      ].join('');
    }

    return [
      '<div class="scoring-summary" id="drawer-scoring-summary">',
        '<div class="scoring-summary__head">',
          '<h3 class="scoring-summary__h">Scoring</h3>',
          '<span class="scoring-summary__meta">',
            sc.n_submitted, ' submitted',
            (sc.n_in_progress ? ' · ' + sc.n_in_progress + ' draft' : ''),
            (sc.n_recused ? ' · ' + sc.n_recused + ' recused' : ''),
          '</span>',
        '</div>',
        inner,
      '</div>',
    ].join('');
  }

  // Judging-progress collapse toggle
  var judgingToggle = document.getElementById('btn-toggle-judging');
  if (judgingToggle) {
    judgingToggle.addEventListener('click', function () {
      var grid = document.getElementById('judging-grid');
      var collapsed = grid.classList.toggle('is-collapsed');
      judgingToggle.textContent = collapsed ? 'Show' : 'Hide';
      judgingToggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    });
  }

  // ---------- Inbox ----------
  function fmtInboxDate(v) {
    if (!v) return '—';
    var d = new Date(v);
    if (isNaN(d)) return v;
    var now = new Date();
    var sameDay = d.toDateString() === now.toDateString();
    var thisYear = d.getFullYear() === now.getFullYear();
    if (sameDay) return d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
    if (thisYear) return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function inboxStatusBadge(s) {
    if (s === 'unread')   return '<span class="badge badge--flagged">Unread</span>';
    if (s === 'read')     return '<span class="badge badge--pending">Read</span>';
    if (s === 'replied')  return '<span class="badge badge--screened">Replied</span>';
    if (s === 'spam')     return '<span class="badge badge--rejected">Spam</span>';
    if (s === 'archived') return '<span class="badge badge--archived">Archived</span>';
    return '<span class="badge badge--pending">' + escHtml(s) + '</span>';
  }

  function applyInboxFilters() {
    var alias = state.inboxAlias;
    var status = state.inboxStatus;
    return state.inbox.filter(function (m) {
      if (alias !== 'all' && m.to_alias !== alias) return false;
      if (status !== 'all' && m.status !== status) return false;
      return true;
    });
  }

  function renderInbox() {
    var sec = document.getElementById('admin-inbox');
    if (!sec) return;
    sec.hidden = false;

    var unread = 0, replied = 0, total = state.inbox.length;
    var byAlias = {};
    state.inbox.forEach(function (m) {
      if (m.status === 'unread')  unread++;
      if (m.status === 'replied') replied++;
      byAlias[m.to_alias] = (byAlias[m.to_alias] || 0) + 1;
    });
    document.getElementById('inbox-sub').textContent =
      total + ' message' + (total === 1 ? '' : 's') +
      (unread ? ' · ' + unread + ' unread' : '') +
      (replied ? ' · ' + replied + ' replied' : '');

    // Per-alias counts
    document.querySelectorAll('[data-inbox-count-alias]').forEach(function (el) {
      var a = el.getAttribute('data-inbox-count-alias');
      el.textContent = a === 'all' ? String(total) : String(byAlias[a] || 0);
    });

    var list = document.getElementById('inbox-list');
    var rows = applyInboxFilters();
    if (rows.length === 0) {
      list.innerHTML = '';
      document.getElementById('inbox-empty').hidden = false;
      return;
    }
    document.getElementById('inbox-empty').hidden = true;
    var html = rows.map(function (m) {
      var fromDisp = m.from_name ? m.from_name : (m.from_address || '—');
      var subj = m.subject || '(no subject)';
      var snip = m.snippet || '';
      var cls = 'inbox-row is-' + escHtml(m.status);
      return [
        '<li><button type="button" class="' + cls + '" data-inbox-id="' + escHtml(m.id) + '">',
          '<span class="inbox-row__alias">', escHtml(m.to_alias), '@</span>',
          '<span class="inbox-row__from">',
            escHtml(fromDisp),
            (m.from_name ? '<span class="from-email">' + escHtml(m.from_address) + '</span>' : ''),
          '</span>',
          '<span class="inbox-row__subject">',
            escHtml(subj),
            '<span class="snippet">', escHtml(snip), '</span>',
          '</span>',
          '<span class="inbox-row__when">', escHtml(fmtInboxDate(m.received_at)), '</span>',
          '<span class="inbox-row__badge">', inboxStatusBadge(m.status), '</span>',
        '</button></li>',
      ].join('');
    }).join('');
    list.innerHTML = html;

    list.querySelectorAll('[data-inbox-id]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        openInboxDrawer(btn.getAttribute('data-inbox-id'));
      });
    });
  }

  // Filter pills
  document.querySelectorAll('[data-inbox-alias]').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('[data-inbox-alias]').forEach(function (x) { x.classList.remove('is-active'); });
      b.classList.add('is-active');
      state.inboxAlias = b.getAttribute('data-inbox-alias');
      renderInbox();
    });
  });
  document.querySelectorAll('[data-inbox-status]').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('[data-inbox-status]').forEach(function (x) { x.classList.remove('is-active'); });
      b.classList.add('is-active');
      state.inboxStatus = b.getAttribute('data-inbox-status');
      renderInbox();
    });
  });

  // Inbox section collapse toggle
  var inboxToggle = document.getElementById('btn-toggle-inbox');
  if (inboxToggle) {
    inboxToggle.addEventListener('click', function () {
      var controls = document.getElementById('inbox-controls');
      var listEl = document.getElementById('inbox-list');
      var emptyEl = document.getElementById('inbox-empty');
      var collapsed = controls.classList.toggle('is-collapsed');
      listEl.classList.toggle('is-collapsed', collapsed);
      emptyEl.hidden = collapsed || emptyEl.hidden;
      inboxToggle.textContent = collapsed ? 'Show' : 'Hide';
      inboxToggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    });
  }

  // ---------- Inbox drawer + reply ----------
  var inboxDrawer = document.getElementById('inbox-drawer');
  var inboxDrawerScrim = document.getElementById('inbox-drawer-scrim');
  var inboxDrawerClose = document.getElementById('inbox-drawer-close');
  var inboxDrawerBody = document.getElementById('inbox-drawer-body');

  async function openInboxDrawer(id) {
    state.inboxActive = state.inbox.find(function (m) { return m.id === id; }) || { id: id };
    document.getElementById('inbox-drawer-alias').textContent = state.inboxActive.to_alias ? state.inboxActive.to_alias + '@america250cfc.org' : '—';
    document.getElementById('inbox-drawer-title').textContent = state.inboxActive.subject || '(no subject)';
    document.getElementById('inbox-drawer-sub').textContent =
      (state.inboxActive.from_name ? state.inboxActive.from_name + ' · ' : '') +
      (state.inboxActive.from_address || '—') + ' · received ' + fmtDateLong(state.inboxActive.received_at);
    inboxDrawerBody.innerHTML = '<p style="color:var(--fg-65); font-family:var(--font); font-size:13px">Loading…</p>';
    inboxDrawer.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';

    // Auto-mark-read on first open
    if (state.inboxActive.status === 'unread') {
      try {
        await fetch('/.netlify/functions/admin-inbox-update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ id: id, action: 'mark_read' }),
        });
        state.inboxActive.status = 'read';
        var idx = state.inbox.findIndex(function (m) { return m.id === id; });
        if (idx > -1) state.inbox[idx].status = 'read';
        renderInbox();
      } catch (_) { /* best effort */ }
    }

    // Fetch full body + replies
    try {
      var res = await fetch('/.netlify/functions/admin-inbox-get?id=' + encodeURIComponent(id), { credentials: 'include' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      var data = await res.json();
      state.inboxActive = Object.assign({}, state.inbox.find(function (m) { return m.id === id; }), data.email);
      renderInboxBody(state.inboxActive, data.replies || []);
    } catch (err) {
      inboxDrawerBody.innerHTML = '<p style="color:var(--c-red); font-family:var(--font); font-size:13px">Couldn\'t load message: ' + escHtml(err.message) + '</p>';
    }
  }

  function renderInboxBody(email, replies) {
    var attachHtml = '';
    if (Array.isArray(email.attachments) && email.attachments.length) {
      attachHtml = '<div class="inbox-msg__attachments">' +
        '<div class="drawer__foot-label" style="color:var(--fg-65)">Attachments</div>' +
        email.attachments.map(function (a) {
          var size = a.size_bytes ? ' · ' + Math.round(a.size_bytes / 1024) + ' KB' : '';
          return '<span class="inbox-msg__attach">📎 ' + escHtml(a.filename || 'untitled') + ' (' + escHtml(a.mime_type || 'unknown') + ')' + size + '</span>';
        }).join('') + '</div>';
    }

    // Prefer text body if present; otherwise sandbox the HTML in a srcdoc iframe.
    var bodyHtml = '';
    if (email.text_body && email.text_body.trim()) {
      bodyHtml = '<div class="inbox-msg__body">' + escHtml(email.text_body) + '</div>';
    } else if (email.html_body) {
      // Sandbox: no scripts, no top navigation, isolated origin.
      var srcdoc = email.html_body
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      bodyHtml = '<iframe sandbox="" referrerpolicy="no-referrer" srcdoc="' + srcdoc + '"></iframe>';
    } else {
      bodyHtml = '<div class="inbox-msg__body" style="color:var(--fg-65);font-style:italic">(empty message)</div>';
    }

    var repliesHtml = '';
    if (replies.length) {
      repliesHtml = '<div class="inbox-replies"><h3 class="inbox-replies__h">Your replies</h3>' +
        replies.map(function (r) {
          return '<div class="inbox-reply">' +
            '<div class="inbox-reply__meta">' +
              escHtml(r.from_alias) + '@america250cfc.org → ' + escHtml(r.to_address) +
              ' · ' + escHtml(fmtDateLong(r.sent_at || r.created_at)) +
              ' · ' + escHtml(r.status) +
            '</div>' +
            '<div class="inbox-reply__body">' + escHtml(r.text_body || '(no text body)') + '</div>' +
          '</div>';
        }).join('') + '</div>';
    }

    inboxDrawerBody.innerHTML = '<article class="inbox-msg">' +
      '<div class="inbox-msg__meta">' +
        'To <strong style="color:var(--c-blue)">' + escHtml(email.to_address) + '</strong> · ' +
        'From <strong style="color:var(--c-black)">' + escHtml(email.from_address) + '</strong>' +
      '</div>' +
      bodyHtml +
      attachHtml +
    '</article>' +
    repliesHtml;
  }

  function closeInboxDrawer() {
    inboxDrawer.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    state.inboxActive = null;
  }
  inboxDrawerScrim.addEventListener('click', closeInboxDrawer);
  inboxDrawerClose.addEventListener('click', closeInboxDrawer);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && inboxDrawer.getAttribute('aria-hidden') === 'false') closeInboxDrawer();
  });

  // Inbox action buttons (mark read/unread/spam/archive)
  document.querySelectorAll('[data-inbox-action]').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      if (!state.inboxActive) return;
      var action = btn.getAttribute('data-inbox-action');
      var id = state.inboxActive.id;
      var prev = btn.textContent;
      btn.disabled = true;
      btn.textContent = '…';
      try {
        var res = await fetch('/.netlify/functions/admin-inbox-update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ id: id, action: action }),
        });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        // Trigger fresh fetch so the row reflects new state
        fetchData();
        if (action === 'archive' || action === 'mark_spam') closeInboxDrawer();
      } catch (err) {
        alert('Action failed: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = prev;
      }
    });
  });

  // Reply composer
  var replyModal = document.getElementById('reply-modal');
  var replyForm = document.getElementById('reply-form');
  var replySubmit = document.getElementById('reply-submit');
  var replyMsg = document.getElementById('reply-msg');

  function openReply() {
    if (!state.inboxActive) return;
    var msg = state.inboxActive;
    document.getElementById('reply-context').textContent =
      'Replying to ' + (msg.from_name || msg.from_address) + ' from ' + msg.to_alias + '@america250cfc.org';
    document.getElementById('reply-to').value = msg.from_address || '';
    var subj = msg.subject || '';
    document.getElementById('reply-subject').value = /^re:/i.test(subj) ? subj : ('Re: ' + subj);
    document.getElementById('reply-text').value = '';
    replyMsg.textContent = '';
    replyMsg.className = 'invite-msg';
    replyModal.setAttribute('aria-hidden', 'false');
    setTimeout(function () { document.getElementById('reply-text').focus(); }, 30);
  }
  function closeReply() {
    replyModal.setAttribute('aria-hidden', 'true');
    replyForm.reset();
  }
  document.getElementById('btn-inbox-reply').addEventListener('click', openReply);
  document.querySelectorAll('[data-reply-close]').forEach(function (el) {
    el.addEventListener('click', closeReply);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && replyModal.getAttribute('aria-hidden') === 'false') closeReply();
  });
  replyForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!state.inboxActive) return;
    var fd = new FormData(replyForm);
    var payload = {
      in_reply_to_id: state.inboxActive.id,
      subject: String(fd.get('subject') || '').trim(),
      text: String(fd.get('text') || '').trim(),
      to_override: String(fd.get('to') || '').trim().toLowerCase(),
    };
    if (!payload.subject || !payload.text || !payload.to_override) {
      replyMsg.textContent = 'All fields required.';
      replyMsg.className = 'invite-msg is-err';
      return;
    }
    replySubmit.disabled = true;
    replyMsg.textContent = 'Sending…';
    replyMsg.className = 'invite-msg';
    try {
      var res = await fetch('/.netlify/functions/send-reply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload),
      });
      var data = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
      replyMsg.textContent = 'Sent.';
      replyMsg.className = 'invite-msg is-ok';
      setTimeout(function () {
        closeReply();
        closeInboxDrawer();
        fetchData();
      }, 800);
    } catch (err) {
      replyMsg.textContent = 'Failed: ' + err.message;
      replyMsg.className = 'invite-msg is-err';
    } finally {
      replySubmit.disabled = false;
    }
  });

  // Status override
  drawerFoot.addEventListener('click', async function (e) {
    var btn = e.target.closest('[data-set-status]');
    if (!btn || !state.activeRow) return;
    var newStatus = btn.getAttribute('data-set-status');
    if (newStatus === state.activeRow.status) return;
    var prevLabel = btn.textContent;
    btn.disabled = true;
    btn.textContent = '…';
    try {
      var res = await fetch(UPDATE_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ id: state.activeRow.id, status: newStatus }),
      });
      if (!res.ok) throw new Error('Update failed: ' + res.status);
      state.activeRow.status = newStatus;
      // Update locally and re-render
      var idx = state.rows.findIndex(function (r) { return r.id === state.activeRow.id; });
      if (idx > -1) state.rows[idx].status = newStatus;
      drawerFoot.querySelectorAll('.btn-mini').forEach(function (b) {
        b.classList.toggle('is-current', b.getAttribute('data-set-status') === newStatus);
      });
      render();
      setStatusPill('live');
    } catch (err) {
      alert('Status update failed. Please try again. (' + err.message + ')');
      setStatusPill('error');
    } finally {
      btn.disabled = false;
      btn.textContent = prevLabel;
    }
  });

  // Re-run AI screening (#5). Only valid for early-state apps; the function
  // returns 409 "already_advanced" otherwise (so a manual decision is safe).
  var btnRescreen = document.getElementById('btn-rescreen');
  var rescreenMsg = document.getElementById('rescreen-msg');
  if (btnRescreen) {
    btnRescreen.addEventListener('click', async function () {
      if (!state.activeRow) return;
      btnRescreen.disabled = true;
      var orig = btnRescreen.textContent;
      btnRescreen.textContent = 'Screening…';
      if (rescreenMsg) { rescreenMsg.textContent = ''; rescreenMsg.className = 'rescreen-msg'; }
      try {
        var res = await fetch('/.netlify/functions/admin-rescreen', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ id: state.activeRow.id })
        });
        if (res.status === 409) {
          if (rescreenMsg) { rescreenMsg.textContent = 'Status already advanced — re-screen unavailable.'; rescreenMsg.className = 'rescreen-msg is-warn'; }
        } else if (!res.ok) {
          throw new Error('HTTP ' + res.status);
        } else {
          if (rescreenMsg) { rescreenMsg.textContent = 'Re-screened. Refreshing…'; rescreenMsg.className = 'rescreen-msg is-ok'; }
          setTimeout(fetchData, 1200);
        }
      } catch (err) {
        if (rescreenMsg) { rescreenMsg.textContent = 'Re-screen failed. Try again.'; rescreenMsg.className = 'rescreen-msg is-err'; }
      } finally {
        btnRescreen.disabled = false;
        btnRescreen.textContent = orig;
      }
    });
  }

  // Finalist / winner notification emails (#7). The function only sends when
  // the application's status already matches (mark status first), so this
  // can't email a "winner" notice to someone who isn't one.
  var notifyMsg = document.getElementById('notify-msg');
  ['btn-notify-finalist', 'btn-notify-winner'].forEach(function (bid) {
    var b = document.getElementById(bid);
    if (!b) return;
    b.addEventListener('click', async function () {
      if (!state.activeRow) return;
      var kind = b.getAttribute('data-kind');
      b.disabled = true;
      var orig = b.textContent; b.textContent = 'Sending…';
      if (notifyMsg) { notifyMsg.textContent = ''; notifyMsg.className = 'rescreen-msg'; }
      try {
        var res = await fetch('/.netlify/functions/admin-notify', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
          body: JSON.stringify({ id: state.activeRow.id, kind: kind })
        });
        var data = await res.json().catch(function () { return {}; });
        if (res.status === 409) {
          if (notifyMsg) { notifyMsg.textContent = 'Mark the application as ' + kind + ' first.'; notifyMsg.className = 'rescreen-msg is-warn'; }
        } else if (res.status === 422) {
          if (notifyMsg) { notifyMsg.textContent = 'No valid applicant email on file.'; notifyMsg.className = 'rescreen-msg is-warn'; }
        } else if (!res.ok) {
          throw new Error('HTTP ' + res.status);
        } else if (notifyMsg) {
          notifyMsg.textContent = 'Sent to ' + (data.sent_to || 'applicant') + '.'; notifyMsg.className = 'rescreen-msg is-ok';
        }
      } catch (err) {
        if (notifyMsg) { notifyMsg.textContent = 'Send failed. Try again.'; notifyMsg.className = 'rescreen-msg is-err'; }
      } finally {
        b.disabled = false; b.textContent = orig;
      }
    });
  });

  // ---------- Bulk selection + status actions (#10) ----------
  var bulkBar = document.getElementById('bulk-bar');
  var bulkCount = document.getElementById('bulk-count');
  var bulkMsg = document.getElementById('bulk-msg');
  var selectAllEl = document.getElementById('select-all');
  function updateBulkBar() {
    var n = selectedIds.size;
    if (bulkBar) bulkBar.hidden = n === 0;
    if (bulkCount) bulkCount.textContent = n + ' selected';
  }
  function syncSelectAll() {
    if (!selectAllEl) return;
    var cbs = tbody.querySelectorAll('.row-cb');
    var checked = 0;
    cbs.forEach(function (cb) { if (cb.checked) checked++; });
    selectAllEl.checked = cbs.length > 0 && checked === cbs.length;
    selectAllEl.indeterminate = checked > 0 && checked < cbs.length;
    updateBulkBar();
  }
  tbody.addEventListener('change', function (e) {
    var cb = e.target.closest('.row-cb');
    if (!cb) return;
    var id = cb.getAttribute('data-cb-id');
    if (cb.checked) selectedIds.add(id); else selectedIds.delete(id);
    syncSelectAll();
  });
  if (selectAllEl) selectAllEl.addEventListener('change', function () {
    tbody.querySelectorAll('.row-cb').forEach(function (cb) {
      cb.checked = selectAllEl.checked;
      var id = cb.getAttribute('data-cb-id');
      if (selectAllEl.checked) selectedIds.add(id); else selectedIds.delete(id);
    });
    updateBulkBar();
  });
  var bulkClear = document.getElementById('bulk-clear');
  if (bulkClear) bulkClear.addEventListener('click', function () {
    selectedIds.clear();
    tbody.querySelectorAll('.row-cb').forEach(function (cb) { cb.checked = false; });
    syncSelectAll();
    if (bulkMsg) bulkMsg.textContent = '';
  });
  if (bulkBar) bulkBar.addEventListener('click', async function (e) {
    var btn = e.target.closest('[data-bulk-status]');
    if (!btn) return;
    var status = btn.getAttribute('data-bulk-status');
    var ids = Array.from(selectedIds);
    if (!ids.length) return;
    if (!window.confirm('Set ' + ids.length + ' application(s) to "' + status + '"?')) return;
    var btns = bulkBar.querySelectorAll('button');
    btns.forEach(function (b) { b.disabled = true; });
    if (bulkMsg) { bulkMsg.textContent = 'Updating ' + ids.length + '…'; bulkMsg.className = 'rescreen-msg'; }
    try {
      var res = await fetch('/.netlify/functions/admin-bulk-update', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
        body: JSON.stringify({ ids: ids, status: status })
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      selectedIds.clear();
      if (bulkMsg) { bulkMsg.textContent = 'Updated. Refreshing…'; bulkMsg.className = 'rescreen-msg is-ok'; }
      setTimeout(fetchData, 800);
    } catch (err) {
      if (bulkMsg) { bulkMsg.textContent = 'Bulk update failed.'; bulkMsg.className = 'rescreen-msg is-err'; }
    } finally {
      btns.forEach(function (b) { b.disabled = false; });
    }
  });

  // ---------- Activity log (#10) ----------
  var activitySection = document.getElementById('admin-activity');
  var activityList = document.getElementById('activity-list');
  var activityToggle = document.getElementById('btn-toggle-activity');
  var activitySub = document.getElementById('activity-sub');
  function auditLine(a) {
    var when = a.at ? new Date(a.at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '';
    var detail = '';
    if (a.before_data && a.before_data.status != null && a.after_data && a.after_data.status != null) {
      detail = escHtml(a.before_data.status) + ' → ' + escHtml(a.after_data.status);
    } else if (a.after_data && a.after_data.status != null) {
      detail = '→ ' + escHtml(a.after_data.status);
    } else if (a.notes) {
      detail = escHtml(a.notes);
    }
    var tgt = a.target_id ? (String(a.target_id).slice(0, 8) + '…') : '';
    return '<li class="activity-item">' +
      '<span class="activity-when">' + escHtml(when) + '</span>' +
      '<span class="activity-action">' + escHtml(String(a.action || '').replace(/_/g, ' ')) + '</span>' +
      '<span class="activity-detail">' + detail + '</span>' +
      '<span class="activity-target">' + escHtml(tgt) + '</span>' +
      '</li>';
  }
  function renderAudit() {
    if (!activitySection || !activityList) return;
    var items = state.audit || [];
    if (!items.length) { activitySection.hidden = true; return; }
    activitySection.hidden = false;
    if (activitySub) activitySub.textContent = items.length + ' recent events';
    activityList.innerHTML = items.map(auditLine).join('');
  }
  if (activityToggle) activityToggle.addEventListener('click', function () {
    var open = activityList.hidden;
    activityList.hidden = !open;
    activityToggle.textContent = open ? 'Hide' : 'Show';
    activityToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  });

  // ---------- Filters ----------
  pillsEl.addEventListener('click', function (e) {
    var b = e.target.closest('[data-filter]');
    if (!b) return;
    pillsEl.querySelectorAll('.filter-pill').forEach(function (x) { x.classList.remove('is-active'); });
    b.classList.add('is-active');
    state.filter = b.getAttribute('data-filter');
    render();
  });
  searchInput.addEventListener('input', function () {
    state.search = searchInput.value || '';
    render();
  });

  // ---------- Polling ----------
  async function fetchData() {
    if (state.fetchInFlight) return;
    state.fetchInFlight = true;
    setStatusPill('loading');
    try {
      var res = await fetch(LIST_ENDPOINT, { credentials: 'include' });
      if (res.status === 401) {
        // Session expired — redirect to admin gate.
        window.location.href = '/admin/';
        return;
      }
      if (!res.ok) throw new Error('Fetch failed: ' + res.status);
      var data = await res.json();
      state.rows = data.rows || [];
      state.stats = data.stats || null;
      state.judgesProgress = data.judges_progress || [];
      state.inbox = data.inbox || [];
      state.inboxStats = data.inbox_stats || null;
      state.outboundReplies = data.outbound_replies || [];
      state.audit = data.audit || [];
      updatedAt.textContent = 'Updated ' + new Date(data.fetched_at).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit' });
      renderJudgesProgress(state.judgesProgress);
      renderInbox();
      renderAudit();
      render();
      // If the drawer is open and the active row got new scoring data, refresh its summary in-place.
      if (state.activeRow) {
        var updated = state.rows.find(function (r) { return r.id === state.activeRow.id; });
        if (updated) {
          state.activeRow.scoring = updated.scoring;
          var sumEl = document.getElementById('drawer-scoring-summary');
          if (sumEl) sumEl.outerHTML = renderScoringSummary(state.activeRow);
        }
      }
      setStatusPill('live');
    } catch (err) {
      console.error('Admin fetch error:', err);
      setStatusPill('error');
    } finally {
      state.fetchInFlight = false;
    }
  }

  function startPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(function () {
      if (document.visibilityState === 'visible') fetchData();
    }, POLL_INTERVAL_MS);
  }

  btnRefresh.addEventListener('click', fetchData);
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') fetchData();
  });

  // ---------- Invite-judge modal ----------
  var inviteBtn = document.getElementById('btn-invite-judge');
  var inviteModal = document.getElementById('invite-modal');
  var inviteForm = document.getElementById('invite-form');
  var inviteSubmit = document.getElementById('invite-submit');
  var inviteMsg = document.getElementById('invite-msg');

  function openInvite() {
    inviteModal.setAttribute('aria-hidden', 'false');
    inviteMsg.textContent = '';
    inviteMsg.className = 'invite-msg';
    var nameInput = inviteForm.querySelector('input[name="name"]');
    if (nameInput) setTimeout(function () { nameInput.focus(); }, 30);
  }
  function closeInvite() {
    inviteModal.setAttribute('aria-hidden', 'true');
    inviteForm.reset();
  }
  if (inviteBtn) inviteBtn.addEventListener('click', openInvite);
  document.querySelectorAll('[data-invite-close]').forEach(function (el) {
    el.addEventListener('click', closeInvite);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && inviteModal.getAttribute('aria-hidden') === 'false') closeInvite();
  });
  if (inviteForm) {
    inviteForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      var fd = new FormData(inviteForm);
      var payload = {
        name: String(fd.get('name') || '').trim(),
        email: String(fd.get('email') || '').trim().toLowerCase(),
        affiliation: String(fd.get('affiliation') || '').trim() || null,
      };
      if (!payload.name || !payload.email) {
        inviteMsg.textContent = 'Name and email are required.';
        inviteMsg.className = 'invite-msg is-err';
        return;
      }
      inviteSubmit.disabled = true;
      inviteMsg.textContent = 'Sending…';
      inviteMsg.className = 'invite-msg';
      try {
        var res = await fetch('/.netlify/functions/invite-judge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(payload),
        });
        var data = await res.json().catch(function () { return {}; });
        if (!res.ok) {
          throw new Error(data.error || ('HTTP ' + res.status));
        }
        inviteMsg.textContent = 'Invite sent to ' + payload.email + '.';
        inviteMsg.className = 'invite-msg is-ok';
        inviteForm.reset();
        setTimeout(closeInvite, 1500);
      } catch (err) {
        inviteMsg.textContent = 'Failed: ' + err.message;
        inviteMsg.className = 'invite-msg is-err';
      } finally {
        inviteSubmit.disabled = false;
      }
    });
  }

  fetchData();
  startPolling();
})();
