/* ============================================================
   America250 Community Futures Challenge — Application form
   Multi-step navigation, auto-save to localStorage, validation,
   file handling, review rendering, stub submit.
   ============================================================ */

(function () {
  'use strict';

  var STORAGE_KEY = 'nn_apply_draft_v1';
  var TOTAL_STEPS = 6;

  // ---------- Supabase config ----------
  // The anon key is public-by-design; row-level security policies in Supabase
  // restrict what it can do. Service-role-key operations live in edge functions
  // (AI screening, admin tools), never the browser.
  var SUPABASE_URL = 'https://emhcsinxtxshdgiceofa.supabase.co';
  var SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVtaGNzaW54dHhzaGRnaWNlb2ZhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzgxODkzMDQsImV4cCI6MjA5Mzc2NTMwNH0.7MuJu7uO8u1mHa02Ld0XoYNgkPXBHL2zX88-ehkN3u4';

  function sbHeaders(extra) {
    var h = {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': 'Bearer ' + SUPABASE_ANON_KEY
    };
    if (extra) Object.keys(extra).forEach(function (k) { h[k] = extra[k]; });
    return h;
  }

  var form = document.getElementById('apply-form');
  if (!form) return;

  var steps = Array.from(form.querySelectorAll('.step'));
  var progressFill = document.getElementById('apply-progress-fill');
  var progressSteps = Array.from(document.querySelectorAll('.apply-progress__step'));
  var btnPrev = document.getElementById('btn-prev');
  var btnNext = document.getElementById('btn-next');
  var btnSubmit = document.getElementById('btn-submit');
  var stepMeta = document.getElementById('step-meta');
  var savedBadge = document.getElementById('apply-saved');
  var successPanel = document.getElementById('apply-success');

  var ELIG_FIELDS = ['elig_age','elig_audience','elig_phase','elig_scope','elig_coi'];

  var current = 1;
  var farthestSeen = 1;

  // ---------- Save-and-resume token (#8) ----------
  var TOKEN_KEY = 'nn_apply_token_v1';
  var TOKEN_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  function newToken() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    // CSPRNG fallback — never Math.random (predictable ids = guessable drafts).
    var b = new Uint8Array(16);
    if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
    var h = [];
    for (var i = 0; i < 16; i++) h.push((b[i] + 0x100).toString(16).slice(1));
    return h[0]+h[1]+h[2]+h[3]+'-'+h[4]+h[5]+'-'+h[6]+h[7]+'-'+h[8]+h[9]+'-'+h[10]+h[11]+h[12]+h[13]+h[14]+h[15];
  }
  var resumeToken = (function () {
    var t = null;
    try { t = localStorage.getItem(TOKEN_KEY); } catch (e) {}
    if (!t || !TOKEN_RE.test(t)) { t = newToken(); try { localStorage.setItem(TOKEN_KEY, t); } catch (e) {} }
    return t;
  })();

  // ---------- State load ----------
  // Populate the form + step from a serialized draft object (localStorage or server).
  function applyDraftData(data) {
    if (!data || typeof data !== 'object') return;
    if (typeof data.step === 'number') current = Math.min(Math.max(data.step, 1), TOTAL_STEPS);
    if (typeof data.farthest === 'number') farthestSeen = Math.min(Math.max(data.farthest, 1), TOTAL_STEPS);
    Object.keys(data.fields || {}).forEach(function (name) {
      var el = form.elements[name];
      if (!el) return;
      if (el.type === 'checkbox') {
        el.checked = !!data.fields[name];
      } else if (el.type === 'radio' || (el.length && el[0] && el[0].type === 'radio')) {
        var nodes = form.querySelectorAll('[name="' + name + '"]');
        nodes.forEach(function (n) { n.checked = (n.value === data.fields[name]); });
      } else {
        el.value = data.fields[name] || '';
      }
    });
  }
  function loadDraft() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (raw) applyDraftData(JSON.parse(raw));
    } catch (e) { /* ignore */ }
  }

  function serialize() {
    var fields = {};
    Array.from(form.elements).forEach(function (el) {
      if (!el.name) return;
      if (el.type === 'submit' || el.type === 'button' || el.type === 'file') return;
      if (el.type === 'checkbox') {
        fields[el.name] = el.checked;
      } else if (el.type === 'radio') {
        if (el.checked) fields[el.name] = el.value;
        else if (!(el.name in fields)) fields[el.name] = '';
      } else {
        fields[el.name] = el.value;
      }
    });
    return { step: current, farthest: farthestSeen, fields: fields, savedAt: Date.now() };
  }

  var saveTimer = null;
  function scheduleSave() {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(serialize()));
        showSavedBadge();
      } catch (e) { /* quota etc. */ }
      scheduleServerSave();
    }, 350);
  }
  // Server-side draft sync (#8) — longer debounce so we don't hammer the API.
  var serverTimer = null;
  function scheduleServerSave() {
    if (serverTimer) clearTimeout(serverTimer);
    serverTimer = setTimeout(function () {
      fetch('/.netlify/functions/apply-draft', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: resumeToken, data: serialize() })
      }).catch(function () { /* offline / non-fatal — localStorage still holds it */ });
    }, 2500);
  }
  var savedTimer = null;
  function showSavedBadge() {
    if (!savedBadge) return;
    savedBadge.hidden = false;
    savedBadge.classList.add('is-fresh');
    if (savedTimer) clearTimeout(savedTimer);
    savedTimer = setTimeout(function () { savedBadge.classList.remove('is-fresh'); }, 1200);
  }

  form.addEventListener('input', scheduleSave);
  form.addEventListener('change', scheduleSave);

  // ---------- URL normalization ----------
  // type="url" inputs reject anything without a protocol, which silently blocks
  // submit even on optional fields. On blur, if the user typed a bare domain
  // (no scheme), prepend https:// for them. Visible change → they see it worked.
  Array.from(form.querySelectorAll('input[type="url"]')).forEach(function (el) {
    el.addEventListener('blur', function () {
      var v = (el.value || '').trim();
      if (!v) return;
      // If it already has a scheme (http://, https://, mailto:, ftp://…) leave it.
      if (/^[a-z][a-z0-9+.\-]*:/i.test(v)) {
        if (v !== el.value) el.value = v;
        return;
      }
      // Otherwise treat it as a bare host/path and prefix https://
      el.value = 'https://' + v;
      // If the field was previously flagged, clear the error state on blur — the
      // value is probably valid now.
      el.classList.remove('is-error');
      var fw = el.closest('.field');
      if (fw) fw.classList.remove('is-error');
      // Persist the normalized value to the draft.
      scheduleSave();
    });
  });

  // ---------- Character counters ----------
  Array.from(form.querySelectorAll('[data-counter]')).forEach(function (ta) {
    var max = parseInt(ta.getAttribute('data-counter'), 10);
    var counter = form.querySelector('[data-count-for="' + ta.name + '"]');
    if (!counter) return;
    function update() {
      var len = ta.value.length;
      counter.textContent = len + ' / ' + max;
      counter.classList.toggle('is-near', len >= max * 0.85 && len < max);
      counter.classList.toggle('is-over', len >= max);
    }
    ta.addEventListener('input', update);
    update();
  });

  // ---------- Eligibility live check ----------
  var eligFail = document.getElementById('elig-fail');
  function checkEligibility() {
    var anyNo = ELIG_FIELDS.some(function (name) {
      var checked = form.querySelector('[name="' + name + '"]:checked');
      return checked && checked.value === 'no';
    });
    if (eligFail) eligFail.hidden = !anyNo;
    return !anyNo;
  }
  ELIG_FIELDS.forEach(function (name) {
    form.querySelectorAll('[name="' + name + '"]').forEach(function (el) {
      el.addEventListener('change', checkEligibility);
    });
  });

  // ---------- Step navigation ----------
  function showStep(n, opts) {
    opts = opts || {};
    n = Math.min(Math.max(n, 1), TOTAL_STEPS);
    current = n;
    if (n > farthestSeen) farthestSeen = n;
    steps.forEach(function (s) {
      s.hidden = parseInt(s.getAttribute('data-step'), 10) !== n;
    });
    progressSteps.forEach(function (b, i) {
      var idx = i + 1;
      b.classList.toggle('is-active', idx === n);
      b.classList.toggle('is-done', idx < n);
      b.disabled = idx > farthestSeen;
    });
    var pct = ((n - 1) / (TOTAL_STEPS - 1)) * 100;
    if (progressFill) progressFill.style.width = pct + '%';
    if (stepMeta) stepMeta.textContent = 'Step ' + n + ' of ' + TOTAL_STEPS + ' · Auto-saving';
    btnPrev.hidden = n === 1;
    btnNext.hidden = n === TOTAL_STEPS;
    btnSubmit.hidden = n !== TOTAL_STEPS;
    if (n === TOTAL_STEPS) renderReview();
    if (!opts.silent) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    scheduleSave();
  }

  // ---------- Validation ----------
  function fieldsForStep(n) {
    var step = form.querySelector('.step[data-step="' + n + '"]');
    if (!step) return [];
    return Array.from(step.querySelectorAll('input, select, textarea')).filter(function (el) {
      return el.name && el.type !== 'submit' && el.type !== 'button';
    });
  }

  function validateStep(n) {
    var firstInvalid = null;
    var fields = fieldsForStep(n);
    fields.forEach(function (el) {
      var fieldWrap = el.closest('.field');
      if (fieldWrap) fieldWrap.classList.remove('is-error');
      var prevError = el.parentElement.querySelector('.field__error');
      if (prevError) prevError.remove();
    });

    if (n === 1) {
      // All eligibility questions answered, all "yes" before continuing.
      var unanswered = ELIG_FIELDS.filter(function (name) {
        return !form.querySelector('[name="' + name + '"]:checked');
      });
      if (unanswered.length > 0) {
        return { ok: false, message: 'Answer every question to continue.' };
      }
      if (!checkEligibility()) {
        return { ok: false, message: 'One or more answers indicate this project may not be eligible. Email apply@america250cfc.org if you think otherwise.' };
      }
      return { ok: true };
    }

    fields.forEach(function (el) {
      if (!el.willValidate) return;
      if (!el.checkValidity()) {
        el.classList.add('is-error');
        var fw = el.closest('.field');
        if (fw) fw.classList.add('is-error');
        if (!firstInvalid) firstInvalid = el;
      }
    });

    if (firstInvalid) {
      try { firstInvalid.focus({ preventScroll: false }); } catch (e) { firstInvalid.focus(); }
      return { ok: false, message: 'Please complete the highlighted fields.' };
    }
    return { ok: true };
  }

  btnNext.addEventListener('click', function () {
    var v = validateStep(current);
    if (!v.ok) {
      // bring step nav meta into a temporary error mode
      if (stepMeta) {
        stepMeta.textContent = v.message;
        stepMeta.style.color = 'var(--c-accent)';
        setTimeout(function () {
          stepMeta.style.color = '';
          stepMeta.textContent = 'Step ' + current + ' of ' + TOTAL_STEPS + ' · Auto-saving';
        }, 4000);
      }
      return;
    }
    showStep(current + 1);
  });
  btnPrev.addEventListener('click', function () { showStep(current - 1); });
  progressSteps.forEach(function (b) {
    b.addEventListener('click', function () {
      var goto = parseInt(b.getAttribute('data-goto'), 10);
      if (goto > farthestSeen) return;
      // validate the current step before jumping forward
      if (goto > current) {
        var v = validateStep(current);
        if (!v.ok) return;
      }
      showStep(goto);
    });
  });

  // ---------- File upload (UI only — actual upload wires to Supabase later) ----------
  var fileInput = document.getElementById('file-input');
  var uploadList = document.getElementById('upload-list');
  var uploadZone = document.getElementById('upload-zone');
  var attachedFiles = [];
  var MAX_FILES = 5;
  var MAX_SIZE = 10 * 1024 * 1024; // 10 MB

  function fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  }
  function renderFileList() {
    if (!uploadList) return;
    uploadList.innerHTML = '';
    attachedFiles.forEach(function (f, i) {
      var li = document.createElement('li');
      li.className = 'upload__item';
      li.innerHTML = '<span><strong class="upload__item-name"></strong> &nbsp;<span class="upload__item-size"></span></span>' +
                     '<button type="button" class="upload__remove" aria-label="Remove file">×</button>';
      li.querySelector('.upload__item-name').textContent = f.name;
      li.querySelector('.upload__item-size').textContent = fmtSize(f.size);
      li.querySelector('.upload__remove').addEventListener('click', function () {
        attachedFiles.splice(i, 1);
        renderFileList();
      });
      uploadList.appendChild(li);
    });
  }
  function addFiles(list) {
    Array.from(list).forEach(function (f) {
      if (attachedFiles.length >= MAX_FILES) return;
      if (f.size > MAX_SIZE) {
        alert('"' + f.name + '" is over the 10MB limit. Please compress or split.');
        return;
      }
      attachedFiles.push(f);
    });
    renderFileList();
  }
  if (fileInput) {
    fileInput.addEventListener('change', function () {
      addFiles(fileInput.files);
      fileInput.value = '';
    });
  }
  if (uploadZone) {
    ['dragenter', 'dragover'].forEach(function (ev) {
      uploadZone.addEventListener(ev, function (e) {
        e.preventDefault(); e.stopPropagation();
        uploadZone.classList.add('is-dragover');
      });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      uploadZone.addEventListener(ev, function (e) {
        e.preventDefault(); e.stopPropagation();
        uploadZone.classList.remove('is-dragover');
      });
    });
    uploadZone.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files) {
        addFiles(e.dataTransfer.files);
      }
    });
  }

  // ---------- Review render ----------
  var REVIEW_GROUPS = [
    { step: 2, title: 'About you & your team', rows: [
      ['Lead applicant', 'lead_name'],
      ['Role', 'lead_role'],
      ['Email', 'lead_email'],
      ['Organization', 'org_name'],
      ['Website', 'org_url'],
      ['Tax status', 'org_type'],
      ['Registered business entity', 'org_has_entity'],
      ['Team', 'team_desc'],
    ]},
    { step: 3, title: 'Project', rows: [
      ['Title', 'proj_title'],
      ['Summary', 'proj_summary'],
      ['Category', 'proj_category'],
      ['Phase', 'proj_phase'],
      ['Location', '_location'],
      ['Communities served', 'proj_communities'],
      ['Total budget', 'proj_budget_total', 'money'],
      ['Already raised', 'proj_budget_raised', 'money'],
      ['What $50K funds', 'proj_use_of_funds'],
    ]},
    { step: 4, title: 'Impact & approach', rows: [
      ['Community impact', 'impact_community'],
      ['Feasibility', 'impact_feasibility'],
      ['Innovation', 'impact_innovation'],
      ['Sustainability', 'impact_sustainability'],
      ['Founder & team', 'impact_founder_team'],
    ]},
    { step: 5, title: 'Attachments', rows: [
      ['Files', '_files'],
      ['Video URL', 'proj_video_url'],
    ]},
  ];

  function fmtMoney(v) {
    if (v === '' || v == null) return '';
    var n = parseInt(v, 10);
    if (isNaN(n)) return v;
    return '$' + n.toLocaleString('en-US');
  }
  function renderReview() {
    var out = document.getElementById('review-output');
    if (!out) return;
    out.innerHTML = '';
    REVIEW_GROUPS.forEach(function (g) {
      var section = document.createElement('section');
      section.className = 'review__group';
      var head = document.createElement('div');
      head.className = 'review__group-h';
      head.innerHTML = '<span></span><button type="button" class="review__edit" data-edit-step="' + g.step + '">Edit</button>';
      head.querySelector('span').textContent = g.title;
      section.appendChild(head);

      var dl = document.createElement('dl');
      g.rows.forEach(function (r) {
        var label = r[0], key = r[1], format = r[2];
        var value = '';
        if (key === '_location') {
          var c = form.elements.proj_city ? form.elements.proj_city.value : '';
          var s = form.elements.proj_state ? form.elements.proj_state.value : '';
          value = (c || s) ? (c + ', ' + s).replace(/^,\s*|\s*,\s*$/g, '') : '';
        } else if (key === '_files') {
          if (attachedFiles.length === 0) value = '';
          else value = attachedFiles.map(function (f) { return f.name + ' (' + fmtSize(f.size) + ')'; }).join('\n');
        } else if (form.elements[key]) {
          value = form.elements[key].value || '';
          if (format === 'money') value = fmtMoney(value);
        }
        var dt = document.createElement('dt');
        var dd = document.createElement('dd');
        dt.textContent = label;
        if (!value) {
          dd.textContent = '—';
          dd.classList.add('empty');
        } else {
          dd.textContent = value;
        }
        var row = document.createElement('div');
        row.className = 'review__row';
        row.appendChild(dt); row.appendChild(dd);
        dl.appendChild(row);
      });
      section.appendChild(dl);
      out.appendChild(section);
    });

    out.querySelectorAll('[data-edit-step]').forEach(function (b) {
      b.addEventListener('click', function () {
        showStep(parseInt(b.getAttribute('data-edit-step'), 10));
      });
    });
  }

  // ---------- Build the Supabase payload from the form ----------
  function buildPayload() {
    var f = form.elements;
    function txt(name) { return (f[name] && f[name].value && f[name].value.trim()) || null; }
    function intOrNull(name) {
      var v = f[name] && f[name].value;
      if (v === '' || v == null) return null;
      var n = parseInt(v, 10);
      return isNaN(n) ? null : n;
    }
    function bool(name) { return !!(f[name] && f[name].checked); }
    function radio(name) {
      var node = form.querySelector('[name="' + name + '"]:checked');
      return node ? node.value : null;
    }
    return {
      elig_age: radio('elig_age'),
      elig_audience: radio('elig_audience'),
      elig_phase: radio('elig_phase'),
      elig_scope: radio('elig_scope'),
      elig_coi: radio('elig_coi'),

      lead_name: txt('lead_name'),
      lead_role: txt('lead_role'),
      lead_email: txt('lead_email'),

      org_name: txt('org_name'),
      org_url: txt('org_url'),
      org_type: txt('org_type'),
      org_has_entity: txt('org_has_entity'),
      team_desc: txt('team_desc'),

      proj_title: txt('proj_title'),
      proj_summary: txt('proj_summary'),
      proj_category: txt('proj_category'),
      proj_phase: txt('proj_phase'),
      proj_city: txt('proj_city'),
      proj_state: txt('proj_state'),
      proj_communities: txt('proj_communities'),
      proj_budget_total: intOrNull('proj_budget_total'),
      proj_budget_raised: intOrNull('proj_budget_raised'),
      proj_use_of_funds: txt('proj_use_of_funds'),
      proj_video_url: txt('proj_video_url'),

      impact_community: txt('impact_community'),
      impact_innovation: txt('impact_innovation'),
      impact_feasibility: txt('impact_feasibility'),
      impact_sustainability: txt('impact_sustainability'),
      impact_founder_team: txt('impact_founder_team'),

      legal_terms: bool('legal_terms'),
      legal_attribution: bool('legal_attribution'),

      user_agent: navigator.userAgent,
      submission_source: 'web'
    };
  }

  function submitError(msg) {
    if (!stepMeta) return;
    stepMeta.textContent = msg;
    stepMeta.style.color = 'var(--c-accent)';
  }

  // ---------- Submit ----------
  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    // Validate every previous step before allowing submit. If anything's wrong,
    // jump back to that step AND surface a message — otherwise the user is left
    // wondering why the submit button "did nothing."
    for (var n = 1; n < TOTAL_STEPS; n++) {
      var v = validateStep(n);
      if (!v.ok) {
        showStep(n);
        if (stepMeta) {
          stepMeta.textContent = 'Step ' + n + ' needs a fix: ' + v.message;
          stepMeta.style.color = 'var(--c-red)';
          setTimeout(function () {
            stepMeta.style.color = '';
            stepMeta.textContent = 'Step ' + current + ' of ' + TOTAL_STEPS + ' · Auto-saving';
          }, 6000);
        }
        return;
      }
    }
    // Required legal checkboxes
    var t = form.elements.legal_terms, a = form.elements.legal_attribution;
    if (!t.checked || !a.checked) {
      submitError('Both confirmations are required to submit.');
      return;
    }

    // Honeypot — if this hidden field is filled, the submitter is a bot. Show
    // a fake-success state so the bot thinks it worked, but never actually submit.
    var honeypotEl = form.elements.nn_organization_url;
    if (honeypotEl && honeypotEl.value) {
      // Silent fake-success.
      form.hidden = true;
      document.querySelector('.apply-progress').hidden = true;
      document.querySelector('.apply-header').hidden = true;
      if (successPanel) successPanel.hidden = false;
      try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
      return;
    }

    // Require the Cloudflare Turnstile token. The widget injects a hidden
    // "cf-turnstile-response" field into the form once the visitor passes.
    var tsField = form.elements['cf-turnstile-response'];
    var tsToken = tsField && tsField.value ? tsField.value : '';
    if (!tsToken) {
      submitError('Please complete the “I’m human” verification, then submit.');
      return;
    }

    // Lock the submit button to prevent double-submit
    var originalLabel = btnSubmit.innerHTML;
    btnSubmit.disabled = true;
    btnSubmit.innerHTML = 'Submitting…';

    // Generate the application id client-side. Using `Prefer: return=representation`
    // would require a SELECT policy on the table (which we intentionally don't grant
    // to anon — applicants shouldn't be able to browse other people's submissions).
    // Generating the UUID here lets us use `return=minimal` and still tell the
    // applicant their reference id immediately.
    var appId = newToken();

    try {
      // 1) Verify (Cloudflare Turnstile) + insert the application via the
      //    server-side gateway. Direct anon inserts are revoked at the DB, so
      //    this token-gated path is the only way to create an application.
      var payload = buildPayload();
      payload.id = appId;
      var insertRes = await fetch('/.netlify/functions/submit-application', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: payload, token: tsToken })
      });
      if (!insertRes.ok) {
        if (window.turnstile) { try { window.turnstile.reset(); } catch (e) {} }
        var txt2 = await insertRes.text();
        throw new Error('Application submit failed (' + insertRes.status + '): ' + txt2);
      }

      // 2) Upload attachments (best-effort — failures don't kill the submission)
      var attachmentRows = [];
      for (var i = 0; i < attachedFiles.length; i++) {
        var file = attachedFiles[i];
        var safe = file.name.replace(/[^\w.\-]+/g, '_').slice(0, 120);
        var path = appId + '/' + Date.now() + '_' + i + '_' + safe;
        try {
          var upRes = await fetch(
            SUPABASE_URL + '/storage/v1/object/application-attachments/' + encodeURI(path),
            {
              method: 'POST',
              headers: sbHeaders({
                'Content-Type': file.type || 'application/octet-stream',
                'x-upsert': 'false'
              }),
              body: file
            }
          );
          if (upRes.ok) {
            attachmentRows.push({
              application_id: appId,
              storage_path: path,
              filename: file.name,
              mime_type: file.type || null,
              size_bytes: file.size
            });
          } else {
            console.warn('Upload failed for', file.name, await upRes.text());
          }
        } catch (err) {
          console.warn('Upload error for', file.name, err);
        }
      }

      // 3) Record attachment metadata (a single batched insert)
      if (attachmentRows.length > 0) {
        await fetch(SUPABASE_URL + '/rest/v1/application_attachments', {
          method: 'POST',
          headers: sbHeaders({
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal'
          }),
          body: JSON.stringify(attachmentRows)
        });
      }
    } catch (err) {
      console.error(err);
      btnSubmit.disabled = false;
      btnSubmit.innerHTML = originalLabel;
      submitError('Couldn’t submit. Please try again, or email apply@america250cfc.org.');
      return;
    }

    // 4) Show success
    var email = form.elements.lead_email.value || '';
    var emailEl = document.getElementById('success-email');
    if (emailEl) emailEl.textContent = email;
    var idEl = document.getElementById('success-id');
    if (idEl && appId) idEl.textContent = appId;

    form.hidden = true;
    document.querySelector('.apply-progress').hidden = true;
    document.querySelector('.apply-header').hidden = true;
    if (successPanel) successPanel.hidden = false;
    window.scrollTo({ top: 0, behavior: 'smooth' });

    try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
  });

  // ---------- Resume link (#8) ----------
  var resumeBtn = document.getElementById('btn-resume-link');
  var resumeMsg = document.getElementById('resume-link-msg');
  function resumeUrl() { return location.origin + '/apply/?resume=' + resumeToken; }
  function updateResumeLink() { if (resumeBtn) resumeBtn.setAttribute('data-url', resumeUrl()); }
  if (resumeBtn) {
    resumeBtn.addEventListener('click', function () {
      var url = resumeUrl();
      // Force an immediate server save so the link works the instant it's shared.
      fetch('/.netlify/functions/apply-draft', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: resumeToken, data: serialize() })
      }).catch(function () {});
      function show(msg) { if (resumeMsg) resumeMsg.textContent = msg; }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(function () { show('Link copied — open it on any device to pick up where you left off.'); })
          .catch(function () { show(url); });
      } else { show(url); }
    });
  }

  // ---------- Social share on success ----------
  (function () {
    var shareUrl = 'https://america250cfc.org';
    var shareText = 'I just applied to the America250 Community Futures Challenge — five community-driven ideas will each win a $50,000 grant.';
    var u = encodeURIComponent(shareUrl);
    var t = encodeURIComponent(shareText);
    var targets = {
      linkedin: 'https://www.linkedin.com/sharing/share-offsite/?url=' + u,
      x: 'https://twitter.com/intent/tweet?text=' + t + '&url=' + u,
      facebook: 'https://www.facebook.com/sharer/sharer.php?u=' + u,
      email: 'mailto:?subject=' + encodeURIComponent('America250 Community Futures Challenge') +
             '&body=' + encodeURIComponent(shareText + '\n\n' + shareUrl)
    };
    var links = document.querySelectorAll('.share-btn[data-share]');
    for (var i = 0; i < links.length; i++) {
      var k = links[i].getAttribute('data-share');
      if (targets[k]) links[i].setAttribute('href', targets[k]);
    }
    var msg = document.getElementById('share-msg');
    function showMsg(s) { if (msg) msg.textContent = s; }
    var nativeBtn = document.getElementById('share-native');
    if (nativeBtn && navigator.share) {
      nativeBtn.hidden = false;
      nativeBtn.addEventListener('click', function () {
        navigator.share({ title: 'America250 Community Futures Challenge', text: shareText, url: shareUrl })
          .catch(function () {});
      });
    }
    var copyBtn = document.getElementById('share-copy');
    if (copyBtn) {
      copyBtn.addEventListener('click', function () {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(shareUrl)
            .then(function () { showMsg('Link copied to clipboard.'); })
            .catch(function () { showMsg(shareUrl); });
        } else { showMsg(shareUrl); }
      });
    }
  })();

  // ---------- Boot ----------
  // If the URL carries a resume token, prefer the server-stored draft so the
  // application can continue on a different device. Otherwise use localStorage.
  var urlResume = null;
  try { urlResume = new URLSearchParams(location.search).get('resume'); } catch (e) {}
  function finishBoot() { showStep(current, { silent: true }); checkEligibility(); updateResumeLink(); }
  if (urlResume && TOKEN_RE.test(urlResume)) {
    resumeToken = urlResume;
    try { localStorage.setItem(TOKEN_KEY, urlResume); } catch (e) {}
    fetch('/.netlify/functions/apply-draft?token=' + encodeURIComponent(urlResume))
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (res) { if (res && res.data) applyDraftData(res.data); else loadDraft(); finishBoot(); })
      .catch(function () { loadDraft(); finishBoot(); });
  } else {
    loadDraft();
    finishBoot();
  }
})();
