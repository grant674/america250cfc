/* ============================================================
   America250 CFC — Judge portal: downloadable score sheets (PDF)

   Builds a PDF in the browser for one application or a packet of
   several: the application as the judge sees it (blind — no applicant
   or organization identity), followed by a score sheet with fillable
   boxes for the five criteria, notes, and the weighted total.

   The PDF is a reading / working copy. Scores only count once they are
   entered and submitted in the judge portal.

   Uses pdf-lib (MIT, vendored at /judge/vendor/pdf-lib.min.js), loaded
   on first use so the judge pages stay light. No data leaves the page:
   the application rows come from the caller (already limited by RLS to
   this judge's assignments) and the file is generated locally.
   ============================================================ */

(function () {
  'use strict';

  // Columns a score sheet needs. Same blind-review set as the scoring page.
  var FIELDS = [
    'id', 'created_at', 'status',
    'lead_role', 'org_type', 'team_desc',
    'proj_title', 'proj_summary', 'proj_category', 'proj_phase',
    'proj_city', 'proj_state', 'proj_communities',
    'proj_budget_total', 'proj_budget_raised', 'proj_use_of_funds', 'proj_video_url',
    'impact_community', 'impact_innovation', 'impact_feasibility', 'impact_sustainability', 'impact_founder_team',
    'elig_age', 'elig_audience', 'elig_phase', 'elig_scope', 'elig_coi', 'elig_nonprofit',
    'judge_notes',
  ].join(',');

  // Keep in step with DIMS in /judge/score/script.js.
  var DIMS = [
    { key: 'community',      col: 'dim_community',      name: 'Community impact', weight: 25, hint: 'Does this innovation meaningfully improve conditions for real people in a real community?' },
    { key: 'feasibility',    col: 'dim_feasibility',    name: 'Feasibility',      weight: 20, hint: 'Is there a credible, executable plan? Does the team have the capacity to deliver?' },
    { key: 'innovation',     col: 'dim_innovation',     name: 'Innovation',       weight: 20, hint: 'Is this a genuinely new approach, or a meaningful improvement on an existing one?' },
    { key: 'sustainability', col: 'dim_sustainability', name: 'Sustainability',   weight: 20, hint: 'Can this grow beyond its initial community? Is there a replication model?' },
    { key: 'founder_team',   col: 'dim_founder_team',   name: 'Founder & team',   weight: 15, hint: 'Does the person or team behind this have the drive, background, and community connection to execute?' },
  ];

  var LIB_URL = '/judge/vendor/pdf-lib.min.js?v=1.17.1';
  var UPLOAD_URL = 'https://america250cfc.org/judge/#upload';
  // a_<application uuid>_<criterion>_<score|notes>
  var FIELD_RE = /^a_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_(community|feasibility|innovation|sustainability|founder_team)_(score|notes)$/;
  var libPromise = null;
  function loadLib() {
    if (window.PDFLib) return Promise.resolve(window.PDFLib);
    if (!libPromise) {
      libPromise = new Promise(function (resolve, reject) {
        var s = document.createElement('script');
        s.src = LIB_URL;
        s.onload = function () { window.PDFLib ? resolve(window.PDFLib) : reject(new Error('PDF library did not load.')); };
        s.onerror = function () { libPromise = null; reject(new Error('Could not load the PDF library.')); };
        document.head.appendChild(s);
      });
    }
    return libPromise;
  }

  // ---- Small formatters ----
  function fmtMoney(v) {
    if (v == null || v === '') return '';
    var n = parseInt(v, 10);
    return isNaN(n) ? String(v) : '$' + n.toLocaleString('en-US');
  }
  function fmtDate(v) {
    if (!v) return '';
    var d = new Date(v);
    return isNaN(d) ? String(v) : d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }
  function slug(s) {
    return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'application';
  }

  // ---- Page geometry (US Letter, points) ----
  var PAGE_W = 612, PAGE_H = 792, M = 54;
  var CONTENT_W = PAGE_W - 2 * M;
  var BOTTOM = M + 22;           // leave room for the footer line

  // The built-in PDF fonts only cover the WinAnsi character set. Applicant
  // text can contain anything (emoji, other scripts), and drawing a character
  // the font lacks throws — so swap common typography for plain equivalents
  // and replace anything else that can't be encoded.
  var SWAPS = {
    '→': '->', '←': '<-', '✓': 'v', '✔': 'v', '✗': 'x', '•': '•',
    ' ': ' ', ' ': ' ', ' ': ' ', ' ': ' ', ' ': ' ', ' ': ' ',
    '​': '', '‌': '', '‍': '', '﻿': '', '️': '', '\t': '    ',
    '‑': '-', '−': '-', '≤': '<=', '≥': '>=', '≠': '!=', '×': 'x',
  };
  function makeSanitizer(font) {
    var cache = {};
    function ok(ch) {
      if (cache[ch] === undefined) {
        try { font.encodeText(ch); cache[ch] = true; } catch (_) { cache[ch] = false; }
      }
      return cache[ch];
    }
    return function (text) {
      var out = '';
      var chars = Array.from(String(text == null ? '' : text).replace(/\r\n?/g, '\n'));
      for (var i = 0; i < chars.length; i++) {
        var ch = chars[i];
        if (ch === '\n') { out += ch; continue; }
        if (Object.prototype.hasOwnProperty.call(SWAPS, ch)) { out += SWAPS[ch]; continue; }
        if (ch < ' ') continue;                       // other control characters
        out += ok(ch) ? ch : (ch.length > 1 ? '' : '?'); // astral (emoji etc.) dropped, others marked
      }
      return out;
    };
  }

  // Greedy word wrap; words wider than the line are broken by character.
  function wrap(text, font, size, maxW) {
    var lines = [];
    String(text).split('\n').forEach(function (para) {
      var words = para.split(/ +/);
      var line = '';
      words.forEach(function (word) {
        var trial = line ? line + ' ' + word : word;
        if (font.widthOfTextAtSize(trial, size) <= maxW) { line = trial; return; }
        if (line) { lines.push(line); line = ''; }
        while (font.widthOfTextAtSize(word, size) > maxW) {
          var cut = word.length - 1;
          while (cut > 1 && font.widthOfTextAtSize(word.slice(0, cut), size) > maxW) cut--;
          lines.push(word.slice(0, cut));
          word = word.slice(cut);
        }
        line = word;
      });
      lines.push(line);
    });
    return lines;
  }

  // ---- Auto-total ----
  // Same formula as the portal and the database: each score (0-10) times its
  // weight, divided by 10. Blank boxes count as 0, so it is a running total
  // until all five are filled; empty when nothing is scored yet.
  function runningTotal(values) {
    var sum = 0, n = 0;
    values.forEach(function (v, i) {
      if (v == null || v === '' || isNaN(Number(v))) return;
      sum += Math.max(0, Math.min(10, Number(v))) * DIMS[i].weight;
      n++;
    });
    return n ? String(Math.round(sum) / 10) : '';
  }
  // The same calculation as a PDF form script (runs inside the PDF viewer,
  // so it must be plain, self-contained ES3).
  function totalJs(prefix) {
    return 'var n=[' + DIMS.map(function (d) { return '"' + prefix + d.key + '_score"'; }).join(',') + '];' +
      'var w=[' + DIMS.map(function (d) { return d.weight; }).join(',') + '];' +
      'var s=0,c=0;' +
      'for(var i=0;i<n.length;i++){var f=this.getField(n[i]);if(!f)continue;var v=String(f.value);' +
      'if(v===""||v==="null"||v==="undefined")continue;var x=Number(v);if(isNaN(x))continue;' +
      'if(x<0)x=0;if(x>10)x=10;s+=x*w[i];c++;}' +
      'event.value=c?String(Math.round(s)/10):"";';
  }
  // Score boxes accept only 0-10 (or blank).
  var VALIDATE_JS = 'if(event.value!==""){var x=Number(event.value);' +
    'if(isNaN(x)||x<0||x>10){app.alert("Please enter a score from 0 to 10.");event.rc=false;}}';

  // ---- Build ----
  // apps: application rows (FIELDS). scoresByApp: { appId: scores row } — any
  // scores already entered in the portal are pre-filled on the sheet.
  async function build(apps, scoresByApp, judgeName) {
    var L = await loadLib();
    var rgb = L.rgb;
    var doc = await L.PDFDocument.create();
    var font = await doc.embedFont(L.StandardFonts.Helvetica);
    var bold = await doc.embedFont(L.StandardFonts.HelveticaBold);
    var italic = await doc.embedFont(L.StandardFonts.HelveticaOblique);
    var clean = makeSanitizer(font);
    var form = doc.getForm();

    var BLUE = rgb(0.106, 0.271, 0.608), MAROON = rgb(0.549, 0.114, 0.251);
    var INK = rgb(0, 0, 0), MUTED = rgb(0.38, 0.38, 0.38), RULE = rgb(0.82, 0.82, 0.82), TINT = rgb(0.945, 0.945, 0.949);

    doc.setTitle(apps.length === 1
      ? 'Score sheet - ' + clean(apps[0].proj_title || 'Application')
      : 'Judging packet - ' + apps.length + ' applications');
    doc.setAuthor('America250 Community Futures Challenge');
    doc.setSubject('Confidential judging material');

    var calcOrder = [];   // total fields, for the form's calculation order
    apps.forEach(function (a, appIndex) {
      var pages = [];
      var page, y;
      function newPage() {
        page = doc.addPage([PAGE_W, PAGE_H]);
        pages.push(page);
        y = PAGE_H - M;
      }
      function need(h) { if (y - h < BOTTOM) newPage(); }
      function text(str, opts) {
        opts = opts || {};
        var f = opts.font || font, size = opts.size || 10, lead = opts.lead || size * 1.38;
        var x = opts.x == null ? M : opts.x, maxW = opts.maxW || (PAGE_W - M - x);
        wrap(clean(str), f, size, maxW).forEach(function (line) {
          need(lead);
          y -= lead;
          if (line) page.drawText(line, { x: x, y: y + lead * 0.26, size: size, font: f, color: opts.color || INK });
        });
      }
      function gap(h) { y -= h; }
      function rule() {
        need(8);
        page.drawLine({ start: { x: M, y: y }, end: { x: PAGE_W - M, y: y }, thickness: 0.6, color: RULE });
      }
      function section(title) {
        need(46);                     // keep a heading with at least a line or two below it
        gap(16);
        page.drawRectangle({ x: M, y: y - 9, width: 14, height: 1.6, color: MAROON });
        page.drawText(clean(title).toUpperCase(), { x: M + 22, y: y - 12, size: 8.5, font: bold, color: MUTED });
        gap(18);
        rule();
        gap(4);
      }
      var LABEL_W = 132;
      function row(label, value) {
        var has = !(value == null || String(value).trim() === '');
        var lines = wrap(clean(has ? value : '-'), font, 10, CONTENT_W - LABEL_W);
        var lead = 13.8;
        need(lead + 4);
        var top = y;
        page.drawText(clean(label), { x: M, y: top - lead + 3.6, size: 9, font: bold, color: MUTED });
        lines.forEach(function (line, i) {
          if (i > 0) need(lead);
          y -= lead;
          if (line) page.drawText(line, { x: M + LABEL_W, y: y + 3.6, size: 10, font: font, color: has ? INK : MUTED });
        });
        gap(4);
      }

      // ----- Cover block -----
      newPage();
      page.drawRectangle({ x: 0, y: PAGE_H - 30, width: PAGE_W, height: 30, color: BLUE });
      page.drawText('AMERICA250 COMMUNITY FUTURES CHALLENGE', { x: M, y: PAGE_H - 19.5, size: 8.5, font: bold, color: rgb(1, 1, 1) });
      var tag = 'JUDGE SCORE SHEET';
      page.drawText(tag, { x: PAGE_W - M - bold.widthOfTextAtSize(tag, 8.5), y: PAGE_H - 19.5, size: 8.5, font: bold, color: rgb(0.949, 0.831, 0.169) });
      y = PAGE_H - 30 - 22;

      if (apps.length > 1) text('Application ' + (appIndex + 1) + ' of ' + apps.length, { size: 9, font: bold, color: MUTED });
      text(a.proj_title || 'Untitled application', { size: 20, font: bold, lead: 25 });
      gap(2);
      var loc = (a.proj_city || '') + (a.proj_state ? (a.proj_city ? ', ' : '') + a.proj_state : '');
      text([String(a.proj_category || '').replace(/-/g, ' '), loc, a.created_at ? 'submitted ' + fmtDate(a.created_at) : '']
        .filter(Boolean).join('  |  '), { size: 10, color: MUTED });
      text('Application ID ' + a.id, { size: 8, color: MUTED });
      gap(8);
      text('Applicant and organization names are removed for impartial review. Please score on the project\'s merits. If a narrative happens to mention specific people or organizations, disregard their identity.',
        { size: 9, font: italic, color: MUTED });

      if (a.judge_notes && String(a.judge_notes).trim()) {
        section('Note from the program team');
        text(a.judge_notes, { size: 10 });
      }

      section('Project');
      row('Summary', a.proj_summary);
      row('Category', String(a.proj_category || '').replace(/-/g, ' '));
      row('Phase', a.proj_phase);
      row('Location', loc);
      row('Communities served', a.proj_communities);
      row('Total budget', fmtMoney(a.proj_budget_total));
      row('Already raised', fmtMoney(a.proj_budget_raised));
      row('Use of $50K', a.proj_use_of_funds);
      row('Video', a.proj_video_url);

      section('Impact & approach');
      DIMS.forEach(function (d) {
        need(40);
        gap(6);
        var top = y;
        page.drawText(clean(d.name), { x: M, y: top - 11, size: 11, font: bold, color: BLUE });
        var wt = d.weight + '% of score';
        page.drawText(wt, { x: PAGE_W - M - font.widthOfTextAtSize(wt, 8.5), y: top - 11, size: 8.5, font: font, color: MUTED });
        gap(16);
        var resp = a['impact_' + d.key];
        if (resp && String(resp).trim()) text(resp, { size: 10 });
        else text('(no response)', { size: 10, font: italic, color: MUTED });
        gap(4);
      });

      section('Team & organization');
      row('Lead role', a.lead_role);
      row('Tax status', a.org_type);
      row('Team', a.team_desc);

      section('Eligibility self-attest');
      row('Lead applicant 21+', a.elig_age);
      row('Serves U.S. adults 21+', a.elig_audience);
      row('Early / pilot / scaling', a.elig_phase);
      row('Not lobbying / partisan', a.elig_scope);
      row('No COI with partners', a.elig_coi);
      row('Registered 501(c)(3)', a.elig_nonprofit);

      // ----- Score sheet (always starts a fresh page, fits on one) -----
      newPage();
      var sc = (scoresByApp && scoresByApp[a.id]) || null;
// "Upload" button, top right: a link to the portal's upload step. A PDF
      // cannot safely send scores itself (it would have to carry the judge's
      // sign-in), so the button opens the portal, where the signed-in judge
      // picks this saved file and reviews what will be saved.
      var upW = 176, upH = 24, upX = PAGE_W - M - upW, upY = y - 26;
      page.drawRectangle({ x: upX, y: upY, width: upW, height: upH, color: BLUE });
      var upLabel = 'UPLOAD SCORES TO THE PORTAL';
      page.drawText(upLabel, { x: upX + (upW - bold.widthOfTextAtSize(upLabel, 8.5)) / 2, y: upY + 8, size: 8.5, font: bold, color: rgb(1, 1, 1) });
      var upNote = 'Save this PDF first, then choose it there.';
      page.drawText(upNote, { x: PAGE_W - M - font.widthOfTextAtSize(upNote, 7.5), y: upY - 10, size: 7.5, font: font, color: MUTED });
      page.node.addAnnot(doc.context.register(doc.context.obj({
        Type: 'Annot', Subtype: 'Link', Rect: [upX, upY, upX + upW, upY + upH], Border: [0, 0, 0],
        A: { Type: 'Action', S: 'URI', URI: L.PDFString.of(UPLOAD_URL) },
      })));

      text('Score sheet', { size: 18, font: bold, lead: 23, maxW: CONTENT_W - upW - 16 });
      text(a.proj_title || 'Untitled application', { size: 11, font: bold, color: BLUE, maxW: CONTENT_W - upW - 16 });
      gap(4);
      text('Score each criterion from 0 (lowest) to 10 (highest), whole numbers. Type into the boxes and the total adds up for you, or print and write by hand.',
        { size: 9.5, color: MUTED });
      if (sc && sc.status === 'submitted') text('You have already submitted scores for this application in the portal; they are shown below.', { size: 9.5, font: bold });
      if (sc && sc.status === 'recused') text('You recused yourself from this application in the portal.', { size: 9.5, font: bold });
      gap(8);

      // Field names carry the application id, so a filled-in sheet can be
      // uploaded back to the portal and matched to the right application
      // (see readScores below). Keep the pattern in step with FIELD_RE.
      var SCORE_W = 62, NOTES_H = 30, prefix = 'a_' + String(a.id).toLowerCase() + '_';
      function field(name, x, yy, w, h, value, multiline) {
        var f = form.createTextField(prefix + name);
        if (multiline) f.enableMultiline();
        if (value != null && value !== '') f.setText(clean(String(value)));
        f.addToPage(page, { x: x, y: yy, width: w, height: h, font: font, borderWidth: 0.8,
          borderColor: rgb(0.45, 0.45, 0.45), backgroundColor: rgb(1, 1, 1), textColor: INK });
        f.setFontSize(multiline ? 9 : 14);
        return f;
      }
      // Attach a form script to a field (C = calculate, V = validate). These
      // run in PDF viewers that support form scripts (Adobe Acrobat / Reader,
      // Chrome, Edge); elsewhere the boxes are simply typed or written in.
      function script(f, kind, js) {
        var action = {};
        action[kind] = { Type: 'Action', S: 'JavaScript', JS: L.PDFHexString.fromText(js) };
        f.acroField.dict.set(L.PDFName.of('AA'), doc.context.obj(action));
      }
      DIMS.forEach(function (d) {
        var blockH = 48 + NOTES_H + 8;
        var top = y;
        page.drawRectangle({ x: M, y: top - blockH, width: CONTENT_W, height: blockH, color: TINT });
        page.drawText(clean(d.name), { x: M + 10, y: top - 16, size: 11.5, font: bold, color: INK });
        var wt = 'weight ' + d.weight + '%';
        page.drawText(wt, { x: M + 14 + bold.widthOfTextAtSize(clean(d.name), 11.5), y: top - 16, size: 8.5, font: font, color: MUTED });
        var hintLines = wrap(clean(d.hint), font, 8.5, CONTENT_W - SCORE_W - 100);
        hintLines.slice(0, 2).forEach(function (line, i) {
          page.drawText(line, { x: M + 10, y: top - 28 - i * 10.5, size: 8.5, font: italic, color: MUTED });
        });
        // Score box, top right
        var sx = PAGE_W - M - 10 - SCORE_W;
        page.drawText('Score', { x: sx - 62, y: top - 20, size: 9, font: bold, color: MUTED });
        page.drawText('/ 10', { x: sx - 62, y: top - 31, size: 8.5, font: font, color: MUTED });
        var sf = field(d.key + '_score', sx - 30, top - 34, SCORE_W + 30 - 0, 24, sc && sc[d.col] != null ? sc[d.col] : '', false);
        script(sf, 'V', VALIDATE_JS);
        // Notes box, full width
        page.drawText('Notes', { x: M + 10, y: top - 48 - 10, size: 7.5, font: bold, color: MUTED });
        field(d.key + '_notes', M + 44, top - 48 - NOTES_H, CONTENT_W - 54, NOTES_H,
          sc && sc.comments && sc.comments[d.key] ? sc.comments[d.key] : '', true);
        y = top - blockH - 6;
      });

      gap(4);
      var totTop = y;
      page.drawRectangle({ x: M, y: totTop - 44, width: CONTENT_W, height: 44, borderColor: BLUE, borderWidth: 1.2 });
      page.drawText('Weighted total', { x: M + 10, y: totTop - 19, size: 12, font: bold, color: BLUE });
      page.drawText('(community x 25 + feasibility x 20 + innovation x 20 + sustainability x 20 + founder & team x 15) / 10',
        { x: M + 10, y: totTop - 33, size: 7.5, font: font, color: MUTED });
      page.drawText('/ 100', { x: PAGE_W - M - 38, y: totTop - 27, size: 10, font: bold, color: MUTED });
      // Auto-total: recalculated by the viewer whenever a score box changes.
      // Pre-filled here too, so it is right even where scripts don't run.
      var pre = runningTotal(DIMS.map(function (d) { return sc ? sc[d.col] : null; }));
      var tf = field('total', PAGE_W - M - 122, totTop - 35, 78, 26, pre, false);
      script(tf, 'C', totalJs(prefix));
      calcOrder.push(tf.acroField.ref);
      y = totTop - 44 - 8;

      text('Working copy: scores count only once they are in the judge portal. Save this PDF, then upload it at america250cfc.org/judge/',
        { size: 9, font: bold });
      text('The total fills in automatically in Adobe Reader, Chrome and Edge; elsewhere, or on paper, use the formula above. To recuse yourself, use the Recuse button in the portal.',
        { size: 8.5, color: MUTED });

      // ----- Footer on every page of this application -----
      var footTitle = clean(a.proj_title || 'Untitled application');
      while (footTitle.length > 4 && font.widthOfTextAtSize(footTitle, 8) > CONTENT_W - 190) footTitle = footTitle.slice(0, -2);
      if (footTitle !== clean(a.proj_title || 'Untitled application')) footTitle += '...';
      pages.forEach(function (p, i) {
        p.drawLine({ start: { x: M, y: M + 6 }, end: { x: PAGE_W - M, y: M + 6 }, thickness: 0.5, color: RULE });
        p.drawText(footTitle, { x: M, y: M - 6, size: 8, font: font, color: MUTED });
        var right = 'Confidential judging material' + (judgeName ? ' - ' + clean(judgeName) : '') + '  |  Page ' + (i + 1) + ' of ' + pages.length;
        while (font.widthOfTextAtSize(right, 8) > 260 && judgeName) { judgeName = ''; right = 'Confidential judging material  |  Page ' + (i + 1) + ' of ' + pages.length; }
        p.drawText(right, { x: PAGE_W - M - font.widthOfTextAtSize(right, 8), y: M - 6, size: 8, font: font, color: MUTED });
      });
    });

    // Tell viewers which fields are calculated (and in what order).
    if (calcOrder.length) form.acroForm.dict.set(L.PDFName.of('CO'), doc.context.obj(calcOrder));
    return await doc.save();
  }

  // ---- Read a filled-in score sheet back ----
  // Returns one entry per application found in the PDF's form fields:
  //   { appId, dims: { dim_community: 8, ... }, comments: { community: '...' }, problems: ['...'] }
  // Only boxes the judge actually filled appear in dims / comments. A score
  // that isn't a whole number from 0 to 10 is reported in `problems` and left
  // out. Throws if the file isn't a PDF or has no score-sheet fields (e.g. a
  // scan or a "print to PDF" copy, which loses the fillable boxes).
  async function readScores(bytes) {
    var L = await loadLib();
    var doc;
    try { doc = await L.PDFDocument.load(bytes, { ignoreEncryption: true }); }
    catch (_) { throw new Error('That file could not be read as a PDF.'); }
    var fields;
    try { fields = doc.getForm().getFields(); } catch (_) { fields = []; }
    var byApp = {}, order = [];
    fields.forEach(function (f) {
      var m = FIELD_RE.exec(f.getName());
      if (!m || typeof f.getText !== 'function') return;
      var appId = m[1], key = m[2], kind = m[3];
      if (!byApp[appId]) { byApp[appId] = { appId: appId, dims: {}, comments: {}, problems: [] }; order.push(appId); }
      var raw;
      try { raw = f.getText(); } catch (_) { raw = ''; }
      raw = String(raw == null ? '' : raw).trim();
      if (!raw) return;
      var dim = DIMS.filter(function (d) { return d.key === key; })[0];
      if (kind === 'notes') { byApp[appId].comments[key] = raw.slice(0, 1000); return; }
      if (/^\d{1,2}(\.0+)?$/.test(raw) && Number(raw) >= 0 && Number(raw) <= 10) byApp[appId].dims[dim.col] = Number(raw);
      else byApp[appId].problems.push(dim.name + ': "' + raw.slice(0, 20) + '" is not a whole number from 0 to 10');
    });
    if (!order.length) throw new Error('No fillable score boxes were found in that PDF. Upload the PDF you downloaded from this portal and filled in (not a scan or a printed copy).');
    return order.map(function (id) { return byApp[id]; });
  }

  function saveFile(bytes, filename) {
    var blob = new Blob([bytes], { type: 'application/pdf' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
  }

  // Public API. Both resolve once the download has been handed to the browser.
  window.CFCJudgePdf = {
    FIELDS: FIELDS,
    DIMS: DIMS,
    build: build,
    readScores: readScores,
    downloadOne: async function (app, score, judgeName) {
      var by = {};
      if (score) by[app.id] = score;
      saveFile(await build([app], by, judgeName), 'CFC-score-sheet-' + slug(app.proj_title) + '.pdf');
    },
    downloadPacket: async function (apps, scoresByApp, judgeName) {
      saveFile(await build(apps, scoresByApp || {}, judgeName),
        'CFC-judging-packet-' + apps.length + '-application' + (apps.length === 1 ? '' : 's') + '.pdf');
    },
  };
})();
