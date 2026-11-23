# America250 Community Futures Challenge — america250cfc.org

Source of truth for the **America250 Community Futures Challenge** site (a PMI U.S.
grant program, operated by Pacheco Ventures). Static pages + Netlify Functions +
an edge auth gate, backed by Supabase, Resend, and Anthropic.

> Recovered into version control 2026-06. Deployed manually (no CI). This repo is
> the durable source of truth — keep it in sync with production.

## Stack & layout
- **Static site** — plain HTML/CSS/JS at the repo root (`index.html`, `apply/`,
  `judge/`, `admin/`, `brand/`, `press/`, `contact/`, `privacy/`, `terms/`, `assets/`).
- **Netlify Functions** — `netlify/functions/*.mjs` (Supabase + Resend + Anthropic).
- **Edge function** — `netlify/edge-functions/auth.ts`: two-tier password gate
  (site + admin), canonical-host redirect, blocks serving of source paths.
- **Backend** — Supabase (Postgres + Storage). DB security model is documented in
  [`db/security-model.sql`](db/security-model.sql) (RLS, grants, triggers, cron).
- **Config** — `netlify.toml` (publish dir, functions, security headers/CSP).

## How it works
- Public form (`/apply/`) → **Cloudflare Turnstile** verified by `submit-application`
  → inserted via service role → an `AFTER INSERT` trigger runs AI screening
  (`screen-application` → Claude) → confirmation email via Resend.
- Judges sign in at `/judge/` with email + password (set or reset by the admin,
  changeable by the judge) or an emailed magic link, score blind (applicant identity is
  withheld at the DB level), data gated by Supabase RLS. A judge sees only the
  applications assigned to them.
- Judging workflow (admin): tick the 25 finalists in the applications table →
  **Send to judging** → **Invite judge** for each judge → in **Judging →
  Assignments** tick which judge scores which finalist (or *Assign all to every
  judge*) → **Save assignments**. Stored in `judge_assignments`
  (`admin-assignments` function). The link beside each tick opens a score
  editor for entering or correcting a judge's scores on their behalf
  (`admin-score` function, audit-logged). Schema + RLS in
  [`db/migrations/2026-11-21-judge-assignments.sql`](db/migrations/2026-11-21-judge-assignments.sql).
- Staff `/admin/` dashboard (separate password) lists applications, scores, inbox,
  audit log; can re-screen, bulk-update status, notify finalists/winners.

## Deploying
Manual deploy via the Netlify CLI (authenticated as the site owner):
```bash
netlify deploy --site <SITE_ID> --dir . --functions netlify/functions   # draft → verify on the draft URL
netlify deploy --site <SITE_ID> --dir . --functions netlify/functions --prod
```
The CLI bundles the functions AND the edge function. Bump the `?v=N` query on any
changed CSS/JS so browsers refetch. DB/RLS changes are applied in Supabase (see
`db/security-model.sql`) — they are not part of the Netlify deploy.

## Secrets (Netlify env vars — never commit)
`SITE_PASSWORD`, `ADMIN_PASSWORD`, `NN_AUTH_SECRET`, `SUPABASE_SERVICE_ROLE_KEY`,
`SUPABASE_ANON_KEY` (public by design), `ANTHROPIC_API_KEY`, `RESEND_API_KEY`,
`RESEND_INBOUND_SIGNING_SECRET`, `SCREENING_WEBHOOK_SECRET`, `TURNSTILE_SECRET_KEY`.
Tunable: `SCREENING_HOURLY_CAP` (default 200).
