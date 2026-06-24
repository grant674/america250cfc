-- ============================================================================
-- America250 CFC — Supabase security model (source-of-truth reference)
-- ----------------------------------------------------------------------------
-- The database security (RLS policies, column grants, triggers, the
-- SECURITY DEFINER helper, the cron purge) lives in Supabase. This file
-- captures it so it is version-controlled, reviewable, and reproducible.
--
-- It reflects the LIVE state as of 2026-06-16. It is intended as documentation
-- + a re-create script; review before running against a fresh DB. The base
-- tables (applications, scores, judges, inbound_emails, outbound_replies,
-- audit_log, application_attachments) predate this work — only their SECURITY
-- objects are captured here, plus the two tables added (notify_signups,
-- application_drafts).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Tables added for features (#4 notify-me, #8 save-and-resume)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.notify_signups (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email      text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  source     text,
  user_agent text
);
CREATE UNIQUE INDEX IF NOT EXISTS notify_signups_email_uniq ON public.notify_signups (lower(email));

CREATE TABLE IF NOT EXISTS public.application_drafts (
  token      text PRIMARY KEY,
  email      text,
  data       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '60 days')
);

-- Email unsubscribe / suppression list. Written by the `unsubscribe` function
-- (one-click + footer link, token-signed with NN_AUTH_SECRET). Program-update /
-- marketing sends must check this before sending; transactional notices
-- (submission confirmation, finalist/winner outcome) send regardless but carry
-- the unsubscribe link + List-Unsubscribe headers.
CREATE TABLE IF NOT EXISTS public.email_suppressions (
  email      text PRIMARY KEY,
  source     text,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Row Level Security: enabled on all app tables.
-- Tables with NO policy below (notify_signups, application_drafts,
-- email_suppressions, audit_log, inbound_emails, outbound_replies) are therefore
-- service-role-only — reachable only through Netlify functions that use the
-- service-role key.
-- ---------------------------------------------------------------------------
ALTER TABLE public.applications           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.application_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scores                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.judges                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_log              ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inbound_emails         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.outbound_replies       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notify_signups         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.application_drafts     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_suppressions     ENABLE ROW LEVEL SECURITY;
-- Defense in depth: no anon/authenticated grants on the suppression list.
REVOKE ALL ON public.email_suppressions FROM anon, authenticated;

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER helper — lets RLS policies confirm an application exists
-- WITHOUT granting anon SELECT on applications. (An inline EXISTS subquery in a
-- policy runs as the calling role; anon can't read applications, so it would
-- always be false and block legit uploads. SECURITY DEFINER bypasses that.)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.application_exists(app_id text)
  RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO 'public'
AS $$ SELECT EXISTS (SELECT 1 FROM public.applications a WHERE a.id::text = app_id); $$;
GRANT EXECUTE ON FUNCTION public.application_exists(text) TO anon, authenticated;

-- ---------------------------------------------------------------------------
-- applications — INSERT is service-role only (anon INSERT policy was REVOKED;
-- the public form posts through the Turnstile-gated submit-application function).
-- A BEFORE INSERT trigger forces server-controlled columns for non-service inserts.
-- Judges (authenticated) may SELECT only in-judging rows of ACTIVE judges, and
-- only NON-IDENTITY columns (blind review) — enforced by column grants below.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.enforce_application_intake()
  RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'public'
AS $$
BEGIN
  IF coalesce(auth.role(), 'anon') <> 'service_role' THEN
    NEW.status := 'submitted';
    NEW.ai_screening_result := NULL;
    NEW.ai_screening_reasons := NULL;
    NEW.ai_screening_at := NULL;
    NEW.created_at := now();
    NEW.updated_at := now();
  END IF;
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS trg_enforce_application_intake ON public.applications;
CREATE TRIGGER trg_enforce_application_intake BEFORE INSERT ON public.applications
  FOR EACH ROW EXECUTE FUNCTION public.enforce_application_intake();

-- Audit trail: log every application status change to audit_log.
CREATE OR REPLACE FUNCTION public.log_application_status_change()
  RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'public'
AS $$
BEGIN
  IF (TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status) THEN
    INSERT INTO public.audit_log (actor, action, target_table, target_id, before_data, after_data)
    VALUES (
      CASE WHEN coalesce(auth.role(), '') = 'service_role' THEN 'admin' ELSE coalesce(auth.role(), 'system') END,
      'status_change', 'applications', NEW.id,
      jsonb_build_object('status', OLD.status), jsonb_build_object('status', NEW.status));
  END IF;
  RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS trg_log_application_status ON public.applications;
CREATE TRIGGER trg_log_application_status AFTER UPDATE ON public.applications
  FOR EACH ROW EXECUTE FUNCTION public.log_application_status_change();
-- NOTE: also present (pre-existing): trigger "AI eligibility screening" (AFTER
-- INSERT → screen-application webhook) and "set_applications_updated_at" (BEFORE UPDATE).

-- Blind review: revoke blanket table SELECT, grant only non-identity columns to judges.
-- Withheld from authenticated: lead_name, lead_email, org_name, org_url,
-- AND ai_screening_result/reasons/at (so the AI verdict can't bias a judge).
-- (lead_phone was removed from the schema entirely — see migration note at end.)
REVOKE SELECT ON public.applications FROM anon;
REVOKE SELECT ON public.applications FROM authenticated;
GRANT SELECT (
  id, created_at, updated_at, status, lead_role, org_type, org_has_entity, team_desc,
  proj_title, proj_summary, proj_category, proj_phase, proj_city, proj_state, proj_communities,
  proj_budget_total, proj_budget_raised, proj_use_of_funds, proj_video_url,
  impact_community, impact_innovation, impact_feasibility, impact_sustainability, impact_founder_team,
  elig_age, elig_audience, elig_phase, elig_scope, elig_coi
) ON public.applications TO authenticated;

DROP POLICY IF EXISTS applications_judge_select ON public.applications;
CREATE POLICY applications_judge_select ON public.applications FOR SELECT TO authenticated
  USING (
    status = ANY (ARRAY['approved','in_judging','finalist','winner'])
    AND EXISTS (SELECT 1 FROM public.judges j WHERE j.id = auth.uid() AND j.active = true)
  );

-- ---------------------------------------------------------------------------
-- application_attachments — anon may INSERT metadata only for a real application
-- (ties uploads to Turnstile-verified submissions). No anon SELECT.
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS anon_insert_attachments ON public.application_attachments;
CREATE POLICY anon_insert_attachments ON public.application_attachments FOR INSERT TO anon, authenticated
  WITH CHECK (public.application_exists(application_id::text));

-- ---------------------------------------------------------------------------
-- scores — a judge may read/insert/update only their OWN scores, only while an
-- ACTIVE judge, and may only edit DRAFT rows. judge_id is pinned to auth.uid().
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS scores_self_insert ON public.scores;
CREATE POLICY scores_self_insert ON public.scores FOR INSERT TO authenticated
  WITH CHECK (judge_id = auth.uid() AND EXISTS (SELECT 1 FROM public.judges j WHERE j.id = auth.uid() AND j.active = true));
DROP POLICY IF EXISTS scores_self_select ON public.scores;
CREATE POLICY scores_self_select ON public.scores FOR SELECT TO authenticated
  USING (judge_id = auth.uid() AND EXISTS (SELECT 1 FROM public.judges j WHERE j.id = auth.uid() AND j.active = true));
DROP POLICY IF EXISTS scores_self_update ON public.scores;
CREATE POLICY scores_self_update ON public.scores FOR UPDATE TO authenticated
  USING (judge_id = auth.uid() AND status = 'draft' AND EXISTS (SELECT 1 FROM public.judges j WHERE j.id = auth.uid() AND j.active = true))
  WITH CHECK (judge_id = auth.uid());

-- ---------------------------------------------------------------------------
-- judges — a judge may read only their own row.
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS judges_self_select ON public.judges;
CREATE POLICY judges_self_select ON public.judges FOR SELECT TO authenticated
  USING (id = auth.uid());

-- ---------------------------------------------------------------------------
-- storage.objects — anon may upload to the application-attachments bucket ONLY
-- under a folder named for a real application id. Bucket is private and capped
-- to 10 MB + application/pdf, image/png, image/jpeg, video/mp4.
-- ---------------------------------------------------------------------------
DROP POLICY IF EXISTS "upload_attachments_for_real_apps" ON storage.objects;
CREATE POLICY "upload_attachments_for_real_apps" ON storage.objects FOR INSERT TO anon, authenticated
  WITH CHECK (bucket_id = 'application-attachments' AND public.application_exists((storage.foldername(name))[1]));

-- ---------------------------------------------------------------------------
-- Scheduled cleanup (pg_cron): purge expired save-and-resume drafts daily.
-- ---------------------------------------------------------------------------
-- CREATE EXTENSION IF NOT EXISTS pg_cron;
-- SELECT cron.schedule('purge-expired-drafts', '0 3 * * *',
--   $$DELETE FROM public.application_drafts WHERE expires_at < now()$$);

-- ---------------------------------------------------------------------------
-- Migration 2026-06-16: phone number removed as a collected data field.
-- The form input, function whitelists, admin drawer, and AI prompt no longer
-- reference it; the column was dropped from the schema.
-- ---------------------------------------------------------------------------
-- ALTER TABLE public.applications DROP COLUMN IF EXISTS lead_phone;
