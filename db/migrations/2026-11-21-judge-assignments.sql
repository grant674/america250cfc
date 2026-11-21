-- ============================================================================
-- Migration 2026-11-21: per-judge assignments.
-- ----------------------------------------------------------------------------
-- Until now every active judge could read (and score) every application in a
-- scoring-phase status. This adds an explicit assignment table, managed from
-- the admin dashboard ("Judging" > "Assignments"), and tightens RLS so a judge
-- can read and score ONLY the applications assigned to them.
--
-- Safe to re-run. Apply in Supabase BEFORE (or together with) deploying the
-- site: the admin dashboard detects a missing table and says so, and the
-- judge portal simply shows an empty queue until assignments exist.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.judge_assignments (
  judge_id       uuid NOT NULL REFERENCES public.judges(id)       ON DELETE CASCADE,
  application_id uuid NOT NULL REFERENCES public.applications(id) ON DELETE CASCADE,
  assigned_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (judge_id, application_id)
);
CREATE INDEX IF NOT EXISTS judge_assignments_application_idx
  ON public.judge_assignments (application_id);

ALTER TABLE public.judge_assignments ENABLE ROW LEVEL SECURITY;

-- Writes are service-role only (admin-assignments function). A judge may read
-- their own assignment rows, which is what lets the policies below see them.
REVOKE ALL ON public.judge_assignments FROM anon, authenticated;
GRANT SELECT ON public.judge_assignments TO authenticated;

DROP POLICY IF EXISTS judge_assignments_self_select ON public.judge_assignments;
CREATE POLICY judge_assignments_self_select ON public.judge_assignments FOR SELECT TO authenticated
  USING (judge_id = auth.uid());

-- applications: scoring-phase status + ACTIVE judge + ASSIGNED to this judge.
DROP POLICY IF EXISTS applications_judge_select ON public.applications;
CREATE POLICY applications_judge_select ON public.applications FOR SELECT TO authenticated
  USING (
    status = ANY (ARRAY['approved','in_judging','finalist','winner'])
    AND EXISTS (SELECT 1 FROM public.judges j WHERE j.id = auth.uid() AND j.active = true)
    AND EXISTS (
      SELECT 1 FROM public.judge_assignments ja
      WHERE ja.judge_id = auth.uid() AND ja.application_id = applications.id
    )
  );

-- scores: a judge may only START a score for an application assigned to them.
-- (Select/update policies are unchanged: own rows only, drafts only.)
DROP POLICY IF EXISTS scores_self_insert ON public.scores;
CREATE POLICY scores_self_insert ON public.scores FOR INSERT TO authenticated
  WITH CHECK (
    judge_id = auth.uid()
    AND EXISTS (SELECT 1 FROM public.judges j WHERE j.id = auth.uid() AND j.active = true)
    AND EXISTS (
      SELECT 1 FROM public.judge_assignments ja
      WHERE ja.judge_id = auth.uid() AND ja.application_id = scores.application_id
    )
  );
