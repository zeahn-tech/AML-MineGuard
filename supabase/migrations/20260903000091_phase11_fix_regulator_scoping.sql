-- ============================================================================
-- MINEGUARD LIBERIA — Phase 11 fix 1: regulator scoping corrections
--
-- Two defects found during Phase 11 probe design review (2026-09-03):
--
-- 1. DEAD POLICIES: workers_select_regulator and
--    organization_members_select_regulator evaluated
--    auth_user_has_permission() against the TARGET org, where a regulator
--    is (by design) never a member. Both policies could never match, so an
--    authorized regulator could never read the worker registry or org
--    membership even when a grant + the required permission existed.
--    Fix: evaluate the permission against the caller's REGULATOR org
--    (resolved from the active grant), mirroring the
--    audit_log_select_regulator pattern from 20260903000090.
--
-- 2. BOOTSTRAP GUARD: bootstrap_first_regulator_admin() allowed the same
--    authenticated user to claim regulator orgs repeatedly (once per
--    claimable org) and allowed users who already hold any active org
--    membership to claim a regulator org. Onboarding is meant to be a
--    one-shot claim for brand-new users. Fix: deny callers who already
--    hold ANY active organization membership.
--
-- Non-destructive: policy swaps + function re-creation only. Existing
-- org-role matrices (Phases 06–09) untouched.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. workers_select_regulator — permission now evaluated at the regulator org
-- ---------------------------------------------------------------------------
drop policy if exists workers_select_regulator on public.workers;
create policy workers_select_regulator on public.workers
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(workers.organization_id, workers.site_id)
        and public.auth_user_has_permission(
            (select g.regulator_org_id
             from public.current_user_active_government_grants() g
             where g.target_org_id = workers.organization_id
             limit 1),
            'workers.view')
    );

comment on policy workers_select_regulator on public.workers is
    'Phase 11: regulators read the target-org worker registry only within an active grant scope AND while holding workers.view at their own regulator org (least privilege preserved; evaluated against the regulator org, not the target org).';

-- ---------------------------------------------------------------------------
-- 2. organization_members_select_regulator — permission at the regulator org
-- ---------------------------------------------------------------------------
drop policy if exists organization_members_select_regulator on public.organization_members;
create policy organization_members_select_regulator on public.organization_members
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(organization_members.organization_id, null)
        and public.auth_user_has_permission(
            (select g.regulator_org_id
             from public.current_user_active_government_grants() g
             where g.target_org_id = organization_members.organization_id
             limit 1),
            'users.view')
    );

comment on policy organization_members_select_regulator on public.organization_members is
    'Phase 11: regulators read target-org membership rows only within an active org-wide grant scope AND while holding users.view at their own regulator org (evaluated against the regulator org, not the target org).';

-- ---------------------------------------------------------------------------
-- 3. bootstrap_first_regulator_admin — one-shot per user
-- ---------------------------------------------------------------------------
create or replace function public.bootstrap_first_regulator_admin()
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org_id uuid;
begin
    if auth.uid() is null then
        raise exception 'authenticated regulator onboarding requires a session';
    end if;

    -- Onboarding is one-shot per user: any active org membership (any org,
    -- any role) makes the caller ineligible. Bootstrap exists to let a
    -- brand-new government user claim the first open regulator org; users
    -- with existing memberships are onboarded through the normal
    -- org_add_member / invite / grant-management paths instead.
    if exists (
        select 1 from public.organization_members
        where user_id = auth.uid()
          and status = 'active'
    ) then
        raise exception 'P0001: caller already holds an active organization membership; regulator onboarding is only for users with no existing membership';
    end if;

    -- Only regulator orgs are claimable here (not mining_company / contractor / platform).
    select id into v_org_id
    from public.organizations
    where org_type = 'regulator'
      and status = 'active'
      and not exists (
          select 1 from public.organization_members
          where organization_id = organizations.id
            and status = 'active'
      )
    order by created_at asc
    limit 1 for update skip locked;

    if v_org_id is null then
        raise exception 'P0001: no claimable regulator organization available';
    end if;

    insert into public.organization_members
        (organization_id, user_id, role, status, created_by)
    values
        (v_org_id, auth.uid(), 'national_regulatory_admin', 'active', auth.uid())
    on conflict (organization_id, user_id) do nothing;

    return v_org_id;
end;
$$;

comment on function public.bootstrap_first_regulator_admin() is
    'Phase 11: a brand-new user (no active org membership anywhere) claims the first claimable regulator org as national_regulatory_admin. One-shot per user; only regulator orgs are claimable; mining/contractor/platform orgs are excluded.';

commit;
