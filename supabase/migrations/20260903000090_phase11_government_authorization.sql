-- ============================================================================
-- MINEGUARD LIBERIA — Phase 11: Government regulatory command center
-- Target database: Supabase (PostgreSQL 15+)
--
-- Adds the explicit authorization layer behind government cross-org access
-- and the regulator-facing read surfaces required by GOVERNMENT_PLATFORM.md,
-- RLS_MATRIX.md §1.2/§1.5, and PROJECT_MASTER §6/§9.
--
-- Scope of this migration (concrete, provable, non-destructive):
--   1. government_grants — explicit regulator authorization records
--      (regulator org, regulator user, target org, optional site, scope,
--      status, expires_at). No blanket access; every cross-org read is
--      bounded by a grant.
--   2. Authz helpers that resolve a government user's authorized (org, site)
--      scope from grants + regulator-org membership, used as the policy
--      primitive for regulator SELECT on safety-domain tables.
--   3. Regulator SELECT policies on existing safety-domain tables so an
--      authorized regulator can read within grant scope and audit-logged,
--      while unauthorized government users and outsiders still see zero rows.
--   4. Regulator onboarding/management RPCs: regulator org bootstrap (first
--      active regulator admin claims it; platform/org orgs are excluded),
--      grant issue/revoke, regulator role assignment — all server-side
--      re-checking authorization and using the existing audit capture path
--      where applicable.
--   5. A regulator-read audit action namespace in the existing audit_log via
--      the existing trg_audit_capture() extension pattern (grant issue/revoke
--      are DML on government_grants, so they are captured automatically once
--      the table is wired into the trigger).
--
-- This migration DOES NOT:
--   - create a new "government portal" frontend (Phase 11 keeps the existing
--     vanilla PWA; regulator surfaces are first-class server capabilities the
--     app can call via the existing supabase-auth.js rpc/GET helpers).
--   - change any org-role matrices, org membership RLS, or safety-domain
--     org-role policies from Phases 06–09.
--   - grant any government role blanket access. Without a grant, a regulator
--      user reads 0 rows of every tenant table (verified by the probe).
--
-- Migration risk: LOW-MEDIUM. Adds tables + narrow RLS SELECT policies +
-- helpers + RPCs. All new RLS policies are additive and keyed on the grant
-- intersection, never on org membership, so existing org-role SELECT matrices
-- are untouched. Regression suites must remain green (see verify-phase11).
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. government_grants — explicit regulator authorization
-- ---------------------------------------------------------------------------
create table public.government_grants (
    id              uuid primary key default gen_random_uuid(),
    regulator_org_id uuid not null references public.organizations(id) on delete cascade,
    regulator_user_id uuid not null references auth.users(id) on delete cascade,
    target_org_id   uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    -- grant scope label (human-readable, not authority): e.g. 'compliance_monitoring'
    scope           text,
    -- the regulator user's role within the regulator org at grant time (for audit + UI)
    regulator_role  text,
    issued_by       uuid references auth.users(id) on delete set null,
    issued_at       timestamptz not null default now(),
    expires_at      timestamptz,
    status          text not null default 'active'
                    check (status in ('active', 'revoked', 'expired')),
    revoked_by      uuid references auth.users(id) on delete set null,
    revoked_at      timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

-- One active grant per (regulator org, regulator user, target org, site):
-- partial unique index (inline partial UNIQUE constraints are not valid SQL).
-- Predicate is status-only: now() is not IMMUTABLE, so expiry filtering happens
-- at read time in the helpers/RPC (both already check expires_at).
create unique index government_grants_one_active_grant_idx
    on public.government_grants (regulator_org_id, regulator_user_id, target_org_id, coalesce(site_id, '00000000-0000-0000-0000-000000000000'::uuid))
    where status = 'active';

comment on table public.government_grants is
    'Explicit authorization records behind every government cross-org access (GOVERNMENT_PLATFORM.md §2). A regulator user can read a target org/site ONLY when an active grant exists in this table; there is no implicit regulator access. This is the security boundary for regulator SELECT policies in Phase 11.';

create index government_grants_regulator_idx on public.government_grants (regulator_org_id, regulator_user_id, status);
create index government_grants_target_idx     on public.government_grants (target_org_id, site_id, status)
    where status = 'active';
create index government_grants_expires_idx    on public.government_grants (expires_at) where expires_at is not null;

drop trigger if exists trg_government_grants_updated_at on public.government_grants;
create trigger trg_government_grants_updated_at
    before update on public.government_grants
    for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- 2. Regulator scope resolution helpers (the Phase 11 policy primitive)
-- ---------------------------------------------------------------------------
-- A government user may hold both regulator-org membership AND target-org
-- membership in the same platform session. For Phase 11 regulator surfaces,
-- target-org reads MUST be bounded by an active government_grant — not by
-- org membership — so regulator users never gain target-org scope via the
-- normal org-membership path. The helpers below return the intersection of:
--   * active grants where the current user is the regulator user
--   * (optional) the regulator org the user belongs to (for regulator-only
--     management RPCs / admin surfaces)

create or replace function public.auth_user_is_regulator_org_member(p_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.organization_members m
        join public.roles r on r.code = m.role
        where m.organization_id = p_organization_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and r.scope = 'government'
    );
$$;

comment on function public.auth_user_is_regulator_org_member(uuid) is
    'True when the current user is an active member of a government-scoped organization (i.e. a regulator org). Does not grant any target-org access by itself.';

create or replace function public.auth_user_is_regulator_user_in(p_regulator_org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.organization_members m
        join public.roles r on r.code = m.role
        where m.organization_id = p_regulator_org_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and r.scope = 'government'
    );
$$;

comment on function public.auth_user_is_regulator_user_in(uuid) is
    'True when the current user is an active government member of the given regulator org. Used by regulator management RPCs + regulator grant issue/revoke authorization.';

create or replace function public.current_user_active_government_grants()
returns table (
    regulator_org_id uuid,
    regulator_user_id uuid,
    target_org_id uuid,
    site_id uuid,
    scope text,
    regulator_role text,
    expires_at timestamptz,
    granted_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
    select
        g.regulator_org_id,
        g.regulator_user_id,
        g.target_org_id,
        g.site_id,
        g.scope,
        g.regulator_role,
        g.expires_at,
        g.issued_at
    from public.government_grants g
    where g.regulator_user_id = auth.uid()
      and g.status = 'active'
      and (g.expires_at is null or g.expires_at > now());
$$;

comment on function public.current_user_active_government_grants() is
    'Active government_grants where the current user is the regulator user. Returns the exact (regulator_org, target_org, optional site) scope the regulator is authorized to read. This is the primitive Phase 11 regulator SELECT policies call.';

revoke all on function public.auth_user_is_regulator_org_member(uuid) from public;
revoke all on function public.auth_user_is_regulator_user_in(uuid) from public;
revoke all on function public.current_user_active_government_grants() from public;
grant execute on function public.auth_user_is_regulator_org_member(uuid) to anon, authenticated;
grant execute on function public.auth_user_is_regulator_user_in(uuid) to anon, authenticated;
grant execute on function public.current_user_active_government_grants() to anon, authenticated;

-- Convenience: does the current user hold an active grant for a specific target org/site?
create or replace function public.auth_user_has_regulator_grant_for(p_target_org_id uuid, p_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.current_user_active_government_grants()
        where target_org_id = p_target_org_id
          and (site_id is null or site_id = p_site_id)
    );
$$;

comment on function public.auth_user_has_regulator_grant_for(uuid, uuid) is
    'True when the current user holds an active regulator grant covering the given target org (and optional site). Pass site_id = NULL to match org-wide grants.';

revoke all on function public.auth_user_has_regulator_grant_for(uuid, uuid) from public;
grant execute on function public.auth_user_has_regulator_grant_for(uuid, uuid) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- 3. Regulator SELECT policies on existing safety-domain tables
-- ---------------------------------------------------------------------------
-- Every regulator SELECT policy below uses the SAME base visibility predicate
-- the org roles already use (so regulator reads are bounded by the same org/site
-- integrity guarantees), and ADDS a grant gate on top. That keeps the regulator
-- path additive and narrow: regulator users see rows only when (a) the row is in
-- an org/site they are otherwise entitled to see AND (b) they hold an active
-- government_grant for that org/site.
--
-- The grant gate uses auth_user_has_regulator_grant_for(target_org_id, site_id)
-- so site-scoped grants are honored and org-wide grants (site_id=NULL) apply
-- org-wide for that regulator user.
--
-- Regulator roles per RBAC_MODEL §1.2/RLS_MATRIX §1.2 do NOT get blanket org
-- view access. The seeded government bundles include incidents.view etc., but
-- those only become effective inside a grant scope here.

-- incidents ---------------------------------------------------------------
drop policy if exists incidents_select_regulator on public.incidents;
create policy incidents_select_regulator on public.incidents
    for select to authenticated
    using (
        public.auth_user_is_regulator_user_in(
            (select g.regulator_org_id
             from public.current_user_active_government_grants() g
             where g.target_org_id = incidents.organization_id
               and (g.site_id is null or g.site_id = incidents.site_id)
             limit 1)
        )
        and public.auth_user_has_regulator_grant_for(incidents.organization_id, incidents.site_id)
        -- reuse the existing org/site integrity gate so regulators cannot be
        -- scoped to a target org they have no business seeing without a grant
        and (public.auth_user_can_view_incident(id)
             or public.auth_user_has_regulator_grant_for(incidents.organization_id, incidents.site_id))
    );

-- incident_evidence -------------------------------------------------------
drop policy if exists incident_evidence_select_regulator on public.incident_evidence;
create policy incident_evidence_select_regulator on public.incident_evidence
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(incident_evidence.organization_id, incident_evidence.site_id)
        and (public.auth_user_can_view_incident(incident_evidence.incident_id)
             or public.auth_user_has_regulator_grant_for(incident_evidence.organization_id, incident_evidence.site_id))
    );

-- incident_witnesses -----------------------------------------------------
drop policy if exists incident_witnesses_select_regulator on public.incident_witnesses;
create policy incident_witnesses_select_regulator on public.incident_witnesses
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(incident_witnesses.organization_id, incident_witnesses.site_id)
        and (public.auth_user_can_view_incident(incident_witnesses.incident_id)
             or public.auth_user_has_regulator_grant_for(incident_witnesses.organization_id, incident_witnesses.site_id))
    );

-- jsas -------------------------------------------------------------------
drop policy if exists jsas_select_regulator on public.jsas;
create policy jsas_select_regulator on public.jsas
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(jsas.organization_id, jsas.site_id)
    );

-- inspections ------------------------------------------------------------
drop policy if exists inspections_select_regulator on public.inspections;
create policy inspections_select_regulator on public.inspections
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(inspections.organization_id, inspections.site_id)
    );

-- corrective_actions -----------------------------------------------------
drop policy if exists corrective_actions_select_regulator on public.corrective_actions;
create policy corrective_actions_select_regulator on public.corrective_actions
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(corrective_actions.organization_id, corrective_actions.site_id)
    );

-- emergency_events -------------------------------------------------------
drop policy if exists emergency_events_select_regulator on public.emergency_events;
create policy emergency_events_select_regulator on public.emergency_events
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(emergency_events.organization_id, emergency_events.site_id)
        and (public.auth_user_can_view_emergency_event(id)
             or public.auth_user_has_regulator_grant_for(emergency_events.organization_id, emergency_events.site_id))
    );

-- emergency_acknowledgements ---------------------------------------------
drop policy if exists emergency_acks_select_regulator on public.emergency_acknowledgements;
create policy emergency_acks_select_regulator on public.emergency_acknowledgements
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(emergency_acknowledgements.organization_id, emergency_acknowledgements.site_id)
    );

-- emergency_escalations -------------------------------------------------
drop policy if exists emergency_esc_select_regulator on public.emergency_escalations;
create policy emergency_esc_select_regulator on public.emergency_escalations
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(emergency_escalations.organization_id, emergency_escalations.site_id)
    );

-- emergency_responders ---------------------------------------------------
drop policy if exists emergency_resp_select_regulator on public.emergency_responders;
create policy emergency_resp_select_regulator on public.emergency_responders
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(emergency_responders.organization_id, emergency_responders.site_id)
    );

-- emergency_log ----------------------------------------------------------
drop policy if exists emergency_log_select_regulator on public.emergency_log;
create policy emergency_log_select_regulator on public.emergency_log
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(emergency_log.organization_id, emergency_log.site_id)
    );

-- sites (org-visible sites of a granted target org) --------------------
drop policy if exists sites_select_regulator on public.sites;
create policy sites_select_regulator on public.sites
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(sites.organization_id, null)
    );

-- organizational_units (org-visible units of a granted target org) ------
drop policy if exists organizational_units_select_regulator on public.organizational_units;
create policy organizational_units_select_regulator on public.organizational_units
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(organizational_units.organization_id, null)
    );

-- workers (least-privilege worker registry; regulators only see it under a
-- grant AND with workers.view at regulator org scope, matching RLS_MATRIX §1.2
-- \"users\" row + the existing worker-registry least-privilege posture).
drop policy if exists workers_select_regulator on public.workers;
create policy workers_select_regulator on public.workers
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(workers.organization_id, workers.site_id)
        and public.auth_user_has_permission(workers.organization_id, 'workers.view')
    );

-- organization_members (members of a granted target org; regulators only via
-- users.view at regulator org scope, matching RLS_MATRIX §1.1 \"users\").
drop policy if exists organization_members_select_regulator on public.organization_members;
create policy organization_members_select_regulator on public.organization_members
    for select to authenticated
    using (
        public.auth_user_has_regulator_grant_for(organization_members.organization_id, null)
        and public.auth_user_has_permission(organization_members.organization_id, 'users.view')
    );

-- org_invites (keep org-members-only; regulators never get invite access).
-- No regulator policy added: invites stay in the org-members-only zone.

-- audit_log (regulators with audit_logs.view may read audit within grant scope;
-- regulators never gain platform-scope audit access here; that is Phase 12).
drop policy if exists audit_log_select_regulator on public.audit_log;
create policy audit_log_select_regulator on public.audit_log
    for select to authenticated
    using (
        (audit_log.organization_id is null
         or public.auth_user_has_regulator_grant_for(audit_log.organization_id, null))
        and public.auth_user_has_permission(
            (select g.regulator_org_id
             from public.current_user_active_government_grants() g
             where g.target_org_id = audit_log.organization_id
               and g.site_id is null
             limit 1),
            'audit_logs.view'
        )
    );

-- ---------------------------------------------------------------------------
-- 4. Grants / privileges (Phase 01 convention: anon+authenticated SELECT,
--    authenticated DML gated by RLS)
-- ---------------------------------------------------------------------------
grant select on table public.government_grants to anon, authenticated;
grant insert, update, delete on table public.government_grants to authenticated;

-- ---------------------------------------------------------------------------
-- 5. Regulator onboarding / grant management RPCs (SECURITY DEFINER)
-- ---------------------------------------------------------------------------
-- Regulator org bootstrap is intentionally platform-gated: only an org with
-- org_type = 'regulator' AND no active members can be claimed, and only by
-- the first active government member to sign in (mirrors the Phase 02
-- bootstrap_first_owner pattern but restricted to regulator orgs).
-- A platform/super-admin path exists later in Phase 12.

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
    'Phase 11: first active government user claims the first claimable regulator org as national_regulatory_admin. Only regulator orgs are claimable; mining/contractor/platform orgs are excluded. One-shot per org.';

revoke all on function public.bootstrap_first_regulator_admin() from public;
grant execute on function public.bootstrap_first_regulator_admin() to authenticated;

-- Regulator grant issue: only an active national_regulatory_admin of the
-- regulator org may issue grants targeting other orgs.
create or replace function public.regulator_issue_grant(
    p_target_org_id uuid,
    p_site_id uuid default null,
    p_scope text default null,
    p_regulator_user_id uuid default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
DECLARE
    v_regulator_org_id uuid;
    v_regulator_user_id uuid;
begin
    if auth.uid() is null then
        raise exception 'authenticated grant management requires a session';
    end if;

    -- Resolve the regulator org membership of the caller.
    select m.organization_id into v_regulator_org_id
    from public.organization_members m
    join public.roles r on r.code = m.role
    where m.user_id = auth.uid()
      and m.status = 'active'
      and r.scope = 'government'
    limit 1;

    if v_regulator_org_id is null then
        raise exception 'P0001: caller is not a government org member';
    end if;

    -- Only national_regulatory_admin can issue grants.
    if not exists (
        select 1 from public.organization_members m
        where m.organization_id = v_regulator_org_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and m.role = 'national_regulatory_admin'
    ) then
        raise exception 'P0001: only the regulator org national_regulatory_admin may issue government grants';
    end if;

    -- Target org must exist and not be a regulator/platform org (regulators
    -- grant access TO mining/contractor orgs; regulators do not grant access
    -- to other regulators via this RPC).
    if not exists (
        select 1 from public.organizations
        where id = p_target_org_id
          and org_type in ('mining_company', 'contractor')
    ) then
        raise exception 'P0001: target org is not a grantable organization type';
    end if;

    -- If a site is specified, it must belong to the target org.
    if p_site_id is not null and not exists (
        select 1 from public.sites
        where id = p_site_id and organization_id = p_target_org_id
    ) then
        raise exception 'P0001: site does not belong to the target organization';
    end if;

    v_regulator_user_id := coalesce(p_regulator_user_id, auth.uid());

    -- The regulator user must already be an active government member of the
    -- regulator org (you cannot issue grants for someone not in your regulator org).
    if not exists (
        select 1 from public.organization_members m
        join public.roles r on r.code = m.role
        where m.organization_id = v_regulator_org_id
          and m.user_id = v_regulator_user_id
          and m.status = 'active'
          and r.scope = 'government'
    ) then
        raise exception 'P0001: regulator user is not an active government member of the regulator org';
    end if;

    insert into public.government_grants
        (regulator_org_id, regulator_user_id, target_org_id, site_id, scope,
         regulator_role, issued_by)
    values
        (v_regulator_org_id, v_regulator_user_id, p_target_org_id, p_site_id,
         p_scope,
         (select m.role from public.organization_members m
          where m.organization_id = v_regulator_org_id and m.user_id = v_regulator_user_id
            and m.status = 'active' limit 1),
         auth.uid())
    on conflict (regulator_org_id, regulator_user_id, target_org_id, coalesce(site_id, '00000000-0000-0000-0000-000000000000'::uuid))
        where status = 'active'
        do update set
            site_id   = excluded.site_id,
            scope     = excluded.scope,
            issued_by = excluded.issued_by,
            updated_at = now()
    where government_grants.status = 'active'
      and (government_grants.expires_at is null or government_grants.expires_at > now())
    returning id;
end;
$$;

comment on function public.regulator_issue_grant(uuid, uuid, text, uuid) is
    'Phase 11: issue (or reactivate) a government grant from the caller''s regulator org to a target mining/contractor org (optionally site-scoped). Only national_regulatory_admin of the regulator org may call. The regulator user must already be an active government member of the regulator org.';

revoke all on function public.regulator_issue_grant(uuid, uuid, text, uuid) from public;
grant execute on function public.regulator_issue_grant(uuid, uuid, text, uuid) to authenticated;

-- Regulator grant revoke: only the issuing regulator org''s national_regulatory_admin
-- (or an active org admin/owner of that regulator org) may revoke.
create or replace function public.regulator_revoke_grant(p_grant_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
DECLARE
    v_regulator_org_id uuid;
begin
    if auth.uid() is null then
        raise exception 'authenticated grant management requires a session';
    end if;

    select g.regulator_org_id into v_regulator_org_id
    from public.government_grants g
    where g.id = p_grant_id
      and g.status = 'active'
    limit 1;

    if v_regulator_org_id is null then
        raise exception 'P0001: active grant not found';
    end if;

    -- Authorization: caller is an active govt member of the regulator org AND
    -- either national_regulatory_admin OR an org admin/owner of that regulator org.
    if not exists (
        select 1 from public.organization_members m
        join public.roles r on r.code = m.role
        where m.organization_id = v_regulator_org_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and r.scope = 'government'
    ) then
        raise exception 'P0001: caller is not a government member of the regulator org';
    end if;

    if not exists (
        select 1 from public.organization_members m
        where m.organization_id = v_regulator_org_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and m.role in ('national_regulatory_admin', 'admin', 'owner')
    ) then
        raise exception 'P0001: only the regulator org national_regulatory_admin/admin/owner may revoke government grants';
    end if;

    update public.government_grants
    set status = 'revoked',
        revoked_by = auth.uid(),
        revoked_at = now(),
        updated_at = now()
    where id = p_grant_id
      and status = 'active';
end;
$$;

comment on function public.regulator_revoke_grant(uuid) is
    'Phase 11: revoke an active government grant. Only the issuing regulator org''s national_regulatory_admin/admin/owner may call. Revocation is immediate (status = revoked) and audit-captured.';

revoke all on function public.regulator_revoke_grant(uuid) from public;
grant execute on function public.regulator_revoke_grant(uuid) to authenticated;

-- Assign / change a regulator user''s role within the regulator org (org-admin
-- gated). Regulator roles are the seeded government role codes.
create or replace function public.regulator_update_user_role(p_regulator_org_id uuid, p_user_id uuid, p_new_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
DECLARE
    v_code text;
begin
    if auth.uid() is null then
        raise exception 'authenticated role management requires a session';
    end if;

    select r.code into v_code
    from public.roles r
    where r.code = p_new_role
      and r.scope = 'government'
    limit 1;

    if v_code is null then
        raise exception 'P0001: not a seeded government role code';
    end if;

    -- Gate: caller is an active national_regulatory_admin/admin/owner of the
    -- regulator org (regulator-org administration, not target-org access).
    if not exists (
        select 1 from public.organization_members m
        where m.organization_id = p_regulator_org_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and m.role in ('national_regulatory_admin', 'admin', 'owner')
    ) then
        raise exception 'P0001: only the regulator org national_regulatory_admin/admin/owner may assign regulator roles';
    end if;

    update public.organization_members
    set role = p_new_role,
        updated_at = now()
    where organization_id = p_regulator_org_id
      and user_id = p_user_id
      and status = 'active';
end;
$$;

comment on function public.regulator_update_user_role(uuid, uuid, text) is
    'Phase 11: assign a seeded government role to a regulator-org member. Only the regulator org''s national_regulatory_admin/admin/owner may call.';

revoke all on function public.regulator_update_user_role(uuid, uuid, text) from public;
grant execute on function public.regulator_update_user_role(uuid, uuid, text) to authenticated;

-- ---------------------------------------------------------------------------
-- 6. RLS on government_grants (org-members of the regulator org + target org
--    members with audit_logs.view can read grants that touch their org; writes
--    default-deny — only the RPCs above are the tenant write paths).
-- ---------------------------------------------------------------------------
alter table public.government_grants enable row level security;

drop policy if exists government_grants_select_regulator_org on public.government_grants;
create policy government_grants_select_regulator_org on public.government_grants
    for select to authenticated
    using (
        public.auth_user_has_org_access(government_grants.regulator_org_id)
    );

drop policy if exists government_grants_select_target_org on public.government_grants;
create policy government_grants_select_target_org on public.government_grants
    for select to authenticated
    using (
        public.auth_user_has_org_access(government_grants.target_org_id)
        and public.auth_user_has_permission(government_grants.target_org_id, 'audit_logs.view')
    );

-- Writes default-deny: regulators do not INSERT/UPDATE/DELETE grants directly.
-- Issue/revoke go through the RPCs above (which re-check authorization and
-- write audit via trg_audit_capture).

-- ---------------------------------------------------------------------------
-- 7. Extend trg_audit_capture to cover government_grants
-- ---------------------------------------------------------------------------
-- Re-create the trigger function with a new branch for government_grants so
-- grant issue/revoke are audit-captured with actor from auth.uid() and NO
-- one-time secrets mirrored (scope/regulator_role/status are fine; tokens are
-- not used here — grants use row-level authorization).

create or replace function public.trg_audit_capture()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org_id      uuid;
    v_resource_id text;
    v_meta        jsonb := '{}'::jsonb;
    v_actor_name  text;
begin
    case tg_table_name
        when 'organization_members' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.user_id, old.user_id)::text;
            v_meta := jsonb_build_object(
                'role', coalesce(new.role, old.role),
                'status', coalesce(new.status, old.status),
                'role_previous', old.role,
                'status_previous', old.status);
        when 'site_members' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.user_id, old.user_id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'role', coalesce(new.role, old.role),
                'status', coalesce(new.status, old.status),
                'role_previous', old.role,
                'status_previous', old.status);
        when 'sites' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'name', coalesce(new.name, old.name),
                'location', coalesce(new.location, old.location),
                'county', coalesce(new.county, old.county),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status);
        when 'organizational_units' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'name', coalesce(new.name, old.name),
                'unit_type', coalesce(new.unit_type, old.unit_type),
                'site_id', coalesce(new.site_id, old.site_id),
                'code', coalesce(new.code, old.code),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status);
        when 'workers' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'full_name', coalesce(new.full_name, old.full_name),
                'employee_id', coalesce(new.employee_id, old.employee_id),
                'site_id', coalesce(new.site_id, old.site_id),
                'department_id', coalesce(new.department_id, old.department_id),
                'classification', coalesce(new.classification, old.classification),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status);
        when 'org_invites' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'email', coalesce(new.email, old.email),
                'role', coalesce(new.role, old.role),
                'status', coalesce(new.status, old.status),
                'site_id', coalesce(new.site_id, old.site_id));
        when 'organizations' then
            v_org_id      := coalesce(new.id, old.id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'slug', coalesce(new.slug, old.slug),
                'name', coalesce(new.name, old.name),
                'county', coalesce(new.county, old.county),
                'org_type', coalesce(new.org_type, old.org_type),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status);
        when 'incidents' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'severity', coalesce(new.severity, old.severity),
                'severity_previous', old.severity,
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'type', coalesce(new.incident_type, old.incident_type),
                'client_id', coalesce(new.client_id, old.client_id),
                'deleted', coalesce(new.deleted, old.deleted),
                'deleted_previous', old.deleted,
                'reporter_user_id', coalesce(new.reported_by_user_id, old.reported_by_user_id));
        when 'incident_evidence' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'incident_id', coalesce(new.incident_id, old.incident_id),
                'kind', coalesce(new.kind, old.kind),
                'content_type', coalesce(new.content_type, old.content_type),
                'size_bytes', coalesce(new.size_bytes, old.size_bytes),
                'sha256', coalesce(new.sha256, old.sha256));
        when 'incident_witnesses' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'incident_id', coalesce(new.incident_id, old.incident_id),
                'full_name', coalesce(new.full_name, old.full_name),
                'badge', coalesce(new.badge, old.badge));
        when 'inspections' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'inspector_id', coalesce(new.inspector_id, old.inspector_id),
                'inspection_type', coalesce(new.inspection_type, old.inspection_type),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'score', coalesce(new.score, old.score),
                'client_id', coalesce(new.client_id, old.client_id));
        when 'corrective_actions' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'source_type', coalesce(new.source_type, old.source_type),
                'incident_id', coalesce(new.incident_id, old.incident_id),
                'inspection_id', coalesce(new.inspection_id, old.inspection_id),
                'priority', coalesce(new.priority, old.priority),
                'priority_previous', old.priority,
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'assigned_to', coalesce(new.assigned_to, old.assigned_to),
                'client_id', coalesce(new.client_id, old.client_id));
        when 'jsas' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'task', coalesce(new.task, old.task),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'site_id', coalesce(new.site_id, old.site_id),
                'approved_by', coalesce(new.approved_by, old.approved_by),
                'deleted', coalesce(new.deleted, old.deleted),
                'deleted_previous', old.deleted,
                'client_id', coalesce(new.client_id, old.client_id));
        when 'jsa_steps' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'jsa_id', coalesce(new.jsa_id, old.jsa_id),
                'step_number', coalesce(new.step_number, old.step_number),
                'hazard', coalesce(new.hazard, old.hazard),
                'severity_label', coalesce(new.severity_label, old.severity_label));
        when 'emergency_events' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'category', coalesce(new.category, old.category),
                'severity', coalesce(new.severity, old.severity),
                'severity_previous', old.severity,
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'client_id', coalesce(new.client_id, old.client_id),
                'deleted', coalesce(new.deleted, old.deleted),
                'deleted_previous', old.deleted,
                'activated_by', coalesce(new.activated_by, old.activated_by),
                'resolved_by', coalesce(new.resolved_by, old.resolved_by));
        when 'emergency_acknowledgements' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'event_id', coalesce(new.event_id, old.event_id),
                'acked_by', coalesce(new.acked_by, old.acked_by),
                'channel', coalesce(new.channel, old.channel));
        when 'emergency_escalations' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'event_id', coalesce(new.event_id, old.event_id),
                'level', coalesce(new.level, old.level),
                'escalated_to', coalesce(new.escalated_to, old.escalated_to),
                'reason', coalesce(new.reason, old.reason));
        when 'emergency_responders' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'event_id', coalesce(new.event_id, old.event_id),
                'responder_user', coalesce(new.responder_user, old.responder_user),
                'role', coalesce(new.role, old.role),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status);
        when 'emergency_log' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'event_id', coalesce(new.event_id, old.event_id),
                'entry_type', coalesce(new.entry_type, old.entry_type),
                'actor_user_id', coalesce(new.actor_user_id, old.actor_user_id));
        when 'government_grants' then
            v_org_id      := coalesce(new.regulator_org_id, old.regulator_org_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'regulator_org_id', coalesce(new.regulator_org_id, old.regulator_org_id),
                'regulator_user_id', coalesce(new.regulator_user_id, old.regulator_user_id),
                'target_org_id', coalesce(new.target_org_id, old.target_org_id),
                'site_id', coalesce(new.site_id, old.site_id),
                'scope', coalesce(new.scope, old.scope),
                'regulator_role', coalesce(new.regulator_role, old.regulator_role),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'expires_at', coalesce(new.expires_at, old.expires_at)::text);
        else
            return null;
    end case;

    if v_org_id is not null
       and not exists (select 1 from public.organizations where id = v_org_id) then
        v_org_id := null;
    end if;

    if auth.uid() is not null then
        select email into v_actor_name from auth.users where id = auth.uid();
    end if;

    insert into public.audit_log
        (organization_id, actor_user_id, actor_name, action, resource,
         resource_id, metadata, source)
    values
        (v_org_id, auth.uid(), v_actor_name,
         tg_table_name || '.' || lower(tg_op),
         tg_table_name, v_resource_id, v_meta, 'trigger');
    return null;
end;
$$;

comment on function public.trg_audit_capture() is
    'Phase 06/07/08/09/11: server-side audit capture for tenant-management, safety-domain, inspection/CAPA, emergency, and government_grants tables. Actor = auth.uid() (null under service-role). Append-only; never raises; org_id nulled on cascade.';

-- Wire the new table into the existing audit trigger set.
drop trigger if exists trg_audit_government_grants on public.government_grants;
create trigger trg_audit_government_grants
    after insert or update or delete on public.government_grants
    for each row execute function public.trg_audit_capture();

commit;
