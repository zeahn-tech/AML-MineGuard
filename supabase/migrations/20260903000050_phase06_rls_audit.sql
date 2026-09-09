-- ============================================================================
-- MINEGUARD LIBERIA — Phase 06: RLS + security enforcement (full RLS_MATRIX)
-- Target database: Supabase (PostgreSQL 15+)
--
-- Implements docs/engineering/RLS_MATRIX.md over the Phases 01–04 tables plus
-- the audit foundation (SECURITY_MODEL §2.6, DATABASE_ARCHITECTURE §2.5):
--
--   1. SELECT matrix enforcement with site scope:
--        sites                → org members OR active members of that site
--        organizational_units → org members OR active members of the unit's site
--        workers (registry)   → least privilege per RLS_MATRIX §1.1: readers
--                               must hold workers.view / users.view at org
--                               scope, or at their own site (site-ONLY users
--                               never widen beyond their site; plain workers
--                               never list the roster — matrix "WRK: –")
--        org_invites / memberships unchanged (invite rows carry one-time
--        tokens; membership reads are own-row + org as of Phase 04)
--
--   2. organizations UPDATE via RLS for org owner/admin
--      (organizations.manage) — the org-row write path per RLS_MATRIX §1.1
--      ("OWN S,I,U own"). INSERT stays platform-level (Phase 12 SaaS).
--
--   3. audit_log table + SERVER-SIDE audit triggers on the tenant-management
--      tables (organization_members, site_members, organizational_units,
--      workers, org_invites, organizations). Rows are written by the database
--      with the ACTOR taken from auth.uid() — never from a client-supplied
--      string (closes C4 spoofable-audit path for these operations). Clients
--      may SELECT (org members with audit_logs.view) but never
--      INSERT/UPDATE/DELETE: no RLS write policies AND table DML privileges
--      are revoked (append-only).
--
-- Explicitly NOT this phase (fixed phase order): safety-domain tables + their
-- policies (Phases 07–09), platform/government grants (Phases 11–12). Those
-- phases extend the SAME policy primitives used here.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. SELECT matrix enforcement with site scope
-- ---------------------------------------------------------------------------

-- sites: org members OR active members of the row's site (Phase 04 helper).
drop policy if exists "sites_select_org_members" on public.sites;
create policy sites_select_org_or_site on public.sites
    for select to authenticated
    using (public.auth_user_has_site_access(organization_id, id));

-- organizational_units: org members OR active members of the unit's site.
drop policy if exists "units_select_org_members" on public.organizational_units;
create policy units_select_org_or_site on public.organizational_units
    for select to authenticated
    using (public.auth_user_has_site_access(organization_id, site_id));

-- workers registry: least privilege per RLS_MATRIX §1.1 (worker/contractor
-- roles never list the roster). Org-scope readers need workers.view or
-- users.view at org scope; site-scope-only readers need the same at their
-- site. has_site_permission already applies max(org role, site role).
drop policy if exists "workers_select_org_members" on public.workers;
create policy workers_select_viewers on public.workers
    for select to authenticated
    using (
        (public.auth_user_has_org_access(organization_id)
         and (public.auth_user_has_permission(organization_id, 'workers.view')
              or public.auth_user_has_permission(organization_id, 'users.view')))
        or (site_id is not null
            and (public.auth_user_has_site_permission(organization_id, site_id, 'workers.view')
                 or public.auth_user_has_site_permission(organization_id, site_id, 'users.view')))
    );

-- org_invites: intentionally unchanged — org members only (rows carry
-- one-time tokens; invites are owner/admin-managed via RPC).

-- ---------------------------------------------------------------------------
-- 2. organizations UPDATE (owner/admin) — RLS_MATRIX §1.1 "OWN S,I,U (own)"
-- ---------------------------------------------------------------------------
drop policy if exists "org_update_owner_admin" on public.organizations;
create policy org_update_owner_admin on public.organizations
    for update to authenticated
    using (
        public.auth_user_has_org_access(id)
        and public.auth_user_has_permission(id, 'organizations.manage')
    )
    with check (
        public.auth_user_has_org_access(id)
        and public.auth_user_has_permission(id, 'organizations.manage')
    );

-- ---------------------------------------------------------------------------
-- 3. audit_log — append-only, server-written (SECURITY_MODEL §2.6)
-- ---------------------------------------------------------------------------
create table public.audit_log (
    id              uuid primary key default gen_random_uuid(),
    -- null = platform-scope rows (Phase 11+ platform/government audit)
    organization_id uuid references public.organizations(id) on delete cascade,
    -- null under service-role/system writes (no JWT identity)
    actor_user_id   uuid references auth.users(id) on delete set null,
    -- display copy (auth.users.email for server writes; legacy import actors)
    actor_name      text,
    -- e.g. 'organization_members.insert' | 'workers.update' | 'organization.update'
    action          text not null,
    resource        text not null,
    resource_id     text,
    metadata        jsonb not null default '{}'::jsonb,
    source          text not null default 'trigger'
                    check (source in ('trigger', 'rpc', 'legacy_import', 'service', 'system')),
    created_at      timestamptz not null default now()
);

comment on table public.audit_log is
    'Append-only server-side audit trail (DATABASE_ARCHITECTURE §2.5). Rows are written by the database (SECURITY DEFINER triggers / RPCs / service role) — never by clients. organization_id is the tenant scope; Phase 05 legacy imports set source = legacy_import and carry actor strings in actor_name.';

create index audit_log_org_created_idx on public.audit_log (organization_id, created_at desc);
create index audit_log_actor_idx      on public.audit_log (actor_user_id);
create index audit_log_action_idx     on public.audit_log (action);

alter table public.audit_log enable row level security;

-- SELECT: org members with audit_logs.view (owner/admin bundles today;
-- platform/government audit readers land with Phases 11–12).
drop policy if exists "audit_select_viewers" on public.audit_log;
create policy audit_select_viewers on public.audit_log
    for select to authenticated
    using (
        organization_id is not null
        and public.auth_user_has_org_access(organization_id)
        and public.auth_user_has_permission(organization_id, 'audit_logs.view')
    );

-- Append-only: no INSERT/UPDATE/DELETE policies, and DML privileges are
-- revoked so even a granted-but-unpolicied path cannot write.
grant select on table public.audit_log to anon, authenticated;
revoke insert, update, delete on table public.audit_log from anon, authenticated;

-- ---------------------------------------------------------------------------
-- 4. Server-side audit capture (trigger)
-- ---------------------------------------------------------------------------
-- One SECURITY DEFINER trigger function covers the tenant-management tables.
-- It records the ACTOR from auth.uid() (never client input), a curated subset
-- of columns in metadata (tokens and other secrets/PII are deliberately NOT
-- mirrored), and maps TG_OP to `{table}.{insert|update|delete}` actions.
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
            -- token is deliberately NOT audited (one-time secret)
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
        else
            return null;
    end case;

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
    return null; -- AFTER trigger: result unused
end;
$$;

comment on function public.trg_audit_capture() is
    'Phase 06: server-side audit capture for tenant-management tables. Actor = auth.uid() (null under service-role writes). Append-only: inserts into audit_log only; never raises.';

drop trigger if exists trg_audit_organization_members on public.organization_members;
create trigger trg_audit_organization_members
    after insert or update or delete on public.organization_members
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_audit_site_members on public.site_members;
create trigger trg_audit_site_members
    after insert or update or delete on public.site_members
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_audit_organizational_units on public.organizational_units;
create trigger trg_audit_organizational_units
    after insert or update or delete on public.organizational_units
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_audit_workers on public.workers;
create trigger trg_audit_workers
    after insert or update or delete on public.workers
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_audit_org_invites on public.org_invites;
create trigger trg_audit_org_invites
    after insert or update or delete on public.org_invites
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_audit_organizations on public.organizations;
create trigger trg_audit_organizations
    after insert or update or delete on public.organizations
    for each row execute function public.trg_audit_capture();

commit;
