-- =============================================================================
-- Migration 071: Phase 08 — Inspections + Corrective Actions (CAPA)
-- Tables: inspections, corrective_actions
-- RLS policies, audit triggers (extends trg_audit_capture from Phase 07)
--
-- Conventions:
--   - All helpers already exist (has_site_access, has_role_in_org,
--     set_updated_at from Phases 04/06/07)
--   - trg_audit_capture is REPLACE'd with new branches (Phase 07 pattern)
--   - RLS follows RLS_MATRIX §1.3 (inspections) and §1.4 (CAPA)
-- =============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. inspections table
-- ---------------------------------------------------------------------------
create table public.inspections (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid not null references public.sites(id) on delete cascade,
    client_id       text unique,                           -- offline idempotency
    title           text not null,
    description     text,
    inspector_id    uuid not null references auth.users(id),
    inspection_type text not null default 'routine'
                    check (inspection_type in ('routine','scheduled','ad-hoc','regulatory')),
    status          text not null default 'draft'
                    check (status in ('draft','in_progress','passed','failed','corrective_action_required')),
    score           integer check (score is null or (score >= 0 and score <= 100)),
    findings        jsonb default '[]'::jsonb,
    scheduled_date  date,
    completed_date  timestamptz,
    created_by      uuid not null references auth.users(id),
    updated_by      uuid,
    deleted_at      timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

comment on table public.inspections is
    'Site safety inspections (MINING_DOMAIN_MODEL §3). org+site scoped; inspector is the designated assessor.';

create index idx_inspections_org      on public.inspections(organization_id);
create index idx_inspections_site     on public.inspections(site_id);
create index idx_inspections_inspector on public.inspections(inspector_id);
create index idx_inspections_status   on public.inspections(status) where deleted_at is null;
create index idx_inspections_sched    on public.inspections(scheduled_date) where deleted_at is null;

drop trigger if exists trg_inspections_timestamp on public.inspections;
create trigger trg_inspections_timestamp
    before update on public.inspections
    for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- 2. corrective_actions table (CAPA)
-- ---------------------------------------------------------------------------
create table public.corrective_actions (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,  -- NULL = org-wide
    client_id       text unique,                           -- offline idempotency
    source_type     text not null check (source_type in ('incident','inspection','manual')),
    source_id       uuid,         -- polymorphic: id in incidents or inspections
    incident_id     uuid references public.incidents(id) on delete set null,
    inspection_id   uuid references public.inspections(id) on delete set null,
    title           text not null,
    description     text,
    priority        text not null default 'medium'
                    check (priority in ('low','medium','high','critical')),
    status          text not null default 'open'
                    check (status in ('open','in_progress','completed','overdue','cancelled')),
    assigned_to     uuid references auth.users(id),
    due_date        date,
    completed_date  timestamptz,
    root_cause      text,
    corrective_action text,
    preventive_action text,
    verified_by     uuid,
    verified_at     timestamptz,
    verification_notes text,
    created_by      uuid not null references auth.users(id),
    updated_by      uuid,
    deleted_at      timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

comment on table public.corrective_actions is
    'Corrective and preventive actions (CAPA) from incidents or inspections. site_id NULL = org-wide.';

create index idx_capa_org         on public.corrective_actions(organization_id);
create index idx_capa_site        on public.corrective_actions(site_id);
create index idx_capa_incident    on public.corrective_actions(incident_id) where incident_id is not null;
create index idx_capa_inspection  on public.corrective_actions(inspection_id) where inspection_id is not null;
create index idx_capa_assigned    on public.corrective_actions(assigned_to) where assigned_to is not null;
create index idx_capa_status      on public.corrective_actions(status) where deleted_at is null;
create index idx_capa_due         on public.corrective_actions(due_date) where deleted_at is null and status not in ('completed','cancelled');

drop trigger if exists trg_capa_timestamp on public.corrective_actions;
create trigger trg_capa_timestamp
    before update on public.corrective_actions
    for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- 3. RLS authorization helpers (SECURITY DEFINER policy primitives)
-- ---------------------------------------------------------------------------
-- has_site_access — exists from Phase 04/06.
-- has_role_in_org — exists from Phase 06.

-- Inspection: inspector-owns check (UPDATE gate)
create or replace function public.auth_user_is_inspector(p_inspector_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select p_inspector_id = auth.uid();
$$;

revoke all on function public.auth_user_is_inspector(uuid) from public;
grant execute on function public.auth_user_is_inspector(uuid) to anon, authenticated;

-- Inspection: insert gate (site member with inspections.create)
create or replace function public.auth_user_can_insert_inspection(p_organization_id uuid, p_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.auth_user_has_site_access(p_organization_id, p_site_id)
       and (public.auth_user_has_permission(p_organization_id, 'inspections.create')
            or public.auth_user_has_site_permission(p_organization_id, p_site_id, 'inspections.create'));
$$;

revoke all on function public.auth_user_can_insert_inspection(uuid, uuid) from public;
grant execute on function public.auth_user_can_insert_inspection(uuid, uuid) to anon, authenticated;

-- Inspection: update gate (inspector owner OR admin/safety_manager on site)
create or replace function public.auth_user_can_update_inspection(p_inspection_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1 from public.inspections i
        where i.id = p_inspection_id
          and public.auth_user_has_site_access(i.organization_id, i.site_id)
          and (
              public.auth_user_is_inspector(i.inspector_id)
              or public.auth_user_effective_role(i.organization_id)
                  in ('owner','admin','safety_manager')
          )
    );
$$;

revoke all on function public.auth_user_can_update_inspection(uuid) from public;
grant execute on function public.auth_user_can_update_inspection(uuid) to anon, authenticated;

-- Inspection: delete gate (admin/safety_manager only)
create or replace function public.auth_user_can_delete_inspection(p_inspection_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1 from public.inspections i
        where i.id = p_inspection_id
          and public.auth_user_has_org_access(i.organization_id)
          and public.auth_user_has_permission(i.organization_id, 'inspections.delete')
    );
$$;

revoke all on function public.auth_user_can_delete_inspection(uuid) from public;
grant execute on function public.auth_user_can_delete_inspection(uuid) to anon, authenticated;

-- CAPA: insert gate (admin/safety_manager/manager with site access)
create or replace function public.auth_user_can_insert_capa(p_organization_id uuid, p_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.auth_user_has_site_access(p_organization_id, p_site_id)
       and (public.auth_user_has_permission(p_organization_id, 'corrective_actions.create')
            or public.auth_user_has_site_permission(p_organization_id, p_site_id, 'corrective_actions.create'));
$$;

revoke all on function public.auth_user_can_insert_capa(uuid, uuid) from public;
grant execute on function public.auth_user_can_insert_capa(uuid, uuid) to anon, authenticated;

-- CAPA: update gate (assignee OR admin/safety_manager)
create or replace function public.auth_user_can_update_capa(p_capa_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1 from public.corrective_actions c
        where c.id = p_capa_id
          and public.auth_user_has_org_access(c.organization_id)
          and (
              c.assigned_to = auth.uid()
              or public.auth_user_effective_role(c.organization_id)
                  in ('owner','admin','safety_manager')
          )
    );
$$;

revoke all on function public.auth_user_can_update_capa(uuid) from public;
grant execute on function public.auth_user_can_update_capa(uuid) to anon, authenticated;

-- CAPA: delete gate (admin only)
create or replace function public.auth_user_can_delete_capa(p_capa_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1 from public.corrective_actions c
        where c.id = p_capa_id
          and public.auth_user_has_org_access(c.organization_id)
          and public.auth_user_has_permission(c.organization_id, 'corrective_actions.delete')
    );
$$;

revoke all on function public.auth_user_can_delete_capa(uuid) from public;
grant execute on function public.auth_user_can_delete_capa(uuid) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- 4. RLS policies
-- ---------------------------------------------------------------------------
alter table public.inspections enable row level security;
alter table public.corrective_actions enable row level security;

-- inspections ----------------------------------------------------------------
drop policy if exists inspections_select on public.inspections;
create policy inspections_select on public.inspections
    for select to authenticated
    using (
        deleted_at is null
        and (
            -- Org-wide safety/admin roles see all inspections
            (public.auth_user_has_org_access(organization_id)
             and public.auth_user_effective_role(organization_id)
                 in ('owner', 'admin', 'safety_manager', 'safety_officer'))
            -- Site-scoped roles see inspections at their site
            or (public.auth_user_has_site_access(organization_id, site_id)
                and public.auth_user_site_effective_role(organization_id, site_id)
                    in ('site_manager', 'supervisor'))
        )
    );

drop policy if exists inspections_insert on public.inspections;
create policy inspections_insert on public.inspections
    for insert to authenticated
    with check (public.auth_user_can_insert_inspection(organization_id, site_id));

drop policy if exists inspections_update on public.inspections;
create policy inspections_update on public.inspections
    for update to authenticated
    using (public.auth_user_can_update_inspection(id))
    with check (public.auth_user_can_update_inspection(id));

drop policy if exists inspections_delete on public.inspections;
create policy inspections_delete on public.inspections
    for delete to authenticated
    using (public.auth_user_can_delete_inspection(id));

-- corrective_actions --------------------------------------------------------
-- SELECT: org-wide safety/admin roles + site-scoped supervisor/site_manager
drop policy if exists capa_select on public.corrective_actions;
create policy capa_select on public.corrective_actions
    for select to authenticated
    using (
        deleted_at is null
        and (
            -- Org-wide safety/admin roles see all CAPAs
            (public.auth_user_has_org_access(organization_id)
             and public.auth_user_effective_role(organization_id)
                 in ('owner', 'admin', 'safety_manager'))
            -- Site-scoped roles see CAPAs at their site
            or (site_id is not null
                and public.auth_user_has_site_access(organization_id, site_id)
                and public.auth_user_site_effective_role(organization_id, site_id)
                    in ('site_manager', 'supervisor'))
        )
    );

drop policy if exists capa_insert on public.corrective_actions;
create policy capa_insert on public.corrective_actions
    for insert to authenticated
    with check (public.auth_user_can_insert_capa(organization_id, site_id));

drop policy if exists capa_update on public.corrective_actions;
create policy capa_update on public.corrective_actions
    for update to authenticated
    using (public.auth_user_can_update_capa(id))
    with check (public.auth_user_can_update_capa(id));

drop policy if exists capa_delete on public.corrective_actions;
create policy capa_delete on public.corrective_actions
    for delete to authenticated
    using (public.auth_user_can_delete_capa(id));

-- ---------------------------------------------------------------------------
-- 5. Grants (consistent with Phases 06/07: anon+authenticated SELECT,
--    authenticated DML gated by RLS)
-- ---------------------------------------------------------------------------
grant select on table public.inspections, public.corrective_actions
    to anon, authenticated;
grant insert, update, delete on table public.inspections, public.corrective_actions
    to authenticated;

-- ---------------------------------------------------------------------------
-- 6. Server-side audit: extend trg_audit_capture with inspections + CAPA
--    branches (Phase 07 pattern — CREATE OR REPLACE preserving all prior
--    branches verbatim)
-- ---------------------------------------------------------------------------
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
        else
            return null;
    end case;

    -- Tenant scope is only valid while the org exists. When the org is being
    -- removed, null it so the append-only audit record is still written.
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
    'Phase 06/07/08: server-side audit capture for tenant-management, safety-domain, and inspection/CAPA tables. Actor = auth.uid(). Append-only; never raises.';

-- Audit triggers for new tables
drop trigger if exists trg_audit_inspections on public.inspections;
create trigger trg_audit_inspections
    after insert or update or delete on public.inspections
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_audit_capa on public.corrective_actions;
create trigger trg_audit_capa
    after insert or update or delete on public.corrective_actions
    for each row execute function public.trg_audit_capture();

commit;
