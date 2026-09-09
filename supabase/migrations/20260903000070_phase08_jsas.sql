-- ============================================================================
-- MINEGUARD LIBERIA — Phase 08: Job Safety Analysis (JSA)
-- Target database: Supabase (PostgreSQL 15+)
--
-- Implements RLS_MATRIX.md §1.2 jsas row:
--   owner/admin/safety_manager/org-admin: S,I,U,D + safety_manager/supervisor may approve
--   safety_officer: S,I,U
--   site_manager: S,I,U (own site)
--   supervisor: S,I,U (own crew reports) + approve
--   worker/contractor: I(own), S(own)
--
-- Tables:
--   jsas      — org-scoped JSA records with approval lifecycle
--   jsa_steps — child hazard steps (per JSA; array-of-objects normalized from
--               the legacy JSON structure: [{hazard, severity, likelihood,
--               score, control, residual_risk}])
--
-- JSA PPE is a JSONB array on jsas (simple list of PPE item names from the
-- legacy form); evidence/photos on JSAs are reserved for Phase 09+ (document
-- storage, same pattern as incident_evidence).
--
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. jsas (Job Safety Analysis)
-- ---------------------------------------------------------------------------
create table public.jsas (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    department_id   uuid references public.organizational_units(id) on delete set null,
    client_id       text unique,
    -- reporter / subject
    reported_by_user_id uuid references auth.users(id) on delete set null,
    reported_by_name  text,
    worker_text       text,          -- legacy worker name (free-text pre-mapping)
    supervisor_text   text,          -- legacy supervisor name
    badge             text,
    dept_text         text,
    -- JSA core fields
    task              text not null,        -- e.g. "Vehicle maintenance"
    activity          text,                 -- optional activity detail
    location_text     text,                 -- free-text location (legacy parity)
    date              date,                 -- planned date of work
    lang              text not null default 'en',
    ppe               jsonb not null default '[]'::jsonb,  -- ["Hard","Steel-Toe",…]
    -- Approval lifecycle
    status            text not null default 'SUBMITTED' check (status in (
                          'DRAFT', 'SUBMITTED', 'APPROVED',
                          'IN_PROGRESS', 'COMPLETED', 'REJECTED',
                          'ARCHIVED')),
    approved_by       uuid references auth.users(id) on delete set null,
    approved_at       timestamptz,
    rejection_reason  text,
    -- Worker-facing broadcast (same concept as incidents site_notice_scope)
    site_notice_scope boolean not null default false,
    -- soft delete
    deleted           boolean not null default false,
    deleted_at        timestamptz,
    deleted_by        uuid references auth.users(id) on delete set null,
    saved_at          timestamptz,
    legacy_status     text,
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),
    created_by        uuid references auth.users(id) on delete set null
);

comment on table public.jsas is
    'Job Safety Analysis records (MINING_DOMAIN_MODEL §2 JSA). Each JSA captures a task, hazards (jsa_steps), required PPE, and an approval lifecycle. organization_id is the security boundary.';

create index jsas_org_created_idx on public.jsas (organization_id, created_at desc);
create index jsas_site_idx     on public.jsas (site_id);
create index jsas_status_idx   on public.jsas (organization_id, status);
create index jsas_reporter_idx on public.jsas (reported_by_user_id);

drop trigger if exists trg_jsas_updated_at on public.jsas;
create trigger trg_jsas_updated_at
    before update on public.jsas
    for each row execute function public.set_updated_at();

-- Reporter + scope integrity (mirrors Phase 07 incident trigger)
drop trigger if exists trg_jsas_guard on public.jsas;
create or replace function public.trg_jsas_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    if tg_op = 'INSERT' then
        if new.reported_by_user_id is not null and auth.uid() is not null
           and new.reported_by_user_id <> auth.uid() then
            raise exception 'reporter must be the current user';
        end if;
        if new.reported_by_user_id is null and auth.uid() is not null then
            new.reported_by_user_id := auth.uid();
        end if;
        if new.created_by is null and auth.uid() is not null then
            new.created_by := auth.uid();
        end if;
    else
        -- UPDATE: pin reporter (immutable), preserve approved_by/at unless set
        new.reported_by_user_id := old.reported_by_user_id;
        if new.approved_by is null and old.approved_by is not null then
            new.approved_by := old.approved_by;
            new.approved_at := old.approved_at;
        end if;
    end if;

    if new.site_id is not null and not exists (
        select 1 from public.sites
        where id = new.site_id and organization_id = new.organization_id
    ) then
        raise exception 'site does not belong to the given organization';
    end if;
    if new.department_id is not null and not exists (
        select 1 from public.organizational_units u
        where u.id = new.department_id
          and u.organization_id = new.organization_id
          and (new.site_id is null or u.site_id = new.site_id)
    ) then
        raise exception 'department does not belong to the given organization/site';
    end if;
    return new;
end;
$$;
create trigger trg_jsas_guard
    before insert or update on public.jsas
    for each row execute function public.trg_jsas_guard();

-- ---------------------------------------------------------------------------
-- 2. jsa_steps (child hazard steps)
-- ---------------------------------------------------------------------------
create table public.jsa_steps (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    jsa_id          uuid not null references public.jsas(id) on delete cascade,
    step_number     integer not null default 1,
    hazard          text not null,
    severity_label  text check (severity_label in ('low','medium','high','critical')),
    likelihood      text,
    score           integer,
    control         text,                 -- existing controls
    additional_controls text,            -- extra controls to be implemented
    residual_risk   text,
    notes           text,
    created_at      timestamptz not null default now(),
    unique (jsa_id, step_number)
);

comment on table public.jsa_steps is
    'Individual hazard steps within a JSA. Each step describes one identified hazard with severity, controls, and residual risk. organization_id/site_id mirror the parent JSA server-side.';

create index jsa_steps_jsa_idx on public.jsa_steps (jsa_id);

-- Mirror org/site from parent + enforce step ordering
drop trigger if exists trg_jsa_steps_guard on public.jsa_steps;
create or replace function public.trg_jsa_steps_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    select organization_id, site_id into new.organization_id, new.site_id
    from public.jsas where id = new.jsa_id;
    if new.organization_id is null then
        raise exception 'JSA does not exist';
    end if;
    return new;
end;
$$;
create trigger trg_jsa_steps_guard
    before insert or update on public.jsa_steps
    for each row execute function public.trg_jsa_steps_guard();

-- ---------------------------------------------------------------------------
-- 3. Authorization helpers (SECURITY DEFINER policy primitives)
-- ---------------------------------------------------------------------------
-- jsas SELECT (per RLS_MATRIX §1.2):
--   org-wide roles: owner/admin/safety_manager/safety_officer → see all org JSAs
--   site_manager: see JSAs at their site(s)
--   supervisor: see JSAs at their site(s) (approve crew)
--   worker/contractor: own submissions only + site_notice_scope broadcast

create or replace function public.auth_user_can_view_jsa(p_jsa_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.jsas j
        where j.id = p_jsa_id
          and public.auth_user_has_site_access(j.organization_id, j.site_id)
          and (
              public.auth_user_effective_role(j.organization_id)
                  in ('owner', 'admin', 'safety_manager', 'safety_officer')
              or public.auth_user_site_effective_role(j.organization_id, j.site_id)
                  in ('site_manager', 'supervisor')
              or j.reported_by_user_id = auth.uid()
              or j.site_notice_scope
          )
    );
$$;

comment on function public.auth_user_can_view_jsa(uuid) is
    'Phase 08: can the current user SELECT this JSA? Matches RLS_MATRIX §1.2 jsas row.';

create or replace function public.auth_user_can_insert_jsa(p_organization_id uuid, p_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.auth_user_has_site_access(p_organization_id, p_site_id)
       and (public.auth_user_has_permission(p_organization_id, 'jsas.create')
            or public.auth_user_has_site_permission(p_organization_id, p_site_id, 'jsas.create'));
$$;

comment on function public.auth_user_can_insert_jsa(uuid, uuid) is
    'Phase 08: can the current user create a JSA in this org/site?';

create or replace function public.auth_user_can_update_jsa(p_jsa_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.jsas j
        where j.id = p_jsa_id
          and public.auth_user_has_site_access(j.organization_id, j.site_id)
          and (
              public.auth_user_effective_role(j.organization_id)
                  in ('owner', 'admin', 'safety_manager', 'safety_officer')
              or public.auth_user_site_effective_role(j.organization_id, j.site_id)
                  in ('site_manager', 'supervisor')
          )
    );
$$;

comment on function public.auth_user_can_update_jsa(uuid) is
    'Phase 08: can the current user UPDATE this JSA? Org/site safety roles; workers cannot edit after submission.';

create or replace function public.auth_user_can_delete_jsa(p_jsa_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.jsas j
        where j.id = p_jsa_id
          and public.auth_user_has_org_access(j.organization_id)
          and public.auth_user_has_permission(j.organization_id, 'jsas.approve')
    );
$$;

comment on function public.auth_user_can_delete_jsa(uuid) is
    'Phase 08: hard-DELETE gate for JSAs (jsas.approve holders: owner/admin/safety_manager).';

-- Step-level: follow parent JSA permissions
create or replace function public.auth_user_can_update_jsa_steps(p_jsa_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.auth_user_can_update_jsa(p_jsa_id);
$$;

revoke all on function public.auth_user_can_view_jsa(uuid) from public;
revoke all on function public.auth_user_can_insert_jsa(uuid, uuid) from public;
revoke all on function public.auth_user_can_update_jsa(uuid) from public;
revoke all on function public.auth_user_can_delete_jsa(uuid) from public;
revoke all on function public.auth_user_can_update_jsa_steps(uuid) from public;
grant execute on function public.auth_user_can_view_jsa(uuid) to anon, authenticated;
grant execute on function public.auth_user_can_insert_jsa(uuid, uuid) to anon, authenticated;
grant execute on function public.auth_user_can_update_jsa(uuid) to anon, authenticated;
grant execute on function public.auth_user_can_delete_jsa(uuid) to anon, authenticated;
grant execute on function public.auth_user_can_update_jsa_steps(uuid) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- 4. RLS policies
-- ---------------------------------------------------------------------------
alter table public.jsas enable row level security;
alter table public.jsa_steps enable row level security;

-- jsas
drop policy if exists jsas_select on public.jsas;
create policy jsas_select on public.jsas
    for select to authenticated
    using (public.auth_user_can_view_jsa(id));

drop policy if exists jsas_insert on public.jsas;
create policy jsas_insert on public.jsas
    for insert to authenticated
    with check (public.auth_user_can_insert_jsa(organization_id, site_id));

drop policy if exists jsas_update on public.jsas;
create policy jsas_update on public.jsas
    for update to authenticated
    using (public.auth_user_can_update_jsa(id))
    with check (public.auth_user_can_update_jsa(id)
                and public.auth_user_can_insert_jsa(organization_id, site_id));

drop policy if exists jsas_delete on public.jsas;
create policy jsas_delete on public.jsas
    for delete to authenticated
    using (public.auth_user_can_delete_jsa(id));

-- jsa_steps (follow parent JSA permissions)
drop policy if exists jsa_steps_select on public.jsa_steps;
create policy jsa_steps_select on public.jsa_steps
    for select to authenticated
    using (public.auth_user_can_view_jsa(jsa_id));

drop policy if exists jsa_steps_insert on public.jsa_steps;
create policy jsa_steps_insert on public.jsa_steps
    for insert to authenticated
    with check (public.auth_user_can_update_jsa_steps(jsa_id));

drop policy if exists jsa_steps_update on public.jsa_steps;
create policy jsa_steps_update on public.jsa_steps
    for update to authenticated
    using (public.auth_user_can_update_jsa_steps(jsa_id))
    with check (public.auth_user_can_update_jsa_steps(jsa_id));

drop policy if exists jsa_steps_delete on public.jsa_steps;
create policy jsa_steps_delete on public.jsa_steps
    for delete to authenticated
    using (public.auth_user_can_update_jsa_steps(jsa_id));

-- ---------------------------------------------------------------------------
-- 5. Grants
-- ---------------------------------------------------------------------------
grant select on table public.jsas, public.jsa_steps to anon, authenticated;
grant insert, update, delete on table public.jsas, public.jsa_steps to authenticated;

-- ---------------------------------------------------------------------------
-- 6. Audit triggers (extend trg_audit_capture + new triggers)
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
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.user_id, old.user_id)::text;
            v_meta := jsonb_build_object(
                'role', coalesce(new.role, old.role), 'status', coalesce(new.status, old.status),
                'role_previous', old.role, 'status_previous', old.status);
        when 'site_members' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.user_id, old.user_id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'role', coalesce(new.role, old.role), 'status', coalesce(new.status, old.status),
                'role_previous', old.role, 'status_previous', old.status);
        when 'sites' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'name', coalesce(new.name, old.name), 'county', coalesce(new.county, old.county),
                'status', coalesce(new.status, old.status), 'status_previous', old.status);
        when 'organizational_units' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'name', coalesce(new.name, old.name), 'unit_type', coalesce(new.unit_type, old.unit_type),
                'status', coalesce(new.status, old.status), 'status_previous', old.status);
        when 'workers' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'full_name', coalesce(new.full_name, old.full_name),
                'employee_id', coalesce(new.employee_id, old.employee_id),
                'status', coalesce(new.status, old.status), 'status_previous', old.status);
        when 'org_invites' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'email', coalesce(new.email, old.email),
                'role', coalesce(new.role, old.role),
                'status', coalesce(new.status, old.status));
        when 'organizations' then
            v_org_id := coalesce(new.id, old.id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'slug', coalesce(new.slug, old.slug), 'name', coalesce(new.name, old.name),
                'status', coalesce(new.status, old.status), 'status_previous', old.status);
        when 'incidents' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'severity', coalesce(new.severity, old.severity),
                'status', coalesce(new.status, old.status), 'status_previous', old.status,
                'type', coalesce(new.incident_type, old.incident_type),
                'site_id', coalesce(new.site_id, old.site_id),
                'deleted', coalesce(new.deleted, old.deleted), 'deleted_previous', old.deleted,
                'client_id', coalesce(new.client_id, old.client_id));
        when 'incident_evidence' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'incident_id', coalesce(new.incident_id, old.incident_id),
                'kind', coalesce(new.kind, old.kind),
                'size_bytes', coalesce(new.size_bytes, old.size_bytes));
        when 'incident_witnesses' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'incident_id', coalesce(new.incident_id, old.incident_id),
                'full_name', coalesce(new.full_name, old.full_name));
        when 'jsas' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'task', coalesce(new.task, old.task),
                'status', coalesce(new.status, old.status), 'status_previous', old.status,
                'site_id', coalesce(new.site_id, old.site_id),
                'approved_by', coalesce(new.approved_by, old.approved_by),
                'deleted', coalesce(new.deleted, old.deleted), 'deleted_previous', old.deleted,
                'client_id', coalesce(new.client_id, old.client_id));
            -- no PPE array or step details in audit (curated only)
        when 'jsa_steps' then
            v_org_id := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'jsa_id', coalesce(new.jsa_id, old.jsa_id),
                'step_number', coalesce(new.step_number, old.step_number),
                'hazard', coalesce(new.hazard, old.hazard),
                'severity_label', coalesce(new.severity_label, old.severity_label));
        else
            return null;
    end case;

    -- Tenant scope nulling on cascade (Phase 06 pattern)
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
    'Phase 06/07/08: server-side audit capture for tenant-management, incident, and JSA tables. Actor = auth.uid() (null under service-role). Append-only; org_id nulled on cascade.';

drop trigger if exists trg_audit_jsas on public.jsas;
create trigger trg_audit_jsas
    after insert or update or delete on public.jsas
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_audit_jsa_steps on public.jsa_steps;
create trigger trg_audit_jsa_steps
    after insert or update or delete on public.jsa_steps
    for each row execute function public.trg_audit_capture();

commit;