-- ============================================================================
-- MINEGUARD LIBERIA — Phase 09: Emergency response + SOS
-- Target database: Supabase (PostgreSQL 15+)
--
-- Implements RLS_MATRIX.md §1.2 emergency rows + MINING_DOMAIN_MODEL.md §2
-- (Emergency Event) + EMERGENCY_RESPONSE_ARCHITECTURE.md §2 on top of the
-- Phase 01–08 primitives (org/site scope helpers, RBAC permission catalog,
-- append-only audit_log, trg_audit_capture extension pattern).
--
-- Tables:
--   emergency_events            — org-scoped emergency/SOS lifecycle records
--                                 (ACTIVATED → … → CLOSED). Phase 05 mapper
--                                 target shape (client_id, category, message,
--                                 contact_number, assembly_point,
--                                 activated_by_text, ended_by_text, started_at,
--                                 deactivated_at, duration_seconds, status,
--                                 notified_workers_legacy, created_at, deleted)
--                                 is a direct column subset for import.
--   emergency_acknowledgements  — per-user acks (identity, not device strings)
--   emergency_escalations       — escalation history
--   emergency_responders        — responder dispatch/disposition
--   emergency_log               — append-only lifecycle event stream
--
-- Role/scope matrix implemented (RLS_MATRIX §1.2 emergency_events row):
--   org-wide roles (owner/admin/safety_manager/safety_officer/site_manager):
--     SELECT org pool, INSERT, UPDATE, close (emergency.resolve)
--   supervisor (site scope): SELECT site events, INSERT (alert/activate)
--   worker/contractor: SELECT events at own site (site_notice_scope), ack
--     (own row via emergency.acknowledge)
--   anon/outsider: none
--
-- Safety-critical rules (PROJECT_MASTER §12.4):
--   * no silently-failed safety operations: activation/ack/lifecycle writes
--     are RLS+trigger enforced server-side, never client booleans.
--   * every lifecycle transition + ack is mirrored to audit_log via
--     trg_audit_capture; the emergency_log stream is append-only.
--   * duplicate prevention: emergency_acknowledgements unique(event, user).
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. emergency_events
-- ---------------------------------------------------------------------------
create table public.emergency_events (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    client_id       text unique,               -- offline idempotency (Phase 10)
    -- legacy import parity (Phase 05 mapper target shape)
    category        text,
    message         text,
    contact_number  text,
    assembly_point  text,
    activated_by_text text,
    ended_by_text   text,
    started_at      timestamptz not null default now(),
    deactivated_at  timestamptz,
    duration_seconds integer,
    notified_workers_legacy integer,
    -- target model
    severity        text not null default 'high' check (severity in ('low','medium','high','critical')),
    status          text not null default 'ACTIVATED' check (status in (
                        'ACTIVATED', 'ACKNOWLEDGED', 'RESPONDING', 'CONTAINED',
                        'RESOLVED', 'CLOSED')),
    location_text   text,
    affected_area   text,
    -- server-side activation identity (never client-attributed)
    activated_by    uuid references auth.users(id) on delete set null,
    resolved_by     uuid references auth.users(id) on delete set null,
    resolution_note text,
    after_action_note text,
    -- workers of the site keep reading the event record (retention/read scope;
    -- visibility of org-wide rows is decided by role below, never by status)
    site_notice_scope boolean not null default true,
    lang            text not null default 'en',
    deleted         boolean not null default false,
    deleted_at      timestamptz,
    deleted_by      uuid references auth.users(id) on delete set null,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    created_by      uuid references auth.users(id) on delete set null
);

comment on table public.emergency_events is
    'Emergency/SOS events (MINING_DOMAIN_MODEL §2 Emergency Event; EMERGENCY_RESPONSE_ARCHITECTURE §2). Lifecycle ACTIVATED→ACKNOWLEDGED→RESPONDING→CONTAINED→RESOLVED→CLOSED enforced server-side (forward-only). organization_id is the security boundary; activated_by is set from auth.uid() and never client-attributed. Phase 05 mapper target shape is a direct column subset.';

create index emergency_events_org_started_idx on public.emergency_events (organization_id, started_at desc);
create index emergency_events_site_idx        on public.emergency_events (site_id);
create index emergency_events_status_idx      on public.emergency_events (organization_id, status);

drop trigger if exists trg_emergency_events_updated_at on public.emergency_events;
create trigger trg_emergency_events_updated_at
    before update on public.emergency_events
    for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- 2. emergency_acknowledgements
-- ---------------------------------------------------------------------------
create table public.emergency_acknowledgements (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    event_id        uuid not null references public.emergency_events(id) on delete cascade,
    acked_by        uuid not null references auth.users(id) on delete cascade,
    acked_at        timestamptz not null default now(),
    note            text,
    channel         text not null default 'app' check (channel in ('app','push','sms','voice','radio')),
    client_id       text,   -- offline idempotency (Phase 10); dedupe on (event,user) unique
    created_at      timestamptz not null default now(),
    unique (event_id, acked_by)
);

comment on table public.emergency_acknowledgements is
    'Per-user emergency acknowledgements (EMERGENCY_RESPONSE_ARCHITECTURE §2.1). One per (event, user) — device retries never duplicate. acked_by is server-pinned to auth.uid().';

create index emergency_acks_event_idx on public.emergency_acknowledgements (event_id);
create index emergency_acks_user_idx  on public.emergency_acknowledgements (acked_by);

-- ---------------------------------------------------------------------------
-- 3. emergency_escalations
-- ---------------------------------------------------------------------------
create table public.emergency_escalations (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    event_id        uuid not null references public.emergency_events(id) on delete cascade,
    level           integer not null check (level >= 1),
    escalated_to    text,           -- role/team label (user linking is Phase 12)
    escalated_to_user uuid references auth.users(id) on delete set null,
    reason          text,
    created_at      timestamptz not null default now(),
    created_by      uuid references auth.users(id) on delete set null
);

comment on table public.emergency_escalations is
    'Escalation history for emergency events (level, target role/team/user, reason).';

create index emergency_esc_event_idx on public.emergency_escalations (event_id);

-- ---------------------------------------------------------------------------
-- 4. emergency_responders
-- ---------------------------------------------------------------------------
create table public.emergency_responders (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    event_id        uuid not null references public.emergency_events(id) on delete cascade,
    responder_user  uuid references auth.users(id) on delete set null,
    responder_text  text,           -- team/role label (legacy/free-text parity)
    role            text,           -- e.g. 'first aider', 'medic', 'rescue'
    status          text not null default 'dispatched' check (status in (
                        'dispatched','en_route','arrived','on_scene','standing_down','stood_down')),
    dispatched_at   timestamptz not null default now(),
    arrived_at      timestamptz,
    client_id       text,           -- offline idempotency (Phase 10)
    created_at      timestamptz not null default now()
);

comment on table public.emergency_responders is
    'Responder dispatch/disposition records per emergency event.';

create index emergency_resp_event_idx on public.emergency_responders (event_id);

-- ---------------------------------------------------------------------------
-- 5. emergency_log (append-only lifecycle stream)
-- ---------------------------------------------------------------------------
create table public.emergency_log (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    event_id        uuid not null references public.emergency_events(id) on delete cascade,
    entry_type      text not null check (entry_type in (
                        'activated','acknowledged','responding','escalated',
                        'contained','resolved','closed','note')),
    actor_user_id   uuid references auth.users(id) on delete set null,
    detail          jsonb not null default '{}'::jsonb,
    created_at      timestamptz not null default now()
);

comment on table public.emergency_log is
    'Append-only lifecycle event stream per emergency event (EMERGENCY_RESPONSE_ARCHITECTURE §2.1 emergency_log). Rows are written by triggers only; no client INSERT/UPDATE/DELETE policy exists.';

create index emergency_log_event_idx on public.emergency_log (event_id);
create index emergency_log_org_idx   on public.emergency_log (organization_id, created_at desc);

-- ---------------------------------------------------------------------------
-- 6. Lifecycle + integrity guard (server-side; safety-critical)
-- ---------------------------------------------------------------------------
--   * activated_by is forced to auth.uid() on INSERT (never client-attributed)
--     and pinned immutable on UPDATE.
--   * status moves FORWARD only (ACTIVATED=0 … CLOSED=5).
--   * resolved_by is immutable once set; legacy deactivation (ACTIVATED →
--     RESOLVED with deactivated_at) records the resolver server-side.
create or replace function public.trg_emergency_events_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    v_rank_new int;
    v_rank_old int;
begin
    if tg_op = 'INSERT' then
        if new.activated_by is not null and auth.uid() is not null
           and new.activated_by <> auth.uid() then
            raise exception 'activated_by must be the current user';
        end if;
        if new.activated_by is null and auth.uid() is not null then
            new.activated_by := auth.uid();
        end if;
        if new.created_by is null and auth.uid() is not null then
            new.created_by := auth.uid();
        end if;
    else
        -- UPDATE: activation identity pinned (immutable)
        new.activated_by := old.activated_by;
        -- legacy deactivation path: ACTIVATED → RESOLVED records the resolver
        if new.status = 'RESOLVED' and old.status = 'ACTIVATED'
           and new.resolved_by is null then
            new.resolved_by := auth.uid();
        end if;
        -- resolved_by immutable once set
        if new.resolved_by is null and old.resolved_by is not null then
            new.resolved_by := old.resolved_by;
        elsif new.resolved_by is not null and old.resolved_by is not null
           and new.resolved_by <> old.resolved_by then
            raise exception 'resolved_by is immutable once set';
        end if;
    end if;

    -- org/site integrity
    if new.site_id is not null and not exists (
        select 1 from public.sites
        where id = new.site_id and organization_id = new.organization_id
    ) then
        raise exception 'site does not belong to the given organization';
    end if;

    -- forward-only lifecycle on UPDATE
    if tg_op = 'UPDATE' then
        v_rank_new := case new.status
            when 'ACTIVATED' then 0 when 'ACKNOWLEDGED' then 1 when 'RESPONDING' then 2
            when 'CONTAINED' then 3 when 'RESOLVED' then 4 when 'CLOSED' then 5 end;
        v_rank_old := case old.status
            when 'ACTIVATED' then 0 when 'ACKNOWLEDGED' then 1 when 'RESPONDING' then 2
            when 'CONTAINED' then 3 when 'RESOLVED' then 4 when 'CLOSED' then 5 end;
        if v_rank_new < v_rank_old then
            raise exception 'emergency status may only move forward';
        end if;
    end if;
    return new;
end;
$$;

-- ---------------------------------------------------------------------------
-- 7. Child-table scope mirroring + ack identity pinning
-- ---------------------------------------------------------------------------
create or replace function public.trg_emergency_child_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    select organization_id, site_id into new.organization_id, new.site_id
    from public.emergency_events where id = new.event_id;
    if new.organization_id is null then
        raise exception 'emergency event does not exist';
    end if;

    if tg_table_name = 'emergency_acknowledgements' then
        if new.acked_by is not null and auth.uid() is not null
           and new.acked_by <> auth.uid() then
            raise exception 'acked_by must be the current user';
        end if;
        if new.acked_by is null and auth.uid() is not null then
            new.acked_by := auth.uid();
        end if;
    end if;

    if tg_table_name = 'emergency_escalations' then
        if new.created_by is null and auth.uid() is not null then
            new.created_by := auth.uid();
        end if;
    end if;
    return new;
end;
$$;

-- ---------------------------------------------------------------------------
-- 8. Lifecycle logging trigger (append-only emergency_log stream)
-- ---------------------------------------------------------------------------
create or replace function public.trg_emergency_log_capture()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    if tg_op = 'INSERT' then
        insert into public.emergency_log (organization_id, site_id, event_id, entry_type, actor_user_id, detail)
        values (new.organization_id, new.site_id, new.id, 'activated', new.activated_by,
                jsonb_build_object('status', new.status, 'category', new.category,
                                   'site_id', new.site_id, 'client_id', new.client_id));
    elsif tg_op = 'UPDATE' and old.status is distinct from new.status then
        insert into public.emergency_log (organization_id, site_id, event_id, entry_type, actor_user_id, detail)
        values (new.organization_id, new.site_id, new.id,
                case new.status
                    when 'ACKNOWLEDGED' then 'acknowledged'
                    when 'RESPONDING' then 'responding'
                    when 'CONTAINED' then 'contained'
                    when 'RESOLVED' then 'resolved'
                    when 'CLOSED' then 'closed'
                    else 'note' end,
                coalesce(new.resolved_by, new.activated_by),
                jsonb_build_object('from', old.status, 'to', new.status));
    end if;
    return null;
end;
$$;

-- ---------------------------------------------------------------------------
-- 9. Authorization helpers (SECURITY DEFINER policy primitives)
-- ---------------------------------------------------------------------------
create or replace function public.auth_user_can_view_emergency_event(p_event_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.emergency_events e
        where e.id = p_event_id
          and public.auth_user_has_site_access(e.organization_id, e.site_id)
          and (
              public.auth_user_effective_role(e.organization_id)
                  in ('owner', 'admin', 'safety_manager', 'safety_officer', 'site_manager')
              or public.auth_user_site_effective_role(e.organization_id, e.site_id) = 'supervisor'
              -- worker/contractor: events of their site (site_notice_scope retention)
              or (e.site_notice_scope
                  and public.auth_user_site_effective_role(e.organization_id, e.site_id)
                      in ('worker', 'contractor'))
          )
    );
$$;

create or replace function public.auth_user_can_insert_emergency_event(p_organization_id uuid, p_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.auth_user_has_site_access(p_organization_id, p_site_id)
       and (public.auth_user_has_permission(p_organization_id, 'emergency.activate')
            or public.auth_user_has_site_permission(p_organization_id, p_site_id, 'emergency.activate'));
$$;

create or replace function public.auth_user_can_ack_emergency_event(p_event_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.emergency_events e
        where e.id = p_event_id
          and public.auth_user_has_site_access(e.organization_id, e.site_id)
          and (public.auth_user_has_permission(e.organization_id, 'emergency.acknowledge')
               or public.auth_user_has_site_permission(e.organization_id, e.site_id, 'emergency.acknowledge'))
          and e.status <> 'CLOSED'
    );
$$;

create or replace function public.auth_user_can_resolve_emergency_event(p_event_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.emergency_events e
        where e.id = p_event_id
          and public.auth_user_has_org_access(e.organization_id)
          and public.auth_user_has_permission(e.organization_id, 'emergency.resolve')
    );
$$;

create or replace function public.auth_user_can_update_emergency_child(p_event_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.emergency_events e
        where e.id = p_event_id
          and public.auth_user_has_site_access(e.organization_id, e.site_id)
          and (
              public.auth_user_has_permission(e.organization_id, 'emergency.resolve')
              -- org-scope acknowledge OR site-scope acknowledge (site-only responders)
              or public.auth_user_has_permission(e.organization_id, 'emergency.acknowledge')
              or public.auth_user_has_site_permission(e.organization_id, e.site_id, 'emergency.acknowledge')
          )
    );
$$;

revoke all on function public.auth_user_can_view_emergency_event(uuid) from public;
revoke all on function public.auth_user_can_insert_emergency_event(uuid, uuid) from public;
revoke all on function public.auth_user_can_ack_emergency_event(uuid) from public;
revoke all on function public.auth_user_can_resolve_emergency_event(uuid) from public;
revoke all on function public.auth_user_can_update_emergency_child(uuid) from public;
grant execute on function public.auth_user_can_view_emergency_event(uuid) to anon, authenticated;
grant execute on function public.auth_user_can_insert_emergency_event(uuid, uuid) to anon, authenticated;
grant execute on function public.auth_user_can_ack_emergency_event(uuid) to anon, authenticated;
grant execute on function public.auth_user_can_resolve_emergency_event(uuid) to anon, authenticated;
grant execute on function public.auth_user_can_update_emergency_child(uuid) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- 10. RLS policies
-- ---------------------------------------------------------------------------
alter table public.emergency_events enable row level security;
alter table public.emergency_acknowledgements enable row level security;
alter table public.emergency_escalations enable row level security;
alter table public.emergency_responders enable row level security;
alter table public.emergency_log enable row level security;

-- emergency_events -----------------------------------------------------------
drop policy if exists emergency_events_select on public.emergency_events;
create policy emergency_events_select on public.emergency_events
    for select to authenticated
    using (public.auth_user_can_view_emergency_event(id));

drop policy if exists emergency_events_insert on public.emergency_events;
create policy emergency_events_insert on public.emergency_events
    for insert to authenticated
    with check (public.auth_user_can_insert_emergency_event(organization_id, site_id));

drop policy if exists emergency_events_update on public.emergency_events;
create policy emergency_events_update on public.emergency_events
    for update to authenticated
    using (public.auth_user_can_resolve_emergency_event(id))
    with check (public.auth_user_can_resolve_emergency_event(id));

-- no DELETE policy: purge is an audited service-role path (Phase 12);
-- soft-delete (deleted=true) rides the UPDATE policy (emergency.resolve holders).

-- emergency_acknowledgements -------------------------------------------------
drop policy if exists emergency_acks_select on public.emergency_acknowledgements;
create policy emergency_acks_select on public.emergency_acknowledgements
    for select to authenticated
    using (public.auth_user_can_view_emergency_event(event_id));

drop policy if exists emergency_acks_insert on public.emergency_acknowledgements;
create policy emergency_acks_insert on public.emergency_acknowledgements
    for insert to authenticated
    with check (public.auth_user_can_ack_emergency_event(event_id));

-- UPDATE/DELETE: none — acks are immutable; unique(event,user) makes retries idempotent.

-- emergency_escalations ------------------------------------------------------
drop policy if exists emergency_esc_select on public.emergency_escalations;
create policy emergency_esc_select on public.emergency_escalations
    for select to authenticated
    using (public.auth_user_can_view_emergency_event(event_id));

drop policy if exists emergency_esc_insert on public.emergency_escalations;
create policy emergency_esc_insert on public.emergency_escalations
    for insert to authenticated
    with check (public.auth_user_can_update_emergency_child(event_id));

-- emergency_responders -------------------------------------------------------
drop policy if exists emergency_resp_select on public.emergency_responders;
create policy emergency_resp_select on public.emergency_responders
    for select to authenticated
    using (public.auth_user_can_view_emergency_event(event_id));

drop policy if exists emergency_resp_insert on public.emergency_responders;
create policy emergency_resp_insert on public.emergency_responders
    for insert to authenticated
    with check (public.auth_user_can_update_emergency_child(event_id));

drop policy if exists emergency_resp_update on public.emergency_responders;
create policy emergency_resp_update on public.emergency_responders
    for update to authenticated
    using (public.auth_user_can_update_emergency_child(event_id))
    with check (public.auth_user_can_update_emergency_child(event_id));

-- emergency_log --------------------------------------------------------------
-- SELECT only; NO write policies (append-only; written by trigger).
drop policy if exists emergency_log_select on public.emergency_log;
create policy emergency_log_select on public.emergency_log
    for select to authenticated
    using (public.auth_user_can_view_emergency_event(event_id));

-- ---------------------------------------------------------------------------
-- 11. Grants (Phase 01 convention)
-- ---------------------------------------------------------------------------
grant select on table public.emergency_events, public.emergency_acknowledgements,
    public.emergency_escalations, public.emergency_responders, public.emergency_log
    to anon, authenticated;
grant insert, update, delete on table public.emergency_events,
    public.emergency_acknowledgements, public.emergency_escalations,
    public.emergency_responders
    to authenticated;
-- emergency_log: SELECT grant only (append-only; no client DML).

-- ---------------------------------------------------------------------------
-- 12. Audit triggers (extend trg_audit_capture — Phase 07/08 pattern)
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
    'Phase 06/07/08/09: server-side audit capture for tenant-management, safety-domain, inspection/CAPA, and emergency tables. Actor = auth.uid() (null under service-role). Append-only; never raises; org_id nulled on cascade.';

-- ---------------------------------------------------------------------------
-- 13. Trigger wiring
-- ---------------------------------------------------------------------------
drop trigger if exists trg_emergency_events_guard on public.emergency_events;
create trigger trg_emergency_events_guard
    before insert or update on public.emergency_events
    for each row execute function public.trg_emergency_events_guard();

drop trigger if exists trg_emergency_events_log on public.emergency_events;
create trigger trg_emergency_events_log
    after insert or update on public.emergency_events
    for each row execute function public.trg_emergency_log_capture();

drop trigger if exists trg_audit_emergency_events on public.emergency_events;
create trigger trg_audit_emergency_events
    after insert or update or delete on public.emergency_events
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_emergency_acks_guard on public.emergency_acknowledgements;
create trigger trg_emergency_acks_guard
    before insert or update on public.emergency_acknowledgements
    for each row execute function public.trg_emergency_child_guard();

drop trigger if exists trg_audit_emergency_acks on public.emergency_acknowledgements;
create trigger trg_audit_emergency_acks
    after insert or update or delete on public.emergency_acknowledgements
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_emergency_esc_guard on public.emergency_escalations;
create trigger trg_emergency_esc_guard
    before insert or update on public.emergency_escalations
    for each row execute function public.trg_emergency_child_guard();

drop trigger if exists trg_audit_emergency_esc on public.emergency_escalations;
create trigger trg_audit_emergency_esc
    after insert or update or delete on public.emergency_escalations
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_emergency_resp_guard on public.emergency_responders;
create trigger trg_emergency_resp_guard
    before insert or update on public.emergency_responders
    for each row execute function public.trg_emergency_child_guard();

drop trigger if exists trg_audit_emergency_resp on public.emergency_responders;
create trigger trg_audit_emergency_resp
    after insert or update or delete on public.emergency_responders
    for each row execute function public.trg_audit_capture();

-- emergency_log: guard mirrors org/site from the event; audit capture fires
-- so stream writes are visible in the org audit trail too (trigger-sourced).
drop trigger if exists trg_emergency_log_guard on public.emergency_log;
create trigger trg_emergency_log_guard
    before insert or update on public.emergency_log
    for each row execute function public.trg_emergency_child_guard();

drop trigger if exists trg_audit_emergency_log on public.emergency_log;
create trigger trg_audit_emergency_log
    after insert or update or delete on public.emergency_log
    for each row execute function public.trg_audit_capture();

commit;
