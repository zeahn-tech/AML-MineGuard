-- ============================================================================
-- MINEGUARD LIBERIA — Phase 07: Incident + evidence management
-- Target database: Supabase (PostgreSQL 15+)
--
-- Implements RLS_MATRIX.md §1.2 (incidents / incident evidence / incident
-- witnesses rows) + MINING_DOMAIN_MODEL.md §2 (Incident / Evidence) on top of
-- the Phase 01–06 primitives (org/site scope helpers, RBAC permissions,
-- append-only audit_log). Also satisfies SECURITY_MODEL.md §2.6 requirement:
-- "incident create/modify/delete/restore" are audited server-side.
--
--   * incidents          — org-scoped safety event records. Every column
--                          carries org scope; the worker-facing free-text
--                          fields (reporter name/badge/dept, witnesses,
--                          location) are retained for fast offline capture
--                          and Phase 05 import compatibility (the mapper's
--                          target payload shape is a direct subset of this
--                          table's columns).
--   * incident_evidence  — object-storage references (photos/docs/videos).
--                          Media bytes live in the private `incident-evidence`
--                          bucket (migration …061); only refs live here.
--   * incident_witnesses — named witness records with statements.
--
-- Role/scope matrix implemented (RLS_MATRIX §1.2):
--   org-wide  view/create/update: owner, admin, safety_manager, safety_officer
--   site-     view/create/update: site_manager, supervisor (own site(s))
--   worker    create: own reports (reported_by_user_id forced to auth.uid());
--             view: own reports (+ rows flagged site_notice_scope at own site)
--   delete (hard) is owner/admin/safety_manager only (incidents.delete);
--             soft delete = UPDATE status/'deleted' by update-capable roles.
--   all writes are RLS-gated; no table grants bypass RLS.
--
-- Migration risk: additive only. The legacy anonymous Firebase worker channel
-- is untouched; incidents land in Supabase and cutover/import is Phase 05.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. incidents
-- ---------------------------------------------------------------------------
create table public.incidents (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    department_id   uuid references public.organizational_units(id) on delete set null,
    -- idempotency key: legacy Firestore _id (Phase 05 import) or client-generated
    -- id for offline-first writes (Phase 10). Unique so retries never duplicate.
    client_id       text unique,
    -- reporter identity. reported_by_user_id is set server-side from auth.uid()
    -- on insert (never client-supplied); reported_by_name/badge/dept_text are
    -- the worker-facing display copy captured at report time (legacy parity).
    reported_by_user_id uuid references auth.users(id) on delete set null,
    reported_by_name  text,
    badge             text,
    dept_text         text,
    incident_type     text not null,
    severity          text not null check (severity in ('low', 'medium', 'high', 'critical')),
    status            text not null default 'SUBMITTED' check (status in (
                          'DRAFT', 'SUBMITTED', 'ACKNOWLEDGED', 'UNDER_INVESTIGATION',
                          'CORRECTIVE_ACTION_REQUIRED', 'PENDING_VERIFICATION',
                          'RESOLVED', 'CLOSED')),
    incident_datetime timestamptz,             -- when the event occurred (legacy `datetime`)
    location_text     text,                    -- free-text location (legacy `location`)
    description       text not null,
    immediate_action  text,                    -- legacy `action`
    witnesses_text    text,                    -- legacy free-text witnesses
    lang              text not null default 'en',
    -- injuries / environment / equipment impact + investigation/closure notes
    impact_text       text,
    investigation_notes text,
    closure_notes     text,
    resolved_at       timestamptz,
    -- site-notice scope: when true, workers of the incident's site may read the
    -- record (RLS_MATRIX §1.2 worker "S(own + site-notice scope)") without ever
    -- exposing the org pool.
    site_notice_scope boolean not null default false,
    -- soft delete (Phase 12 purges / Phase 05 import parity)
    deleted           boolean not null default false,
    deleted_at        timestamptz,
    deleted_by        uuid references auth.users(id) on delete set null,
    saved_at          timestamptz,              -- legacy local save time (Phase 05 parity)
    legacy_status     text,                     -- original Firestore status preserved on import
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),
    created_by        uuid references auth.users(id) on delete set null
);

comment on table public.incidents is
    'Safety incident reports (MINING_DOMAIN_MODEL §2 Incident). organization_id is the security boundary; site_id/department_id place the event in the hierarchy. reported_by_user_id is set server-side from auth.uid() and never trusted from client input. Status lifecycle: DRAFT→SUBMITTED→ACKNOWLEDGED→UNDER_INVESTIGATION→CORRECTIVE_ACTION_REQUIRED→PENDING_VERIFICATION→RESOLVED→CLOSED.';

create index incidents_org_created_idx on public.incidents (organization_id, created_at desc);
create index incidents_site_idx     on public.incidents (site_id);
create index incidents_status_idx   on public.incidents (organization_id, status);
create index incidents_reporter_idx on public.incidents (reported_by_user_id);

drop trigger if exists trg_incidents_updated_at on public.incidents;
create trigger trg_incidents_updated_at
    before update on public.incidents
    for each row execute function public.set_updated_at();

-- Reporter + scope integrity:
--   * reported_by_user_id is forced to auth.uid() when the client omits it and
--     rejected when the client tries to attribute the report to someone else.
--   * site must belong to the org; department must belong to the org (+site).
drop trigger if exists trg_incidents_insert_guard on public.incidents;
create or replace function public.trg_incidents_insert_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    if tg_op = 'INSERT' then
        -- reporter identity is set server-side (never client-attributed)
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
        -- UPDATE: the reporter is historical and immutable — the database
        -- pins it to the original value so no editor can re-attribute it.
        new.reported_by_user_id := old.reported_by_user_id;
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
create trigger trg_incidents_insert_guard
    before insert or update on public.incidents
    for each row execute function public.trg_incidents_insert_guard();

-- ---------------------------------------------------------------------------
-- 2. incident_evidence (object-storage references)
-- ---------------------------------------------------------------------------
create table public.incident_evidence (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    incident_id     uuid not null references public.incidents(id) on delete cascade,
    storage_path    text not null unique,      -- object name inside incident-evidence bucket
    kind            text not null default 'photo' check (kind in ('photo', 'document', 'video', 'other')),
    content_type    text,
    size_bytes      bigint check (size_bytes is null or size_bytes >= 0),
    sha256          text,
    captured_at     timestamptz,
    uploaded_by     uuid references auth.users(id) on delete set null,
    created_at      timestamptz not null default now()
);

comment on table public.incident_evidence is
    'Object-storage references for incident media (MINING_DOMAIN_MODEL §2 Evidence). Bytes live in the private incident-evidence bucket keyed organizations/{org}/sites/{site}/incidents/{incident}/{file}; this table holds the reference + integrity metadata. organization_id/site_id mirror the incident server-side.';

create index incident_evidence_incident_idx on public.incident_evidence (incident_id);
create index incident_evidence_org_idx      on public.incident_evidence (organization_id);

-- Mirror the incident's org/site and the uploader server-side (never client).
drop trigger if exists trg_incident_evidence_scope on public.incident_evidence;
create or replace function public.trg_incident_evidence_scope()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    select organization_id, site_id into new.organization_id, new.site_id
    from public.incidents where id = new.incident_id;
    if new.organization_id is null then
        raise exception 'incident does not exist';
    end if;
    if new.uploaded_by is null and auth.uid() is not null then
        new.uploaded_by := auth.uid();
    end if;
    return new;
end;
$$;
create trigger trg_incident_evidence_scope
    before insert or update on public.incident_evidence
    for each row execute function public.trg_incident_evidence_scope();

-- ---------------------------------------------------------------------------
-- 3. incident_witnesses
-- ---------------------------------------------------------------------------
create table public.incident_witnesses (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    incident_id     uuid not null references public.incidents(id) on delete cascade,
    full_name       text not null,
    badge           text,
    role_text       text,                       -- e.g. 'eyewitness', 'first aider'
    statement       text,
    created_at      timestamptz not null default now(),
    created_by      uuid references auth.users(id) on delete set null
);

comment on table public.incident_witnesses is
    'Named witnesses/statements attached to an incident. organization_id/site_id mirror the incident server-side.';

create index incident_witnesses_incident_idx on public.incident_witnesses (incident_id);

drop trigger if exists trg_incident_witnesses_scope on public.incident_witnesses;
create or replace function public.trg_incident_witnesses_scope()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    select organization_id, site_id into new.organization_id, new.site_id
    from public.incidents where id = new.incident_id;
    if new.organization_id is null then
        raise exception 'incident does not exist';
    end if;
    if new.created_by is null and auth.uid() is not null then
        new.created_by := auth.uid();
    end if;
    return new;
end;
$$;
create trigger trg_incident_witnesses_scope
    before insert or update on public.incident_witnesses
    for each row execute function public.trg_incident_witnesses_scope();

-- ---------------------------------------------------------------------------
-- 4. Authorization helpers (SECURITY DEFINER policy primitives, Phase 07)
-- ---------------------------------------------------------------------------
-- RLS_MATRIX §1.2 roles:
--   owner/admin/safety_manager/safety_officer  → org-wide incident scope
--   site_manager/supervisor                    → rows of their own site(s)
--   worker/contractor                          → own reports (+ site_notice_scope)
--   member                                     → inert: no incident scope (documented)
--   anon/outsider                              → none
-- Effective role = org role (via auth_user_effective_role) or site role (via
-- auth_user_site_effective_role) at the row's site; site-only users (no org
-- membership) resolve through the site path (Phase 04 semantics).

create or replace function public.auth_user_can_view_incident(p_incident_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.incidents i
        where i.id = p_incident_id
          and (
              -- base gate: org member OR active member of the row's site
              public.auth_user_has_site_access(i.organization_id, i.site_id)
          )
          and (
              -- org-wide safety/management roles
              public.auth_user_effective_role(i.organization_id)
                  in ('owner', 'admin', 'safety_manager', 'safety_officer')
              -- site-scoped roles at this site
              or public.auth_user_site_effective_role(i.organization_id, i.site_id)
                  in ('site_manager', 'supervisor')
              -- own report
              or i.reported_by_user_id = auth.uid()
              -- site-notice scope: workers of the site may read broadcast rows
              or i.site_notice_scope
          )
    );
$$;

comment on function public.auth_user_can_view_incident(uuid) is
    'Phase 07: can the current user SELECT this incident? Matches RLS_MATRIX §1.2 (org-wide roles, site-scoped roles at the row site, own reports, site_notice_scope broadcast). SECURITY DEFINER so policies may call it without recursion; org/site integrity is enforced by the base gate.';

create or replace function public.auth_user_can_insert_incident(p_organization_id uuid, p_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.auth_user_has_site_access(p_organization_id, p_site_id)
       and (public.auth_user_has_permission(p_organization_id, 'incidents.create')
            or public.auth_user_has_site_permission(p_organization_id, p_site_id, 'incidents.create'));
$$;

comment on function public.auth_user_can_insert_incident(uuid, uuid) is
    'Phase 07: can the current user submit an incident in this org/site? Anyone with incidents.create at org or site scope (worker/contractor included), gated by org/site membership.';

create or replace function public.auth_user_can_update_incident(p_incident_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.incidents i
        where i.id = p_incident_id
          and public.auth_user_has_site_access(i.organization_id, i.site_id)
          and (
              public.auth_user_effective_role(i.organization_id)
                  in ('owner', 'admin', 'safety_manager', 'safety_officer')
              or public.auth_user_site_effective_role(i.organization_id, i.site_id)
                  in ('site_manager', 'supervisor')
          )
    );
$$;

comment on function public.auth_user_can_update_incident(uuid) is
    'Phase 07: can the current user UPDATE/soft-delete this incident? Org-wide safety roles + site roles at the row site (RLS_MATRIX §1.2 U column); workers never update (their row is read-only after submission).';

create or replace function public.auth_user_can_delete_incident(p_incident_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.incidents i
        where i.id = p_incident_id
          and public.auth_user_has_org_access(i.organization_id)
          and public.auth_user_has_permission(i.organization_id, 'incidents.delete')
    );
$$;

comment on function public.auth_user_can_delete_incident(uuid) is
    'Phase 07: hard-DELETE gate (incidents.delete = owner/admin/safety_manager bundles). Normal removal is soft-delete via UPDATE by update-capable roles; this is the audited purge path only.';

create or replace function public.auth_user_can_insert_incident_evidence(p_incident_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.incidents i
        where i.id = p_incident_id
          and (i.reported_by_user_id = auth.uid()
               or public.auth_user_can_update_incident(p_incident_id))
    );
$$;

comment on function public.auth_user_can_insert_incident_evidence(uuid) is
    'Phase 07: can the current user attach evidence/witnesses to this incident? Reporters (I(own)) and all update-capable roles (RLS_MATRIX §1.2 evidence/witnesses INSERT columns).';

revoke all on function public.auth_user_can_view_incident(uuid) from public;
revoke all on function public.auth_user_can_insert_incident(uuid, uuid) from public;
revoke all on function public.auth_user_can_update_incident(uuid) from public;
revoke all on function public.auth_user_can_delete_incident(uuid) from public;
revoke all on function public.auth_user_can_insert_incident_evidence(uuid) from public;
grant execute on function public.auth_user_can_view_incident(uuid) to anon, authenticated;
grant execute on function public.auth_user_can_insert_incident(uuid, uuid) to anon, authenticated;
grant execute on function public.auth_user_can_update_incident(uuid) to anon, authenticated;
grant execute on function public.auth_user_can_delete_incident(uuid) to anon, authenticated;
grant execute on function public.auth_user_can_insert_incident_evidence(uuid) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- 5. RLS policies (RLS_MATRIX §1.2)
-- ---------------------------------------------------------------------------
alter table public.incidents enable row level security;
alter table public.incident_evidence enable row level security;
alter table public.incident_witnesses enable row level security;

-- incidents ----------------------------------------------------------------
drop policy if exists incidents_select on public.incidents;
create policy incidents_select on public.incidents
    for select to authenticated
    using (public.auth_user_can_view_incident(id));

drop policy if exists incidents_insert on public.incidents;
create policy incidents_insert on public.incidents
    for insert to authenticated
    with check (public.auth_user_can_insert_incident(organization_id, site_id));

drop policy if exists incidents_update on public.incidents;
create policy incidents_update on public.incidents
    for update to authenticated
    using (public.auth_user_can_update_incident(id))
    with check (public.auth_user_can_update_incident(id)
                and public.auth_user_can_insert_incident(organization_id, site_id));

drop policy if exists incidents_delete on public.incidents;
create policy incidents_delete on public.incidents
    for delete to authenticated
    using (public.auth_user_can_delete_incident(id));

-- incident_evidence --------------------------------------------------------
drop policy if exists incident_evidence_select on public.incident_evidence;
create policy incident_evidence_select on public.incident_evidence
    for select to authenticated
    using (public.auth_user_can_view_incident(incident_id));

drop policy if exists incident_evidence_insert on public.incident_evidence;
create policy incident_evidence_insert on public.incident_evidence
    for insert to authenticated
    with check (public.auth_user_can_insert_incident_evidence(incident_id));

drop policy if exists incident_evidence_update on public.incident_evidence;
create policy incident_evidence_update on public.incident_evidence
    for update to authenticated
    using (public.auth_user_can_update_incident(incident_id))
    with check (public.auth_user_can_update_incident(incident_id));

drop policy if exists incident_evidence_delete on public.incident_evidence;
create policy incident_evidence_delete on public.incident_evidence
    for delete to authenticated
    using (public.auth_user_can_delete_incident(incident_id));

-- incident_witnesses -------------------------------------------------------
drop policy if exists incident_witnesses_select on public.incident_witnesses;
create policy incident_witnesses_select on public.incident_witnesses
    for select to authenticated
    using (public.auth_user_can_view_incident(incident_id));

drop policy if exists incident_witnesses_insert on public.incident_witnesses;
create policy incident_witnesses_insert on public.incident_witnesses
    for insert to authenticated
    with check (public.auth_user_can_insert_incident_evidence(incident_id));

drop policy if exists incident_witnesses_update on public.incident_witnesses;
create policy incident_witnesses_update on public.incident_witnesses
    for update to authenticated
    using (public.auth_user_can_update_incident(incident_id))
    with check (public.auth_user_can_update_incident(incident_id));

-- witnesses have no DELETE policy (RLS_MATRIX §1.2 witnesses D column is
-- blank across all org roles); edits go through UPDATE, removals are handled
-- by incident lifecycle, and purge is an audited Phase 12 path.

-- ---------------------------------------------------------------------------
-- 6. Grants (base + RLS filtering, Supabase convention as Phases 01/04/06)
-- ---------------------------------------------------------------------------
grant select on table public.incidents, public.incident_evidence, public.incident_witnesses
    to anon, authenticated;
grant insert, update, delete on table public.incidents, public.incident_evidence, public.incident_witnesses
    to authenticated;
-- anon may SELECT only what RLS exposes (nothing, without a session);
-- authenticated DML is fully gated by the policies above.

-- ---------------------------------------------------------------------------
-- 7. Server-side audit for the safety domain (SECURITY_MODEL §2.6: incident
--    create/modify/delete/restore; evidence uploads; witness records)
-- ---------------------------------------------------------------------------
-- Re-create trg_audit_capture() with the Phase 07 branches, preserving every
-- Phase 06 branch + the org-scope nulling fix (…051/…052) verbatim.
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
        when 'incidents' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            -- no description/photo bytes in audit (curated metadata only);
            -- no invite-style secrets exist on this table
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
            -- storage_path deliberately omitted (object key not needed in audit)
        when 'incident_witnesses' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'incident_id', coalesce(new.incident_id, old.incident_id),
                'full_name', coalesce(new.full_name, old.full_name),
                'badge', coalesce(new.badge, old.badge));
            -- statement text omitted (PII beyond the name)
        else
            return null;
    end case;

    -- Tenant scope is only valid while the org exists. When the org is being
    -- removed (its own delete, or the cascade-delete of its child rows), null
    -- it so the append-only audit record is still written and never violates
    -- the FK. Retained as platform-scope history (organization_id = null).
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
    return null; -- AFTER trigger: result unused
end;
$$;

comment on function public.trg_audit_capture() is
    'Phase 06/07: server-side audit capture for tenant-management AND safety-domain tables (org memberships/sites/units/workers/invites/orgs + incidents/evidence/witnesses). Actor = auth.uid() (null under service-role writes). Append-only: inserts into audit_log only; never raises. organization_id is nulled when the referenced org no longer exists (org deletion / cascade), preserving the record with platform scope.';

drop trigger if exists trg_audit_incidents on public.incidents;
create trigger trg_audit_incidents
    after insert or update or delete on public.incidents
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_audit_incident_evidence on public.incident_evidence;
create trigger trg_audit_incident_evidence
    after insert or update or delete on public.incident_evidence
    for each row execute function public.trg_audit_capture();

drop trigger if exists trg_audit_incident_witnesses on public.incident_witnesses;
create trigger trg_audit_incident_witnesses
    after insert or update or delete on public.incident_witnesses
    for each row execute function public.trg_audit_capture();

commit;