-- ============================================================================
-- MINEGUARD LIBERIA — Phase 04: Mining company + site hierarchy
-- Target database: Supabase (PostgreSQL 15+)
--
-- Implements the hierarchy + org-admin flows documented in
-- docs/engineering/MINING_DOMAIN_MODEL.md and RBAC_MODEL.md §1.4/§1.5:
--
--   * organizational_units — departments / teams / work zones
--     (one self-referencing table; unit_type + parent_id model the
--     Organization → Site → Department → Team/Work Zone drill-down)
--   * site_members — site-scoped memberships. Roles reuse the SAME role
--     codes as organization_members (owner…member) so the RBAC join layer
--     (roles.role_permissions) works unchanged.
--   * workers — the worker registry (safety profile: employee id, site,
--     department/team, classification, contact, status; user_id links a
--     worker to a platform identity when one exists — Phase 05+ mapping).
--   * org_invites — email invites for org-admin member onboarding. No email
--     infra yet (Phase 09/13): the admin shares the returned token/link; the
--     invited user claims it with org_accept_invite(). A provider hookup
--     later only replaces how the token is delivered.
--
-- Authorization:
--   * NEW site-scoped helpers:
--       auth_user_site_effective_role(org, site) -> role | null
--       auth_user_has_site_access(org, site)      -> boolean
--       auth_user_has_site_permission(org, site, perm) -> boolean (max of
--         org role and site role at that site — RBAC_MODEL §1.5)
--   * auth_user_has_permission / auth_user_permissions are UPGRADED to the
--     max(org role, site role) semantics: for an active ORG member, site
--     memberships inside that org may widen scope. Site-only members (no org
--     membership) get site-scoped access through the *_site_* helpers only —
--     they never obtain org-scope via the site row (no privilege escalation).
--   * New permission codes: organizational_units.create / .update (catalog
--     grows 60 → 62; owner/admin/safety_manager get create+update,
--     safety_officer/site_manager get update).
--   * All tenant writes go through SECURITY DEFINER RPCs that re-check
--     authorization server-side (owner/admin gate for member management,
--     site-scoped site_manager gate for site members and units of their
--     site). Direct table writes remain default-deny for end users; full
--     per-table RLS_MATRIX policies still land in Phase 06.
--
-- Tenant isolation: every table carries organization_id; SELECT policies are
-- membership-scoped; the probe suite (scripts/verify-phase04.mjs) proves
-- Company A can never see Company B's hierarchy/members/workers/invites.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. Permission catalog additions (domain: organizational_units)
-- ---------------------------------------------------------------------------
insert into public.permissions (code, domain, description) values
    ('organizational_units.create', 'organizational_units', 'Create departments/teams/work zones'),
    ('organizational_units.update', 'organizational_units', 'Update/soft-delete departments/teams/work zones')
on conflict (code) do nothing;

insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code in ('owner', 'admin', 'safety_manager')
  and p.code = 'organizational_units.create'
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code in ('owner', 'admin', 'safety_manager', 'safety_officer', 'site_manager')
  and p.code = 'organizational_units.update'
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- 2. Organizational units (departments / teams / work zones)
-- ---------------------------------------------------------------------------
create table public.organizational_units (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid not null references public.sites(id) on delete cascade,
    parent_id       uuid references public.organizational_units(id) on delete set null,
    unit_type       text not null check (unit_type in ('department', 'team', 'work_zone')),
    name            text not null,
    code            text,                                   -- optional short code (e.g. 'MIN-PIT3')
    status          text not null default 'active'
                    check (status in ('active', 'inactive', 'deleted')),
    deleted_at      timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    created_by      uuid references auth.users(id) on delete set null,
    unique (organization_id, site_id, name)
);

comment on table public.organizational_units is
    'Departments / teams / work zones (MINING_DOMAIN_MODEL §1-§2). One table, parent_id + unit_type model the hierarchy. organization_id is the security scope.';

create index organizational_units_org_idx      on public.organizational_units (organization_id);
create index organizational_units_site_idx     on public.organizational_units (site_id);
create index organizational_units_parent_idx   on public.organizational_units (parent_id);

drop trigger if exists trg_organizational_units_updated_at on public.organizational_units;
create trigger trg_organizational_units_updated_at
    before update on public.organizational_units
    for each row execute function public.set_updated_at();

-- A unit's parent must live in the same organization AND the same site.
create or replace function public.trg_organizational_units_scope()
returns trigger
language plpgsql
as $$
declare
    v_parent_site uuid;
begin
    if new.parent_id is not null then
        select site_id into v_parent_site
        from public.organizational_units
        where id = new.parent_id;
        if v_parent_site is distinct from new.site_id then
            raise exception 'parent unit must belong to the same site';
        end if;
        if not exists (
            select 1 from public.organizational_units
            where id = new.parent_id and organization_id = new.organization_id
        ) then
            raise exception 'parent unit must belong to the same organization';
        end if;
    end if;
    return new;
end;
$$;

drop trigger if exists trg_organizational_units_scope on public.organizational_units;
create trigger trg_organizational_units_scope
    before insert or update on public.organizational_units
    for each row execute function public.trg_organizational_units_scope();

-- ---------------------------------------------------------------------------
-- 3. Site members (site-scoped roles; role codes = organization role codes)
-- ---------------------------------------------------------------------------
create table public.site_members (
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid not null references public.sites(id) on delete cascade,
    user_id         uuid not null references auth.users(id) on delete cascade,
    role            text not null default 'member'
                    check (role in (
                        'owner', 'admin', 'safety_manager', 'safety_officer',
                        'site_manager', 'supervisor', 'worker', 'contractor', 'member'
                    )),
    status          text not null default 'active'
                    check (status in ('active', 'invited', 'suspended', 'removed')),
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    created_by      uuid references auth.users(id) on delete set null,
    primary key (site_id, user_id)
);

comment on table public.site_members is
    'Site-scoped memberships (RBAC_MODEL §1.4/§1.5). Roles reuse organization role codes; effective permission = max(org role, site role). organization_id mirrors the site so tenant queries/indexes stay cheap.';

create index site_members_org_idx       on public.site_members (organization_id);
create index site_members_user_id_idx   on public.site_members (user_id);

drop trigger if exists trg_site_members_updated_at on public.site_members;
create trigger trg_site_members_updated_at
    before update on public.site_members
    for each row execute function public.set_updated_at();

-- The membership row must never contradict its site's organization.
create or replace function public.trg_site_members_org_match()
returns trigger
language plpgsql
as $$
begin
    if not exists (
        select 1 from public.sites
        where id = new.site_id and organization_id = new.organization_id
    ) then
        raise exception 'site does not belong to the given organization';
    end if;
    return new;
end;
$$;

drop trigger if exists trg_site_members_org_match on public.site_members;
create trigger trg_site_members_org_match
    before insert or update on public.site_members
    for each row execute function public.trg_site_members_org_match();

-- ---------------------------------------------------------------------------
-- 4. Workers (worker registry / safety profile)
-- ---------------------------------------------------------------------------
create table public.workers (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete cascade,
    department_id   uuid references public.organizational_units(id) on delete set null,
    team_id         uuid references public.organizational_units(id) on delete set null,
    user_id         uuid references auth.users(id) on delete set null,  -- platform identity link (Phase 05+)
    employee_id     text,                                               -- badge / employee number
    full_name       text not null,
    classification  text not null default 'employee'
                    check (classification in ('employee', 'contractor', 'other')),
    contact_phone   text,
    status          text not null default 'active'
                    check (status in ('active', 'suspended', 'terminated', 'deleted')),
    deleted_at      timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    created_by      uuid references auth.users(id) on delete set null,
    unique (organization_id, employee_id)
);

comment on table public.workers is
    'Worker registry (MINING_DOMAIN_MODEL §2 Worker). organization_id is the security scope; site/department/team place the worker in the hierarchy. user_id links to a platform identity when one exists.';

create index workers_org_idx            on public.workers (organization_id);
create index workers_site_idx           on public.workers (site_id);
create index workers_department_idx     on public.workers (department_id);
create index workers_user_id_idx        on public.workers (user_id);

drop trigger if exists trg_workers_updated_at on public.workers;
create trigger trg_workers_updated_at
    before update on public.workers
    for each row execute function public.set_updated_at();

-- site/department/team references must agree with each other and the org.
create or replace function public.trg_workers_scope()
returns trigger
language plpgsql
as $$
declare
    v_site_id uuid;
begin
    -- department and team (when both set) must belong to the same site
    if new.department_id is not null and new.team_id is not null then
        select site_id into v_site_id
        from public.organizational_units where id = new.department_id;
        if v_site_id is distinct from (
            select site_id from public.organizational_units where id = new.team_id
        ) then
            raise exception 'department and team must belong to the same site';
        end if;
    end if;
    -- a unit reference implies a site reference to the same site
    for v_site_id in
        select u.site_id from public.organizational_units u
        where u.id in (new.department_id, new.team_id) and u.id is not null
    loop
        if new.site_id is null then
            raise exception 'site_id is required when department/team is set';
        end if;
        if v_site_id is distinct from new.site_id then
            raise exception 'department/team must belong to the worker''s site';
        end if;
    end loop;
    -- site must belong to the org
    if new.site_id is not null and not exists (
        select 1 from public.sites where id = new.site_id and organization_id = new.organization_id
    ) then
        raise exception 'site does not belong to the given organization';
    end if;
    return new;
end;
$$;

drop trigger if exists trg_workers_scope on public.workers;
create trigger trg_workers_scope
    before insert or update on public.workers
    for each row execute function public.trg_workers_scope();

-- ---------------------------------------------------------------------------
-- 5. Org invites (email-based onboarding)
-- ---------------------------------------------------------------------------
create table public.org_invites (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete cascade,
    email           text not null,
    role            text not null check (role in (
                        'owner', 'admin', 'safety_manager', 'safety_officer',
                        'site_manager', 'supervisor', 'worker', 'contractor', 'member'
                    )),
    token           text not null unique,
    status          text not null default 'pending'
                    check (status in ('pending', 'accepted', 'revoked', 'expired')),
    expires_at      timestamptz not null default (now() + interval '7 days'),
    invited_by      uuid references auth.users(id) on delete set null,
    accepted_by     uuid references auth.users(id) on delete set null,
    accepted_at     timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

comment on table public.org_invites is
    'Email invites for org-admin onboarding (Phase 04). Tokens are one-time secrets; org_accept_invite() verifies the caller''s email matches. Email delivery provider hooks in later (Phase 09/13).';

create index org_invites_org_idx      on public.org_invites (organization_id);
create index org_invites_email_idx    on public.org_invites (email);
create index org_invites_status_idx   on public.org_invites (organization_id, status);

-- one pending invite per (org, email)
create unique index org_invites_pending_uidx on public.org_invites (organization_id, lower(email))
    where status = 'pending';

drop trigger if exists trg_org_invites_updated_at on public.org_invites;
create trigger trg_org_invites_updated_at
    before update on public.org_invites
    for each row execute function public.set_updated_at();

create or replace function public.trg_org_invites_site_org_match()
returns trigger
language plpgsql
as $$
begin
    if new.site_id is not null and not exists (
        select 1 from public.sites
        where id = new.site_id and organization_id = new.organization_id
    ) then
        raise exception 'site does not belong to the given organization';
    end if;
    return new;
end;
$$;

drop trigger if exists trg_org_invites_site_org_match on public.org_invites;
create trigger trg_org_invites_site_org_match
    before insert or update on public.org_invites
    for each row execute function public.trg_org_invites_site_org_match();

-- ---------------------------------------------------------------------------
-- 6. Site-scoped authorization helpers
-- ---------------------------------------------------------------------------
create or replace function public.auth_user_site_effective_role(p_organization_id uuid, p_site_id uuid)
returns text
language sql
stable
security definer
set search_path = public
as $$
    select coalesce(
        (select sm.role
         from public.site_members sm
         where sm.organization_id = p_organization_id
           and sm.site_id = p_site_id
           and sm.user_id = auth.uid()
           and sm.status = 'active'
         limit 1),
        (select m.role
         from public.organization_members m
         where m.organization_id = p_organization_id
           and m.user_id = auth.uid()
           and m.status = 'active'
         limit 1)
    );
$$;

comment on function public.auth_user_site_effective_role(uuid, uuid) is
    'Phase 04: effective role at a site = site role if an active site membership exists, else the org role (RBAC_MODEL §1.5). Null when neither exists.';

create or replace function public.auth_user_has_site_access(p_organization_id uuid, p_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.organization_members m
        where m.organization_id = p_organization_id
          and m.user_id = auth.uid()
          and m.status = 'active'
    )
    or exists (
        select 1
        from public.site_members sm
        where sm.organization_id = p_organization_id
          and sm.site_id = p_site_id
          and sm.user_id = auth.uid()
          and sm.status = 'active'
    );
$$;

comment on function public.auth_user_has_site_access(uuid, uuid) is
    'Phase 04: true when the current user is an active org member OR an active member of the given site.';

create or replace function public.auth_user_has_site_permission(p_organization_id uuid, p_site_id uuid, p_permission text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.site_members sm
        join public.roles r            on r.code = sm.role
        join public.role_permissions rp on rp.role_id = r.id
        join public.permissions p      on p.id = rp.permission_id
        where sm.organization_id = p_organization_id
          and sm.site_id = p_site_id
          and sm.user_id = auth.uid()
          and sm.status = 'active'
          and p.code = p_permission
    )
    or exists (
        select 1
        from public.organization_members m
        join public.roles r            on r.code = m.role
        join public.role_permissions rp on rp.role_id = r.id
        join public.permissions p      on p.id = rp.permission_id
        where m.organization_id = p_organization_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and p.code = p_permission
    );
$$;

comment on function public.auth_user_has_site_permission(uuid, uuid, text) is
    'Phase 04: max(org role, site role) permission check at a specific site. This is the primitive Phase 06 policies use for site-scoped rows.';

-- Upgrade the org-scope primitives to the max(org role, site role) semantics:
-- an ACTIVE ORG MEMBER may be widened by site memberships inside the org;
-- site-only users (no org membership) never gain org-scope from site rows.
create or replace function public.auth_user_has_permission(p_organization_id uuid, p_permission text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.organization_members m
        join public.roles r            on r.code = m.role
        join public.role_permissions rp on rp.role_id = r.id
        join public.permissions p      on p.id = rp.permission_id
        where m.organization_id = p_organization_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and p.code = p_permission
    )
    or exists (
        -- site role widens scope only for users who already hold an org membership
        select 1
        from public.organization_members m
        join public.site_members sm
          on sm.organization_id = m.organization_id
         and sm.user_id = m.user_id
        join public.roles r            on r.code = sm.role
        join public.role_permissions rp on rp.role_id = r.id
        join public.permissions p      on p.id = rp.permission_id
        where m.organization_id = p_organization_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and sm.status = 'active'
          and p.code = p_permission
    );
$$;

comment on function public.auth_user_has_permission(uuid, text) is
    'Phase 03/04 RBAC: true when the current user''s ACTIVE ORG role — or an active SITE role (only for org members) — holds the permission. Site-only users resolve via auth_user_has_site_permission. The primitive Phase 06 policies call.';

create or replace function public.auth_user_permissions(p_organization_id uuid)
returns setof text
language sql
stable
security definer
set search_path = public
as $$
    select distinct p.code
    from public.organization_members m
    join public.roles r            on r.code = m.role
    join public.role_permissions rp on rp.role_id = r.id
    join public.permissions p      on p.id = rp.permission_id
    where m.organization_id = p_organization_id
      and m.user_id = auth.uid()
      and m.status = 'active'
    union
    select distinct p.code
    from public.organization_members m
    join public.site_members sm
      on sm.organization_id = m.organization_id
     and sm.user_id = m.user_id
    join public.roles r            on r.code = sm.role
    join public.role_permissions rp on rp.role_id = r.id
    join public.permissions p      on p.id = rp.permission_id
    where m.organization_id = p_organization_id
      and m.user_id = auth.uid()
      and m.status = 'active'
      and sm.status = 'active';
$$;

comment on function public.auth_user_permissions(uuid) is
    'Phase 03/04: the current user''s permission codes within the organization (org role ∪ site roles, org membership required).';

revoke all on function public.auth_user_site_effective_role(uuid, uuid) from public;
revoke all on function public.auth_user_has_site_access(uuid, uuid) from public;
revoke all on function public.auth_user_has_site_permission(uuid, uuid, text) from public;
grant execute on function public.auth_user_site_effective_role(uuid, uuid) to anon, authenticated;
grant execute on function public.auth_user_has_site_access(uuid, uuid) to anon, authenticated;
grant execute on function public.auth_user_has_site_permission(uuid, uuid, text) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- 7. Internal gate helpers (invoked inside SECURITY DEFINER RPCs; no grants
--    to end-user roles — they are called only within definer context)
-- ---------------------------------------------------------------------------
create or replace function public.require_org_admin(p_organization_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.auth_user_is_org_admin(p_organization_id) then
        raise exception 'access denied: organization administrator role required';
    end if;
end;
$$;

create or replace function public.require_org_permission(p_organization_id uuid, p_permission text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.auth_user_has_permission(p_organization_id, p_permission) then
        raise exception 'access denied: missing permission %', p_permission;
    end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- 8. Organization member management RPCs (owner/admin only)
-- ---------------------------------------------------------------------------
create or replace function public.org_add_member(p_organization_id uuid, p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_active_owner_exists boolean;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    perform public.require_org_admin(p_organization_id);

    if not exists (select 1 from auth.users where id = p_user_id) then
        raise exception 'user does not exist';
    end if;
    if p_role not in ('owner','admin','safety_manager','safety_officer','site_manager',
                      'supervisor','worker','contractor','member') then
        raise exception 'invalid role: %', p_role;
    end if;

    -- Only the current owner may create another owner, and only if none exists.
    if p_role = 'owner' then
        select exists (
            select 1 from public.organization_members
            where organization_id = p_organization_id and role = 'owner' and status = 'active'
        ) into v_active_owner_exists;
        if v_active_owner_exists then
            raise exception 'an active owner already exists for this organization';
        end if;
        if not exists (
            select 1 from public.organization_members
            where organization_id = p_organization_id and user_id = auth.uid()
              and role = 'owner' and status = 'active'
        ) then
            raise exception 'access denied: only the organization owner can grant ownership';
        end if;
    end if;

    insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values (p_organization_id, p_user_id, p_role, 'active', auth.uid())
    on conflict (organization_id, user_id) do update
        set role = excluded.role, status = 'active', updated_at = now();
end;
$$;

create or replace function public.org_update_member_role(p_organization_id uuid, p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_is_target_owner boolean;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    perform public.require_org_admin(p_organization_id);

    if p_role not in ('owner','admin','safety_manager','safety_officer','site_manager',
                      'supervisor','worker','contractor','member') then
        raise exception 'invalid role: %', p_role;
    end if;

    select exists (
        select 1 from public.organization_members
        where organization_id = p_organization_id and user_id = p_user_id
          and role = 'owner' and status = 'active'
    ) into v_is_target_owner;
    if v_is_target_owner then
        raise exception 'the organization owner cannot be re-role or removed';
    end if;

    update public.organization_members
    set role = p_role, updated_at = now()
    where organization_id = p_organization_id and user_id = p_user_id;
end;
$$;

create or replace function public.org_remove_member(p_organization_id uuid, p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    perform public.require_org_admin(p_organization_id);

    if exists (
        select 1 from public.organization_members
        where organization_id = p_organization_id and user_id = p_user_id
          and role = 'owner' and status = 'active'
    ) then
        raise exception 'the organization owner cannot be removed';
    end if;

    update public.organization_members
    set status = 'removed', updated_at = now()
    where organization_id = p_organization_id and user_id = p_user_id;

    -- withdraw site memberships along with the org membership
    update public.site_members
    set status = 'removed', updated_at = now()
    where organization_id = p_organization_id and user_id = p_user_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- 9. Site member management RPCs (owner/admin org-wide; site_manager for own
--    site via sites.update)
-- ---------------------------------------------------------------------------
create or replace function public.site_assign_member(p_organization_id uuid, p_site_id uuid, p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    if not public.auth_user_is_org_admin(p_organization_id)
       and not public.auth_user_has_site_permission(p_organization_id, p_site_id, 'sites.update') then
        raise exception 'access denied: organization administrator or site manager role required';
    end if;

    if not exists (select 1 from auth.users where id = p_user_id) then
        raise exception 'user does not exist';
    end if;
    if not exists (select 1 from public.sites where id = p_site_id and organization_id = p_organization_id) then
        raise exception 'site does not belong to the given organization';
    end if;
    if p_role not in ('owner','admin','safety_manager','safety_officer','site_manager',
                      'supervisor','worker','contractor','member') then
        raise exception 'invalid role: %', p_role;
    end if;

    insert into public.site_members (organization_id, site_id, user_id, role, status, created_by)
    values (p_organization_id, p_site_id, p_user_id, p_role, 'active', auth.uid())
    on conflict (site_id, user_id) do update
        set role = excluded.role, status = 'active', updated_at = now();
end;
$$;

create or replace function public.site_remove_member(p_organization_id uuid, p_site_id uuid, p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    if not public.auth_user_is_org_admin(p_organization_id)
       and not public.auth_user_has_site_permission(p_organization_id, p_site_id, 'sites.update') then
        raise exception 'access denied: organization administrator or site manager role required';
    end if;

    update public.site_members
    set status = 'removed', updated_at = now()
    where organization_id = p_organization_id and site_id = p_site_id and user_id = p_user_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- 10. Invite flows
-- ---------------------------------------------------------------------------
create or replace function public.org_send_invite(p_organization_id uuid, p_email text, p_role text, p_site_id uuid)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
    v_email  text := lower(trim(p_email));
    v_token  text := encode(gen_random_bytes(24), 'hex');
    v_uid    uuid;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    perform public.require_org_admin(p_organization_id);

    if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
        raise exception 'invalid email address';
    end if;
    if p_role not in ('owner','admin','safety_manager','safety_officer','site_manager',
                      'supervisor','worker','contractor','member') then
        raise exception 'invalid role: %', p_role;
    end if;
    if p_role = 'owner' then
        raise exception 'ownership is granted by an existing owner, not by invite';
    end if;
    if p_site_id is not null and not exists (
        select 1 from public.sites where id = p_site_id and organization_id = p_organization_id
    ) then
        raise exception 'site does not belong to the given organization';
    end if;

    -- If the invited person already has an account, refuse duplicate invites.
    select id into v_uid from auth.users where lower(email) = v_email limit 1;
    if v_uid is not null and exists (
        select 1 from public.organization_members
        where organization_id = p_organization_id and user_id = v_uid and status <> 'removed'
    ) then
        raise exception 'user is already a member of this organization';
    end if;

    insert into public.org_invites (organization_id, site_id, email, role, token, invited_by)
    values (p_organization_id, p_site_id, v_email, p_role, v_token, auth.uid())
    on conflict (organization_id, lower(email)) where status = 'pending'
        do update set role = excluded.role, site_id = excluded.site_id,
                      token = excluded.token, expires_at = excluded.expires_at,
                      invited_by = excluded.invited_by, updated_at = now()
    returning token into v_token;

    return v_token;
end;
$$;

create or replace function public.org_accept_invite(p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_invite public.org_invites%rowtype;
    v_email  text;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;

    select * into v_invite from public.org_invites where token = p_token;
    if not found then
        raise exception 'invite not found';
    end if;
    if v_invite.status <> 'pending' then
        raise exception 'invite is no longer pending';
    end if;
    if v_invite.expires_at < now() then
        update public.org_invites set status = 'expired', updated_at = now()
        where id = v_invite.id;
        raise exception 'invite has expired';
    end if;

    select email into v_email from auth.users where id = auth.uid();
    if v_email is null or lower(v_email) <> lower(v_invite.email) then
        raise exception 'invite is not addressed to this account';
    end if;

    insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values (v_invite.organization_id, auth.uid(), v_invite.role, 'active', v_invite.invited_by)
    on conflict (organization_id, user_id) do update
        set role = excluded.role, status = 'active', updated_at = now();

    if v_invite.site_id is not null then
        insert into public.site_members (organization_id, site_id, user_id, role, status, created_by)
        values (v_invite.organization_id, v_invite.site_id, auth.uid(), v_invite.role, 'active', v_invite.invited_by)
        on conflict (site_id, user_id) do update
            set role = excluded.role, status = 'active', updated_at = now();
    end if;

    update public.org_invites
    set status = 'accepted', accepted_by = auth.uid(), accepted_at = now(), updated_at = now()
    where id = v_invite.id;
end;
$$;

create or replace function public.org_revoke_invite(p_organization_id uuid, p_invite_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    perform public.require_org_admin(p_organization_id);

    update public.org_invites
    set status = 'revoked', updated_at = now()
    where id = p_invite_id and organization_id = p_organization_id and status = 'pending';
end;
$$;

-- ---------------------------------------------------------------------------
-- 11. Hierarchy (organizational units) management RPCs
-- ---------------------------------------------------------------------------
create or replace function public.org_create_unit(p_organization_id uuid, p_site_id uuid,
    p_parent_id uuid, p_unit_type text, p_name text, p_code text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_id uuid;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    if not public.auth_user_is_org_admin(p_organization_id)
       and not public.auth_user_has_permission(p_organization_id, 'organizational_units.create') then
        raise exception 'access denied: organization administrator or safety manager role required';
    end if;

    if not exists (select 1 from public.sites where id = p_site_id and organization_id = p_organization_id) then
        raise exception 'site does not belong to the given organization';
    end if;
    if p_unit_type not in ('department', 'team', 'work_zone') then
        raise exception 'invalid unit type: %', p_unit_type;
    end if;
    if nullif(trim(p_name), '') is null then
        raise exception 'unit name is required';
    end if;

    insert into public.organizational_units
        (organization_id, site_id, parent_id, unit_type, name, code, created_by)
    values
        (p_organization_id, p_site_id, p_parent_id, p_unit_type, trim(p_name), nullif(trim(p_code), ''), auth.uid())
    returning id into v_id;

    return v_id;
end;
$$;

create or replace function public.org_update_unit(p_unit_id uuid, p_name text, p_code text, p_status text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org uuid;
    v_site uuid;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;

    select organization_id, site_id into v_org, v_site
    from public.organizational_units where id = p_unit_id;
    if not found then
        raise exception 'unit not found';
    end if;
    if not public.auth_user_is_org_admin(v_org)
       and not public.auth_user_has_site_permission(v_org, v_site, 'organizational_units.update') then
        raise exception 'access denied: organization administrator or site manager role required';
    end if;
    if p_status is not null and p_status not in ('active', 'inactive', 'deleted') then
        raise exception 'invalid status: %', p_status;
    end if;

    update public.organizational_units
    set name     = coalesce(nullif(trim(p_name), ''), name),
        code     = coalesce(nullif(trim(p_code), ''), code),
        status   = coalesce(p_status, status),
        deleted_at = case when p_status = 'deleted' then now() else deleted_at end,
        updated_at = now()
    where id = p_unit_id;
end;
$$;

create or replace function public.org_remove_unit(p_unit_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    perform public.org_update_unit(p_unit_id, null, null, 'deleted');
end;
$$;

-- ---------------------------------------------------------------------------
-- 12. Worker registry RPCs (owner/admin via workers.manage)
-- ---------------------------------------------------------------------------
create or replace function public.worker_add(p_organization_id uuid, p_site_id uuid,
    p_department_id uuid, p_team_id uuid, p_user_id uuid, p_employee_id text,
    p_full_name text, p_classification text, p_contact_phone text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_id uuid;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    perform public.require_org_permission(p_organization_id, 'workers.manage');

    if nullif(trim(p_full_name), '') is null then
        raise exception 'worker full name is required';
    end if;
    if p_classification not in ('employee', 'contractor', 'other') then
        raise exception 'invalid classification: %', p_classification;
    end if;
    if p_user_id is not null and not exists (select 1 from auth.users where id = p_user_id) then
        raise exception 'linked user does not exist';
    end if;

    insert into public.workers
        (organization_id, site_id, department_id, team_id, user_id, employee_id,
         full_name, classification, contact_phone, created_by)
    values
        (p_organization_id, p_site_id, p_department_id, p_team_id, p_user_id,
         nullif(trim(p_employee_id), ''), trim(p_full_name), p_classification,
         nullif(trim(p_contact_phone), ''), auth.uid())
    returning id into v_id;

    return v_id;
end;
$$;

create or replace function public.worker_update(p_worker_id uuid, p_site_id uuid,
    p_department_id uuid, p_team_id uuid, p_employee_id text, p_full_name text,
    p_classification text, p_contact_phone text, p_status text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org uuid;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;

    select organization_id into v_org from public.workers where id = p_worker_id;
    if not found then
        raise exception 'worker not found';
    end if;
    perform public.require_org_permission(v_org, 'workers.manage');

    if p_status is not null and p_status not in ('active', 'suspended', 'terminated', 'deleted') then
        raise exception 'invalid status: %', p_status;
    end if;

    update public.workers
    set site_id       = coalesce(p_site_id, site_id),
        department_id = coalesce(p_department_id, department_id),
        team_id       = coalesce(p_team_id, team_id),
        employee_id   = coalesce(nullif(trim(p_employee_id), ''), employee_id),
        full_name     = coalesce(nullif(trim(p_full_name), ''), full_name),
        classification= coalesce(p_classification, classification),
        contact_phone = coalesce(nullif(trim(p_contact_phone), ''), contact_phone),
        status        = coalesce(p_status, status),
        deleted_at    = case when p_status = 'deleted' then now() else deleted_at end,
        updated_at    = now()
    where id = p_worker_id;
end;
$$;

create or replace function public.worker_remove(p_worker_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org uuid;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    select organization_id into v_org from public.workers where id = p_worker_id;
    if not found then
        raise exception 'worker not found';
    end if;
    perform public.require_org_permission(v_org, 'workers.manage');
    perform public.worker_update(p_worker_id, null, null, null, null, null, null, null, 'deleted');
end;
$$;

-- ---------------------------------------------------------------------------
-- 13. Member listing with emails (org members may view their org's people)
-- ---------------------------------------------------------------------------
create or replace function public.org_list_members(p_organization_id uuid)
returns table (user_id uuid, email text, role text, status text, created_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null or not public.auth_user_has_org_access(p_organization_id) then
        raise exception 'access denied: organization membership required';
    end if;
    return query
        select m.user_id, u.email, m.role, m.status, m.created_at
        from public.organization_members m
        left join auth.users u on u.id = m.user_id
        where m.organization_id = p_organization_id
        order by m.created_at asc;
end;
$$;

-- ---------------------------------------------------------------------------
-- 14. RLS on the four new tables
-- ---------------------------------------------------------------------------
alter table public.organizational_units enable row level security;
alter table public.site_members enable row level security;
alter table public.workers enable row level security;
alter table public.org_invites enable row level security;

drop policy if exists "units_select_org_members" on public.organizational_units;
create policy units_select_org_members on public.organizational_units
    for select to authenticated
    using (public.auth_user_has_org_access(organization_id));

drop policy if exists "site_members_select_self_or_org" on public.site_members;
create policy site_members_select_self_or_org on public.site_members
    for select to authenticated
    using (
        user_id = auth.uid()
        or public.auth_user_has_org_access(organization_id)
    );

drop policy if exists "workers_select_org_members" on public.workers;
create policy workers_select_org_members on public.workers
    for select to authenticated
    using (public.auth_user_has_org_access(organization_id));

drop policy if exists "invites_select_org_members" on public.org_invites;
create policy invites_select_org_members on public.org_invites
    for select to authenticated
    using (public.auth_user_has_org_access(organization_id));

-- Writes on all four tables stay default-deny for end users: the org-admin /
-- site-manager flows above are the ONLY tenant write paths (SECURITY DEFINER
-- with explicit authorization checks). Phase 06 may convert selective paths
-- to RLS policies; the RPCs remain valid either way.

-- ---------------------------------------------------------------------------
-- 15. Privileges (base grants + RLS filtering, Supabase convention)
-- ---------------------------------------------------------------------------
grant select on table public.organizational_units, public.site_members, public.workers, public.org_invites
    to anon, authenticated;
grant insert, update, delete on table public.organizational_units, public.site_members, public.workers, public.org_invites
    to authenticated;

-- Default EXECUTE on new functions goes to PUBLIC; remove it so anon (and
-- anything not explicitly granted) gets no callable surface on these RPCs.
revoke all on function public.require_org_admin(uuid) from public;
revoke all on function public.require_org_permission(uuid, text) from public;
revoke all on function public.org_add_member(uuid, uuid, text) from public;
revoke all on function public.org_update_member_role(uuid, uuid, text) from public;
revoke all on function public.org_remove_member(uuid, uuid) from public;
revoke all on function public.site_assign_member(uuid, uuid, uuid, text) from public;
revoke all on function public.site_remove_member(uuid, uuid, uuid) from public;
revoke all on function public.org_send_invite(uuid, text, text, uuid) from public;
revoke all on function public.org_accept_invite(text) from public;
revoke all on function public.org_revoke_invite(uuid, uuid) from public;
revoke all on function public.org_create_unit(uuid, uuid, uuid, text, text, text) from public;
revoke all on function public.org_update_unit(uuid, text, text, text) from public;
revoke all on function public.org_remove_unit(uuid) from public;
revoke all on function public.worker_add(uuid, uuid, uuid, uuid, uuid, text, text, text, text) from public;
revoke all on function public.worker_update(uuid, uuid, uuid, uuid, text, text, text, text, text) from public;
revoke all on function public.worker_remove(uuid) from public;
revoke all on function public.org_list_members(uuid) from public;
-- authz helper grants (anon returns false/null — consistent with Phase 03)
-- (the §6 block already grants them; kept here as explicit documentation)
grant execute on function public.require_org_admin(uuid) to authenticated;
grant execute on function public.require_org_permission(uuid, text) to authenticated;
grant execute on function public.org_add_member(uuid, uuid, text) to authenticated;
grant execute on function public.org_update_member_role(uuid, uuid, text) to authenticated;
grant execute on function public.org_remove_member(uuid, uuid) to authenticated;
grant execute on function public.site_assign_member(uuid, uuid, uuid, text) to authenticated;
grant execute on function public.site_remove_member(uuid, uuid, uuid) to authenticated;
grant execute on function public.org_send_invite(uuid, text, text, uuid) to authenticated;
grant execute on function public.org_accept_invite(text) to authenticated;
grant execute on function public.org_revoke_invite(uuid, uuid) to authenticated;
grant execute on function public.org_create_unit(uuid, uuid, uuid, text, text, text) to authenticated;
grant execute on function public.org_update_unit(uuid, text, text, text) to authenticated;
grant execute on function public.org_remove_unit(uuid) to authenticated;
grant execute on function public.worker_add(uuid, uuid, uuid, uuid, uuid, text, text, text, text) to authenticated;
grant execute on function public.worker_update(uuid, uuid, uuid, uuid, text, text, text, text, text) to authenticated;
grant execute on function public.worker_remove(uuid) to authenticated;
grant execute on function public.org_list_members(uuid) to authenticated;

revoke all on function public.org_add_member(uuid, uuid, text) from anon;
revoke all on function public.org_update_member_role(uuid, uuid, text) from anon;
revoke all on function public.org_remove_member(uuid, uuid) from anon;
revoke all on function public.site_assign_member(uuid, uuid, uuid, text) from anon;
revoke all on function public.site_remove_member(uuid, uuid, uuid) from anon;
revoke all on function public.org_send_invite(uuid, text, text, uuid) from anon;
revoke all on function public.org_accept_invite(text) from anon;
revoke all on function public.org_revoke_invite(uuid, uuid) from anon;
revoke all on function public.org_create_unit(uuid, uuid, uuid, text, text, text) from anon;
revoke all on function public.org_update_unit(uuid, text, text, text) from anon;
revoke all on function public.org_remove_unit(uuid) from anon;
revoke all on function public.worker_add(uuid, uuid, uuid, uuid, uuid, text, text, text, text) from anon;
revoke all on function public.worker_update(uuid, uuid, uuid, uuid, text, text, text, text, text) from anon;
revoke all on function public.worker_remove(uuid) from anon;
revoke all on function public.org_list_members(uuid) from anon;

commit;