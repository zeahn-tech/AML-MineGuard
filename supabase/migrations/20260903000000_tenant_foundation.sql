-- ============================================================================
-- MINEGUARD LIBERIA — Phase 01: Multi-tenant organization database foundation
-- Target database: Supabase (PostgreSQL 15+) — decided 2026-09-03 (DECISIONS.md ADR-008)
--
-- Scope of THIS migration (Phase 01 only):
--   * organizations / sites / organization_members (the tenancy backbone)
--   * reusable SQL authorization helpers (authz layer that RLS policies and
--     future phases call — Phase 03 RBAC, Phase 06 full RLS_MATRIX policies)
--   * RLS ENABLED on tenancy tables with minimal membership policies so tenant
--     boundaries exist from day one. Full per-table policy matrix lands in
--     Phase 06; safety-domain tables arrive in Phases 04-09.
--
-- Conventions (see docs/engineering/DATABASE_ARCHITECTURE.md, RLS_MATRIX.md):
--   * every tenant-owned table carries organization_id (uuid, NOT NULL, FK)
--   * soft delete via status/deleted_at + deleted_by, mirroring legacy behavior
--   * updated_at maintained by triggers
--   * server/service_role is the only writer of org/membership rows until the
--     Phase 02/04 onboarding flows land (no INSERT policies for end users yet)
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- Organizations — the hard tenant boundary
-- ---------------------------------------------------------------------------
create table public.organizations (
    id          uuid primary key default gen_random_uuid(),
    slug        text not null unique,          -- url-safe identifier; immutable
    name        text not null,
    county      text,
    org_type    text not null default 'mining_company'
                check (org_type in ('mining_company', 'contractor', 'regulator', 'platform')),
    status      text not null default 'active'
                check (status in ('active', 'suspended', 'deleted')),
    deleted_at  timestamptz,
    settings    jsonb not null default '{}'::jsonb,  -- org-scoped settings (risk matrix later)
    branding    jsonb not null default '{}'::jsonb,  -- org identity: name/logo/colors (Phase 04/12)
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    created_by  uuid references auth.users(id) on delete set null
);

comment on table public.organizations is
    'Tenant root. Every org-owned record in the platform references organizations.id via organization_id.';

create unique index organizations_name_lower_uidx on public.organizations (lower(name));

-- ---------------------------------------------------------------------------
-- Sites — physical locations inside an organization
-- ---------------------------------------------------------------------------
create table public.sites (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    name            text not null,
    location        text,
    county          text,
    status          text not null default 'active'
                    check (status in ('active', 'inactive', 'deleted')),
    deleted_at      timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    created_by      uuid references auth.users(id) on delete set null,
    unique (organization_id, name)
);

comment on table public.sites is
    'Sites belong to exactly one organization; organization_id is the security scope.';

create index sites_organization_id_idx on public.sites (organization_id);
create index sites_organization_created_idx on public.sites (organization_id, created_at desc);

-- ---------------------------------------------------------------------------
-- Organization members — user <-> org membership (roles simplified for Phase 01;
-- full RBAC roles/permissions land in Phase 03 and will replace this column).
-- ---------------------------------------------------------------------------
create table public.organization_members (
    organization_id uuid not null references public.organizations(id) on delete cascade,
    user_id         uuid not null references auth.users(id) on delete cascade,
    role            text not null default 'member'
                    check (role in ('owner', 'admin', 'member')),  -- Phase 03 expands this
    status          text not null default 'active'
                    check (status in ('active', 'invited', 'suspended', 'removed')),
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    created_by      uuid references auth.users(id) on delete set null,
    primary key (organization_id, user_id)
);

comment on table public.organization_members is
    'Who belongs to which organization and at what standing. Only active members have tenant access.';

create index organization_members_user_id_idx on public.organization_members (user_id);

-- ---------------------------------------------------------------------------
-- updated_at trigger helper + triggers
-- ---------------------------------------------------------------------------
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

drop trigger if exists trg_organizations_updated_at on public.organizations;
create trigger trg_organizations_updated_at
    before update on public.organizations
    for each row execute function public.set_updated_at();

drop trigger if exists trg_sites_updated_at on public.sites;
create trigger trg_sites_updated_at
    before update on public.sites
    for each row execute function public.set_updated_at();

drop trigger if exists trg_organization_members_updated_at on public.organization_members;
create trigger trg_organization_members_updated_at
    before update on public.organization_members
    for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- Authorization helpers (the reusable authz layer; callable from RLS policies,
-- RPCs, and future phases). SECURITY DEFINER + fixed search_path so policies can
-- use them without recursion/leakage. Equivalent of the documented
-- auth_user_has_org_access() / auth_user_is_org_admin() functions.
-- ---------------------------------------------------------------------------
create or replace function public.current_user_org_ids()
returns setof uuid
language sql
stable
security definer
set search_path = public
as $$
    select m.organization_id
    from public.organization_members m
    where m.user_id = auth.uid()
      and m.status = 'active';
$$;

comment on function public.current_user_org_ids() is
    'Set of organization ids the current user is an ACTIVE member of. Security definer (owner privileges).';

create or replace function public.auth_user_has_org_access(p_organization_id uuid)
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
    );
$$;

comment on function public.auth_user_has_org_access(uuid) is
    'True when the current user is an active member of the given organization.';

create or replace function public.auth_user_is_org_admin(p_organization_id uuid)
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
          and m.role in ('owner', 'admin')
    );
$$;

comment on function public.auth_user_is_org_admin(uuid) is
    'True when the current user is an owner/admin of the given organization. Role model expands in Phase 03.';

revoke all on function public.current_user_org_ids() from public;
revoke all on function public.auth_user_has_org_access(uuid) from public;
revoke all on function public.auth_user_is_org_admin(uuid) from public;
grant execute on function public.current_user_org_ids() to authenticated;
grant execute on function public.auth_user_has_org_access(uuid) to authenticated;
grant execute on function public.auth_user_is_org_admin(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Row Level Security — enabled and enforced from Phase 01 on tenancy tables.
-- Inserts/updates/deletes are intentionally service-role/admin-only for now
-- (no end-user org-creation flows yet); SELECT follows membership.
-- Full matrix: docs/engineering/RLS_MATRIX.md (Phase 06 wires the rest).
-- ---------------------------------------------------------------------------
alter table public.organizations enable row level security;
alter table public.sites enable row level security;
alter table public.organization_members enable row level security;

-- organizations: members may read their own organization(s).
drop policy if exists "org_select_members" on public.organizations;
create policy org_select_members on public.organizations
    for select
    to authenticated
    using (public.auth_user_has_org_access(id));

-- sites: read follows org membership.
drop policy if exists "sites_select_org_members" on public.sites;
create policy sites_select_org_members on public.sites
    for select
    to authenticated
    using (public.auth_user_has_org_access(organization_id));

-- organization_members: read own membership row or rows of an org you belong to
-- (helper is SECURITY DEFINER, so no recursive policy evaluation here).
drop policy if exists "members_select_self_or_org" on public.organization_members;
create policy members_select_self_or_org on public.organization_members
    for select
    to authenticated
    using (
        user_id = auth.uid()
        or public.auth_user_has_org_access(organization_id)
    );

-- Default-deny posture for authenticated writes on tenancy tables is implicit:
-- no INSERT/UPDATE/DELETE policies exist, so only table owners / service_role
-- (bypass RLS) can write. Onboarding flows in Phase 02/04 will add narrowly
-- scoped policies (e.g., first-admin self-provisioning) after review.

commit;
