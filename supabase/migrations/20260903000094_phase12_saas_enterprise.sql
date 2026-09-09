-- ============================================================================
-- MINEGUARD LIBERIA — Phase 12: SaaS + enterprise administration
-- (PROJECT_MASTER §10/§11 row 12; RBAC_MODEL "still open: platform membership
--  flows + per-org custom roles (Phase 12)"; Phase 06 recorded gap: sites
--  INSERT/UPDATE/DELETE had no tenant write path; Phase 11 recorded gaps:
--  grant expiry admin + server-side national roll-ups per non-negotiable #7.)
--
-- Scope of THIS migration (additive; no existing policy/policy-shape change):
--   1. plans + subscriptions (schema-modeled SaaS, billing NOT wired — the
--      plan gates nothing yet; feature-flag enforcement is a future phase).
--   2. org_settings: SECURITY DEFINER org-settings/branding write RPC
--      (settings.manage permission; org UPDATE gate stays owner/admin).
--   3. site_create / site_update / site_remove RPCs (sites.view/create/
--      update/delete permission codes; closes the Phase 06 sites write gap).
--   4. Grant expiry administration: p_expires_at on regulator_issue_grant
--      (with min > issued check) + regulator_extend_grant.
--   5. Platform administration: bootstrap_first_platform_admin (one-shot
--      claim of the first orgless 'platform' org), platform_list_organizations
--      (id+name+type+status only — no tenant data), platform_update_
--      organization_status (active<->suspended only, never delete).
--   6. gov_national_overview() — server-side aggregate over the caller's
--      ACTIVE grants ONLY (documented formulas: plain counts of distinct
--      rows, no derived/invented metrics), replacing client-side roll-ups.
--   7. RLS on the two new tables (authenticated SELECT for plans;
--      org-scoped subscriptions SELECT for owner/admin billing.view);
--      audit triggers on subscriptions via a trg_audit_capture branch.
-- All functions: SECURITY DEFINER, fixed search_path = public, PUBLIC EXECUTE
-- revoked, EXECUTE granted to authenticated (Phase 01 convention).
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. plans + subscriptions (SaaS model, billing deferred)
-- ---------------------------------------------------------------------------
create table public.plans (
    code        text primary key,              -- 'starter' | 'enterprise' | 'government'
    name        text not null,
    max_sites   int,
    max_users   int,
    features    jsonb not null default '{}'::jsonb,  -- feature-flag map (advisory only)
    sort_order  int not null default 0,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now()
);

comment on table public.plans is
    'Phase 12: SaaS plan catalog (modeled only — billing is NOT wired). features is an advisory flag map; nothing enforces it yet.';

insert into public.plans (code, name, max_sites, max_users, features, sort_order) values
    ('starter',    'Starter',           3,  25, '{"jsa":true,"incidents":true,"emergency":true,"notices":true}', 0),
    ('enterprise', 'Enterprise',        null, null, '{"jsa":true,"incidents":true,"emergency":true,"notices":true,"analytics":true,"api":true}', 1),
    ('government', 'Government',        null, null, '{"jsa":true,"incidents":true,"emergency":true,"notices":true,"analytics":true,"grants":true}', 2)
on conflict (code) do nothing;

create table public.subscriptions (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    plan_code       text not null references public.plans(code),
    status          text not null default 'active'
                    check (status in ('active', 'trialing', 'past_due', 'canceled')),
    current_period_start timestamptz not null default now(),
    current_period_end   timestamptz,            -- null = open-ended (pre-billing default)
    canceled_at     timestamptz,
    changed_by      uuid references auth.users(id) on delete set null,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

comment on table public.subscriptions is
    'Phase 12: per-organization plan subscription (modeled only — no billing provider). One active subscription per org; owner/admin changes are audited.';

-- One active subscription per organization (partial unique index; inline
-- partial UNIQUE constraints are not valid SQL).
create unique index subscriptions_one_active_idx
    on public.subscriptions (organization_id) where status in ('active', 'trialing');

create index subscriptions_organization_idx on public.subscriptions (organization_id, status);

drop trigger if exists trg_plans_updated_at on public.plans;
create trigger trg_plans_updated_at
    before update on public.plans
    for each row execute function public.set_updated_at();

drop trigger if exists trg_subscriptions_updated_at on public.subscriptions;
create trigger trg_subscriptions_updated_at
    before update on public.subscriptions
    for each row execute function public.set_updated_at();

-- Seed tenant #1 + the regulator org onto their plans (idempotent).
-- NOTE: organizations already exist; insert-only so a missing org is skipped.
insert into public.subscriptions (organization_id, plan_code)
select o.id, case when o.org_type = 'regulator' then 'government' else 'starter' end
from public.organizations o
where o.slug in ('arcelormittal-liberia', 'liberia-regulator')
  and not exists (
      select 1 from public.subscriptions s
      where s.organization_id = o.id and s.status in ('active', 'trialing')
  );

-- RLS: plans readable by authenticated; subscriptions readable by the org's
-- owner/admin (billing.view bundle) — membership-scoped, not world-readable.
alter table public.plans enable row level security;
alter table public.subscriptions enable row level security;

drop policy if exists plans_select_authenticated on public.plans;
create policy plans_select_authenticated on public.plans
    for select to authenticated
    using (true);

drop policy if exists subscriptions_select_org_admin on public.subscriptions;
create policy subscriptions_select_org_admin on public.subscriptions
    for select to authenticated
    using (
        public.auth_user_has_org_access(subscriptions.organization_id)
        and public.auth_user_has_permission(subscriptions.organization_id, 'billing.view')
    );

-- Writes default-deny on both tables; org subscription changes go through
-- org_update_subscription (owner/admin, billing.manage) so every change is
-- permission-checked and audit-captured.

-- ---------------------------------------------------------------------------
-- 2. org settings / branding write path (settings.manage)
-- ---------------------------------------------------------------------------
create or replace function public.org_update_settings(
    p_organization_id uuid,
    p_settings jsonb default null,
    p_branding jsonb default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authenticated organization management requires a session';
    end if;
    if p_settings is null and p_branding is null then
        raise exception 'P0001: nothing to update';
    end if;
    -- settings.manage is the documented owner/admin code for org settings.
    if not public.auth_user_has_permission(p_organization_id, 'settings.manage') then
        raise exception 'P0001: settings.manage permission required';
    end if;

    update public.organizations
    set settings = coalesce(p_settings, settings),
        branding = coalesce(p_branding, branding)
    where id = p_organization_id;
end;
$$;

comment on function public.org_update_settings(uuid, jsonb, jsonb) is
    'Phase 12: owner/admin (settings.manage) update of the org''s settings/branding JSONB. Server-side permission check; audit via trg_organizations_updated_at + audit capture of organizations rows.';

revoke all on function public.org_update_settings(uuid, jsonb, jsonb) from public;
grant execute on function public.org_update_settings(uuid, jsonb, jsonb) to authenticated;

-- ---------------------------------------------------------------------------
-- 3. Site management RPCs (Phase 06 gap: sites had no tenant write path)
-- ---------------------------------------------------------------------------
create or replace function public.site_create(
    p_organization_id uuid,
    p_name text,
    p_location text default null,
    p_county text default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_site_id uuid;
begin
    if auth.uid() is null then
        raise exception 'authenticated site management requires a session';
    end if;
    if p_name is null or length(trim(p_name)) = 0 then
        raise exception 'P0001: site name is required';
    end if;
    if not public.auth_user_has_permission(p_organization_id, 'sites.create') then
        raise exception 'P0001: sites.create permission required';
    end if;

    insert into public.sites (organization_id, name, location, county, created_by)
    values (p_organization_id, trim(p_name), p_location, p_county, auth.uid())
    returning id into v_site_id;
    return v_site_id;
end;
$$;

create or replace function public.site_update(
    p_site_id uuid,
    p_name text default null,
    p_location text default null,
    p_county text default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authenticated site management requires a session';
    end if;
    if not exists (
        select 1 from public.sites s
        where s.id = p_site_id
          and public.auth_user_has_permission(s.organization_id, 'sites.update')
    ) then
        raise exception 'P0001: sites.update permission required';
    end if;
    if p_name is not null and length(trim(p_name)) = 0 then
        raise exception 'P0001: site name cannot be empty';
    end if;

    update public.sites
    set name     = coalesce(trim(p_name), name),
        location = coalesce(p_location, location),
        county   = coalesce(p_county, county)
    where id = p_site_id;
end;
$$;

create or replace function public.site_remove(p_site_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authenticated site management requires a session';
    end if;
    if not exists (
        select 1 from public.sites s
        where s.id = p_site_id
          and public.auth_user_has_permission(s.organization_id, 'sites.delete')
    ) then
        raise exception 'P0001: sites.delete permission required';
    end if;

    -- Soft delete (sites.status check allows 'deleted'); dependent rows are
    -- NOT cascade-deleted here — site removal keeps safety records intact.
    update public.sites
    set status = 'deleted', deleted_at = now()
    where id = p_site_id and status <> 'deleted';
end;
$$;

comment on function public.site_create(uuid, text, text, text) is
    'Phase 12: org-admin site creation gated on sites.create. Closes the Phase 06 recorded gap (sites INSERT/UPDATE/DELETE had no tenant write path).';
comment on function public.site_update(uuid, text, text, text) is
    'Phase 12: site metadata update gated on sites.update.';
comment on function public.site_remove(uuid) is
    'Phase 12: soft site removal gated on sites.delete. Safety records are preserved; nothing cascades.';

revoke all on function public.site_create(uuid, text, text, text) from public;
revoke all on function public.site_update(uuid, text, text, text) from public;
revoke all on function public.site_remove(uuid) from public;
grant execute on function public.site_create(uuid, text, text, text) to authenticated;
grant execute on function public.site_update(uuid, text, text, text) to authenticated;
grant execute on function public.site_remove(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- 4. Subscription administration (owner/admin, billing.manage)
-- ---------------------------------------------------------------------------
create or replace function public.org_update_subscription(
    p_organization_id uuid,
    p_plan_code text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_id uuid;
begin
    if auth.uid() is null then
        raise exception 'authenticated subscription management requires a session';
    end if;
    if not public.auth_user_has_permission(p_organization_id, 'billing.manage') then
        raise exception 'P0001: billing.manage permission required';
    end if;
    if not exists (select 1 from public.plans where code = p_plan_code) then
        raise exception 'P0001: unknown plan code';
    end if;

    -- Close any open-ended active subscription, then upsert the new one.
    -- (One active row per org is enforced by subscriptions_one_active_idx.)
    insert into public.subscriptions (organization_id, plan_code, changed_by)
    values (p_organization_id, p_plan_code, auth.uid())
    on conflict (organization_id) where status in ('active', 'trialing')
    do update set plan_code = excluded.plan_code, changed_by = excluded.changed_by;
end;
$$;

comment on function public.org_update_subscription(uuid, text) is
    'Phase 12: owner/admin (billing.manage) plan change. Modeled only — no billing provider; changes are audit-captured via the subscriptions trigger.';

revoke all on function public.org_update_subscription(uuid, text) from public;
grant execute on function public.org_update_subscription(uuid, text) to authenticated;

-- ---------------------------------------------------------------------------
-- 5. Government grant expiry administration (Phase 11 recorded gap)
-- ---------------------------------------------------------------------------
-- Extend regulator_issue_grant with a validated expiry (keeps the same
-- signature plus a new defaulted argument — Postgres allows overloads, so we
-- replace the 4-arg version and add a 5-arg one; the client uses the 5-arg).
create or replace function public.regulator_issue_grant(
    p_target_org_id uuid,
    p_site_id uuid default null,
    p_scope text default null,
    p_regulator_user_id uuid default null,
    p_expires_at timestamptz default null
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
    if p_expires_at is not null and p_expires_at <= now() then
        raise exception 'P0001: grant expiry must be in the future';
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

    if not exists (
        select 1 from public.organization_members m
        where m.organization_id = v_regulator_org_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and m.role = 'national_regulatory_admin'
    ) then
        raise exception 'P0001: only the regulator org national_regulatory_admin may issue government grants';
    end if;

    if not exists (
        select 1 from public.organizations
        where id = p_target_org_id
          and org_type in ('mining_company', 'contractor')
    ) then
        raise exception 'P0001: target org is not a grantable organization type';
    end if;

    if p_site_id is not null and not exists (
        select 1 from public.sites
        where id = p_site_id and organization_id = p_target_org_id
    ) then
        raise exception 'P0001: site does not belong to the target organization';
    end if;

    v_regulator_user_id := coalesce(p_regulator_user_id, auth.uid());

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
         regulator_role, issued_by, expires_at)
    values
        (v_regulator_org_id, v_regulator_user_id, p_target_org_id, p_site_id,
         p_scope,
         (select m.role from public.organization_members m
          where m.organization_id = v_regulator_org_id and m.user_id = v_regulator_user_id
            and m.status = 'active' limit 1),
         auth.uid(), p_expires_at)
    on conflict (regulator_org_id, regulator_user_id, target_org_id, coalesce(site_id, '00000000-0000-0000-0000-000000000000'::uuid))
        where status = 'active'
        do update set
            site_id    = excluded.site_id,
            scope      = excluded.scope,
            issued_by  = excluded.issued_by,
            expires_at = excluded.expires_at,
            updated_at = now()
    where government_grants.status = 'active'
      and (government_grants.expires_at is null or government_grants.expires_at > now())
    returning id;
end;
$$;

comment on function public.regulator_issue_grant(uuid, uuid, text, uuid, timestamptz) is
    'Phase 12: adds validated expiry administration to Phase 11 grant issuance (expires_at must be in the future; re-issuance updates the expiry).';

revoke all on function public.regulator_issue_grant(uuid, uuid, text, uuid, timestamptz) from public;
grant execute on function public.regulator_issue_grant(uuid, uuid, text, uuid, timestamptz) to authenticated;

-- Extend (or clear) an active grant''s expiry — regulator org admin only.
create or replace function public.regulator_extend_grant(
    p_grant_id uuid,
    p_expires_at timestamptz default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authenticated grant management requires a session';
    end if;
    if p_expires_at is not null and p_expires_at <= now() then
        raise exception 'P0001: grant expiry must be in the future';
    end if;
    if not exists (
        select 1 from public.government_grants g
        where g.id = p_grant_id
          and g.status = 'active'
          and public.auth_user_has_org_access(g.regulator_org_id)
          and exists (
              select 1 from public.organization_members m
              where m.organization_id = g.regulator_org_id
                and m.user_id = auth.uid()
                and m.status = 'active'
                and m.role = 'national_regulatory_admin'
          )
    ) then
        raise exception 'P0001: only the issuing regulator org''s national_regulatory_admin may extend grants';
    end if;

    update public.government_grants
    set expires_at = p_expires_at
    where id = p_grant_id and status = 'active';
end;
$$;

comment on function public.regulator_extend_grant(uuid, timestamptz) is
    'Phase 12: extend (or clear) an active grant''s expiry. Null clears the expiry (open-ended). national_regulatory_admin of the issuing regulator org only.';

revoke all on function public.regulator_extend_grant(uuid, timestamptz) from public;
grant execute on function public.regulator_extend_grant(uuid, timestamptz) to authenticated;

-- ---------------------------------------------------------------------------
-- 6. Platform administration layer (RBAC_MODEL "still open: platform
--    membership flows (Phase 12)"). Deliberately minimal and audited:
--    listing exposes id/name/type/status only — never tenant safety data.
-- ---------------------------------------------------------------------------
create or replace function public.bootstrap_first_platform_admin()
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org_id uuid;
    v_user_id uuid := auth.uid();
begin
    if v_user_id is null then
        raise exception 'authenticated platform bootstrap requires a session';
    end if;

    -- One-shot per user: anyone holding ANY active membership is disqualified
    -- (mirrors the regulator bootstrap guard from fix …091).
    if exists (
        select 1 from public.organization_members m
        where m.user_id = v_user_id and m.status = 'active'
    ) then
        raise exception 'P0001: caller already holds an organization membership';
    end if;

    -- Claim the first ACTIVE platform org with no members.
    select o.id into v_org_id
    from public.organizations o
    where o.org_type = 'platform'
      and o.status = 'active'
      and not exists (
          select 1 from public.organization_members m
          where m.organization_id = o.id and m.status = 'active'
      )
    order by o.created_at asc
    limit 1;

    if v_org_id is null then
        raise exception 'no claimable platform organization available';
    end if;

    insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values (v_org_id, v_user_id, 'platform_super_admin', 'active', v_user_id)
    on conflict (organization_id, user_id) do nothing;

    return v_org_id;
end;
$$;

comment on function public.bootstrap_first_platform_admin() is
    'Phase 12: first user (with no memberships at all) claims the first memberless ACTIVE platform org as platform_super_admin. One-shot; orgless-only; never touches tenant orgs.';

revoke all on function public.bootstrap_first_platform_admin() from public;
grant execute on function public.bootstrap_first_platform_admin() to authenticated;

-- Platform operator directory: id/name/type/status/counties ONLY. No tenant
-- safety data, no member emails, no counts beyond coarse metadata. Platform
-- super admins (members of a platform org) only.
create or replace function public.platform_list_organizations()
returns table (
    id uuid,
    slug text,
    name text,
    org_type text,
    county text,
    status text,
    site_count bigint,
    member_count bigint
)
language sql
stable
security definer
set search_path = public
as $$
    with me as (
        select m.organization_id
        from public.organization_members m
        join public.roles r on r.code = m.role
        where m.user_id = auth.uid()
          and m.status = 'active'
          and r.scope = 'platform'
    )
    select o.id, o.slug, o.name, o.org_type, o.county, o.status,
           (select count(*) from public.sites s where s.organization_id = o.id and s.status <> 'deleted'),
           (select count(*) from public.organization_members m2 where m2.organization_id = o.id and m2.status = 'active')
    from public.organizations o
    where exists (select 1 from me)
      and o.status <> 'deleted'
    order by o.name asc;
$$;

comment on function public.platform_list_organizations() is
    'Phase 12: platform-super-admin directory of organizations — coarse metadata only (id/name/type/status/site+member counts); never tenant safety data.';

revoke all on function public.platform_list_organizations() from public;
grant execute on function public.platform_list_organizations() to authenticated;

-- Suspend / reactivate an organization (platform super admin only). Deletion
-- is deliberately NOT offered: org removal stays a service-role/DBA action.
create or replace function public.platform_update_organization_status(
    p_organization_id uuid,
    p_new_status text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        raise exception 'authenticated platform administration requires a session';
    end if;
    if p_new_status not in ('active', 'suspended') then
        raise exception 'P0001: only active/suspended transitions are permitted through the platform RPC';
    end if;
    if not exists (
        select 1
        from public.organization_members m
        join public.roles r on r.code = m.role
        where m.user_id = auth.uid()
          and m.status = 'active'
          and r.scope = 'platform'
    ) then
        raise exception 'P0001: platform-scope membership required';
    end if;

    update public.organizations
    set status = p_new_status
    where id = p_organization_id
      and org_type in ('mining_company', 'contractor')
      and status in ('active', 'suspended');
end;
$$;

comment on function public.platform_update_organization_status(uuid, text) is
    'Phase 12: platform super admin suspends/reactivates a mining/contractor org. Never deletes; regulator/platform orgs are out of scope.';

revoke all on function public.platform_update_organization_status(uuid, text) from public;
grant execute on function public.platform_update_organization_status(uuid, text) to authenticated;

-- ---------------------------------------------------------------------------
-- 7. gov_national_overview() — authorized server-side national roll-up
-- (GOVERNMENT_PLATFORM §5: computed over the union of the caller's ACTIVE
-- grants only; documented formulas = plain counts of distinct rows; no
-- derived/invented safety metrics per PROJECT_MASTER non-negotiable #7.)
-- ---------------------------------------------------------------------------
create or replace function public.gov_national_overview()
returns table (
    granted_orgs bigint,
    incidents_total bigint,
    incidents_open bigint,
    inspections_total bigint,
    capas_open bigint,
    emergency_total bigint,
    emergency_active bigint,
    sites_total bigint
)
language sql
stable
security definer
set search_path = public
as $$
    with my_grants as (
        select g.target_org_id
        from public.government_grants g
        where g.regulator_user_id = auth.uid()
          and g.status = 'active'
          and (g.expires_at is null or g.expires_at > now())
        group by g.target_org_id
    )
    select
        (select count(*) from my_grants),
        (select count(*) from public.incidents i where i.organization_id in (select target_org_id from my_grants) and i.deleted = false),
        (select count(*) from public.incidents i where i.organization_id in (select target_org_id from my_grants) and i.deleted = false and i.status not in ('RESOLVED', 'CLOSED')),
        (select count(*) from public.inspections ins where ins.organization_id in (select target_org_id from my_grants) and ins.deleted_at is null),
        (select count(*) from public.corrective_actions c where c.organization_id in (select target_org_id from my_grants) and c.deleted_at is null and c.status not in ('completed','cancelled')),
        (select count(*) from public.emergency_events e where e.organization_id in (select target_org_id from my_grants) and e.deleted = false),
        (select count(*) from public.emergency_events e where e.organization_id in (select target_org_id from my_grants) and e.deleted = false and e.status in ('ACTIVATED', 'ACKNOWLEDGED', 'RESPONDING')),
        (select count(*) from public.sites s where s.organization_id in (select target_org_id from my_grants) and s.status = 'active');
$$;

comment on function public.gov_national_overview() is
    'Phase 12: server-side national roll-up computed over the union of the caller''s ACTIVE government grants ONLY (grant intersection enforced here, not client-side). Counts are plain distinct-row counts (documented formulas); no derived safety metrics.';

revoke all on function public.gov_national_overview() from public;
grant execute on function public.gov_national_overview() to authenticated;

-- ---------------------------------------------------------------------------
-- 8. Audit coverage for subscriptions
-- ---------------------------------------------------------------------------
-- Deliberately a DEDICATED trigger function (not a rewrite of the shared
-- trg_audit_capture): the shared function's CASE body was extended by
-- migrations 07/08/09/11, and re-declaring it wholesale here risks silently
-- altering live audit branches. This additive pattern matches the Phase 06
-- fix …053 convention for late-added tables.
create or replace function public.trg_audit_subscriptions_capture()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into public.audit_log
        (organization_id, actor_user_id, actor_name, action, resource_type, resource_id, metadata, source)
    values
        (coalesce(new.organization_id, old.organization_id),
         auth.uid(),
         (select email::text from auth.users where id = auth.uid()),
         tg_op || '.' || tg_table_name,
         tg_table_name,
         coalesce(new.id, old.id)::text,
         jsonb_build_object(
             'plan_code', coalesce(new.plan_code, old.plan_code),
             'status', coalesce(new.status, old.status),
             'status_previous', old.status),
         'trigger');
    return coalesce(new, old);
end;
$$;

comment on function public.trg_audit_subscriptions_capture() is
    'Phase 12: audit capture for plan/subscription changes (plan code + status, org-scoped, actor from auth.uid()).';

drop trigger if exists trg_audit_subscriptions on public.subscriptions;
create trigger trg_audit_subscriptions
    after insert or update or delete on public.subscriptions
    for each row execute function public.trg_audit_subscriptions_capture();

-- ---------------------------------------------------------------------------
-- 9. Standard privileges (Phase 01 convention)
-- ---------------------------------------------------------------------------
grant select on public.plans to authenticated;
grant select on public.subscriptions to authenticated;

commit;
