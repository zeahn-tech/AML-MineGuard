-- ============================================================
-- Phase 13 — Production hardening (2026-09-10)
--
-- Closes the two Phase 12 recorded hardening gaps:
--   1. `site_create` did not enforce the organization's plan
--      `plans.max_sites` (Phase 12 known limitation). The RPC now
--      counts the org's ACTIVE (non-soft-deleted) sites and rejects
--      creation once the active plan's cap is reached. Enterprise /
--      Government plans have max_sites = null (unlimited).
--   2. Government grants with `expires_at` in the past kept
--      `status = 'active'` forever (reads already excluded them via
--      `expires_at > now()`, but the record never lapsed —
--      Phase 12 known limitation "no expiry sweep job").
--      `regulator_expire_due_grants()` is the audited sweep: it
--      flips all due active grants to `expired` (idempotent) and
--      returns the number lapsed. Safe to run on a schedule
--      (cron/pg_cron) or on demand by a national_regulatory_admin.
--
-- Conventions preserved: SECURITY DEFINER + fixed search_path,
-- explicit auth gates, additive-only (the shared audit trigger is
-- NOT rewritten; government_grants UPDATE audit capture already
-- exists from Phase 11, so every sweep lapse is audited).
-- ============================================================

-- 1. site_create WITH max_sites enforcement (replace in place —
--    same 4-arg signature, no overload: PostgREST PGRST203 lesson
--    from Phase 12).
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
    v_max_sites int;
    v_site_count int;
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

    -- Phase 13: enforce the organization's active plan site cap.
    -- Unlimited when no active subscription exists (pre-SaaS tenant,
    -- e.g. tenant #1 before billing) or when the plan caps at null.
    select p.max_sites into v_max_sites
    from public.subscriptions s
    join public.plans p on p.code = s.plan_code
    where s.organization_id = p_organization_id
      and s.status = 'active'
    order by s.created_at desc
    limit 1;

    if v_max_sites is not null then
        select count(*) into v_site_count
        from public.sites
        where organization_id = p_organization_id
          and status <> 'deleted';
        if v_site_count >= v_max_sites then
            raise exception 'P0001: plan site limit reached (%) — upgrade the subscription to add more sites',
                v_max_sites;
        end if;
    end if;

    insert into public.sites (organization_id, name, location, county, created_by)
    values (p_organization_id, trim(p_name), p_location, p_county, auth.uid())
    returning id into v_site_id;
    return v_site_id;
end;
$$;

comment on function public.site_create(uuid, text, text, text) is
'Phase 12/13: creates a site (sites.create permission required) and enforces the organization''s active plan max_sites cap (null = unlimited; no active subscription = unlimited until billing).';

-- 2. Grant expiry sweep — audited, idempotent, safe for scheduled runs.
create or replace function public.regulator_expire_due_grants()
returns int
language plpgsql
security definer
set search_path = public
as $$
declare
    v_expired int := 0;
begin
    -- Callable by the platform scheduler (no session / service role)
    -- or by a seated national_regulatory_admin. Everyone else denied.
    if auth.uid() is not null then
        if not exists (
            select 1
            from public.organization_members m
            join public.organizations o on o.id = m.organization_id
            where m.user_id = auth.uid()
              and m.status = 'active'
              and m.role = 'national_regulatory_admin'
              and o.org_type = 'regulator'
              and o.status = 'active'
        ) then
            raise exception 'P0001: national_regulatory_admin of a regulator organization required';
        end if;
    end if;

    update public.government_grants
    set status = 'expired'
    where status = 'active'
      and expires_at is not null
      and expires_at <= now();
    get diagnostics v_expired = row_count;
    return v_expired;
end;
$$;

comment on function public.regulator_expire_due_grants() is
'Phase 13: flips all active government_grants whose expires_at has passed to expired (idempotent; returns the count lapsed). Each lapse is captured by the existing government_grants audit trigger. Callable by the platform scheduler (no session) or a national_regulatory_admin.';

revoke all on function public.regulator_expire_due_grants() from public;
grant execute on function public.regulator_expire_due_grants() to authenticated;
