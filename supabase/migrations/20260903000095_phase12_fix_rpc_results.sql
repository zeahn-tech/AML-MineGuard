-- ============================================================================
-- Phase 12 fix migration — probe-driven repairs (convention: …091–…093)
--
-- 1. regulator_issue_grant (5-arg): plpgsql `insert … returning id;` without
--    an INTO target raises 42601 "query has no destination for result data".
--    Capture into a variable, then return it.
-- 2. trg_audit_subscriptions_capture: inserted into audit_log.resource_type,
--    which does not exist (audit_log columns are `resource`, `resource_id`).
--    Every subscription change therefore failed with 42703. Corrected to the
--    real audit_log schema.
-- 3. platform_list_organizations: returned an empty row set (HTTP 200 []) for
--    non-platform callers. Raise P0001 instead — unauthorized invocation must
--    be explicit, not silently empty (SECURITY_MODEL §API security).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Fix grant-issue result capture
-- ---------------------------------------------------------------------------
-- Also drop the legacy 4-arg overload: with both 4-arg and 5-arg variants
-- present, PostgREST cannot resolve partial named-argument calls (PGRST203).
-- One canonical 5-arg signature with defaults (probe-driven fix).
drop function if exists public.regulator_issue_grant(uuid, uuid, text, uuid);

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
    v_grant_id uuid;
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
    returning id into v_grant_id;

    return v_grant_id;
end;
$$;

comment on function public.regulator_issue_grant(uuid, uuid, text, uuid, timestamptz) is
    'Phase 12 (fix …095): adds validated expiry administration to Phase 11 grant issuance; fixes plpgsql result capture (returning id into variable).';

revoke all on function public.regulator_issue_grant(uuid, uuid, text, uuid, timestamptz) from public;
grant execute on function public.regulator_issue_grant(uuid, uuid, text, uuid, timestamptz) to authenticated;

-- ---------------------------------------------------------------------------
-- 2. Fix subscription audit capture (real audit_log columns)
-- ---------------------------------------------------------------------------
create or replace function public.trg_audit_subscriptions_capture()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into public.audit_log
        (organization_id, actor_user_id, actor_name, action, resource, resource_id, metadata, source)
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
    'Phase 12 (fix …095): audit capture for plan/subscription changes using the real audit_log columns (resource/resource_id).';

drop trigger if exists trg_audit_subscriptions on public.subscriptions;
create trigger trg_audit_subscriptions
    after insert or update or delete on public.subscriptions
    for each row execute function public.trg_audit_subscriptions_capture();

-- ---------------------------------------------------------------------------
-- 3. Platform listing must explicitly reject non-platform callers
-- ---------------------------------------------------------------------------
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
language plpgsql
stable
security definer
set search_path = public
as $$
begin
    -- language sql functions cannot raise; explicit gate here (probe-driven fix).
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

    return query
    select o.id, o.slug, o.name, o.org_type, o.county, o.status,
           (select count(*) from public.sites s where s.organization_id = o.id and s.status <> 'deleted'),
           (select count(*) from public.organization_members m2 where m2.organization_id = o.id and m2.status = 'active')
    from public.organizations o
    where o.status <> 'deleted'
    order by o.name asc;
end;
$$;

comment on function public.platform_list_organizations() is
    'Phase 12 (fix …095): platform-scope membership required — non-platform callers receive an explicit P0001 error rather than an empty tenant list.';

revoke all on function public.platform_list_organizations() from public;
grant execute on function public.platform_list_organizations() to authenticated;
