-- ============================================================================
-- MINEGUARD LIBERIA — Phase 11 fix 3: regulator_issue_grant result capture
--
-- Defect found by the Phase 11 live probe (2026-09-03): the INSERT inside
-- regulator_issue_grant used RETURNING id without an INTO target, which is
-- invalid in plpgsql ("query has no destination for result data", 42601) —
-- every grant issuance failed at runtime even though authorization passed.
--
-- Fix: capture the returned id into a variable and RETURN it.
-- Authorization logic unchanged; no data changes.
-- ============================================================================

create or replace function public.regulator_issue_grant(
    p_target_org_id uuid,
    p_site_id uuid default null,
    p_scope text default null,
    p_regulator_user_id uuid default null
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

    -- Only national_regulatory_admin can issue grants.
    if not exists (
        select 1 from public.organization_members m
        where m.organization_id = v_regulator_org_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and m.role = 'national_regulatory_admin'
    ) then
        raise exception 'P0001: only the regulator org national_regulatory_admin may issue government grants';
    end if;

    -- Target org must exist and not be a regulator/platform org (regulators
    -- grant access TO mining/contractor orgs; regulators do not grant access
    -- to other regulators via this RPC).
    if not exists (
        select 1 from public.organizations
        where id = p_target_org_id
          and org_type in ('mining_company', 'contractor')
    ) then
        raise exception 'P0001: target org is not a grantable organization type';
    end if;

    -- If a site is specified, it must belong to the target org.
    if p_site_id is not null and not exists (
        select 1 from public.sites
        where id = p_site_id and organization_id = p_target_org_id
    ) then
        raise exception 'P0001: site does not belong to the target organization';
    end if;

    v_regulator_user_id := coalesce(p_regulator_user_id, auth.uid());

    -- The regulator user must already be an active government member of the
    -- regulator org (you cannot issue grants for someone not in your regulator org).
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
         regulator_role, issued_by)
    values
        (v_regulator_org_id, v_regulator_user_id, p_target_org_id, p_site_id,
         p_scope,
         (select m.role from public.organization_members m
          where m.organization_id = v_regulator_org_id and m.user_id = v_regulator_user_id
            and m.status = 'active' limit 1),
         auth.uid())
    on conflict (regulator_org_id, regulator_user_id, target_org_id, coalesce(site_id, '00000000-0000-0000-0000-000000000000'::uuid))
        where status = 'active'
        do update set
            site_id   = excluded.site_id,
            scope     = excluded.scope,
            issued_by = excluded.issued_by,
            updated_at = now()
    returning id into v_grant_id;

    return v_grant_id;
end;
$$;

comment on function public.regulator_issue_grant(uuid, uuid, text, uuid) is
    'Phase 11: issue (or reactivate) a government grant from the caller''s regulator org to a target mining/contractor org (optionally site-scoped). Only national_regulatory_admin of the regulator org may call. The regulator user must already be an active government member of the regulator org. Returns the grant id.';
