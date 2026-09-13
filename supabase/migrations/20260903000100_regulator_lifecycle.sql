-- ============================================================================
-- 20260903000100_regulator_lifecycle.sql — Regulator organization lifecycle
-- (session 20 corrective work).
--
-- Forensic findings (audited before writing this file):
--   1. The "Claim Regulator Organization" button lives in gov-admin.js
--      (Government panel empty state), wired to onBootstrap() →
--      MG_AUTH.bootstrapFirstRegulatorAdmin() → RPC
--      bootstrap_first_regulator_admin() (…090, hardened by …091).
--   2. The button SILENTLY NO-OPs on every outcome because onBootstrap
--      reports through statusLine() → el("govStatus") — an element that only
--      exists in renderPanel() (the regulator view), never in the bootstrap
--      empty state. Both success AND failure vanish.
--   3. The RPC is correct-by-design (Model A/C): SECURITY DEFINER, session
--      required, one-shot per user (any active membership disqualifies),
--      claims only the FIRST memberless ACTIVE org of org_type='regulator'
--      (for update skip locked), assigns national_regulatory_admin, audited by
--      the organization_members trigger. It is NOT privilege escalation: an
--      authenticated user can only claim a regulator org that has ZERO active
--      members, exactly once.
--   4. LIVE STATE: the project currently has NO regulator organization at all
--      (the seed.sql 'liberia-regulator' placeholder was never applied to the
--      live project during the fresh-start cutover), so the RPC raises
--      'no claimable regulator organization available' — invisibly (finding 2).
--   5. GAP: there is no authorized server-side provisioning path for the
--      regulator organization itself. If the claimable org is absent, nobody
--      — including a platform administrator — can create one without direct
--      service-role SQL. create_organization() (…099) deliberately refuses
--      regulator/platform types.
--
-- This migration closes the lifecycle additively (no existing policy weakened,
-- no RPC authorization loosened):
--   1. provision_regulator_organization(p_name, p_county) — SECURITY DEFINER.
--      Authorized callers ONLY: active members of an org_type='platform'
--      organization holding a platform-scoped role (platform_super_admin /
--      platform_support_admin / platform_auditor). Derives actor from
--      auth.uid(); server UUID/timestamps; collision-safe slug; status
--      'active'; NO owner membership, NO subscription (regulator orgs are not
--      commercial tenants); audited by the existing organizations trigger.
--      Uniqueness: at most ONE active regulator organization (partial unique
--      index) — duplicates prevented at the database level.
--   2. Partial unique index:
--        organizations (org_type='regulator' and status='active') → 1 row max.
--   3. regulator_claim_status() — SECURITY DEFINER TVF for the UI: returns the
--      claimable regulator org (id/name/county/status/created_at) when the
--      caller holds NO active membership and a claimable org exists;
--      'already_claimed' state when a regulator org exists but has members;
--      'not_authorized' is a client-side rendering decision (the TVF simply
--      returns zero rows for members — they are not eligible).
--   4. Re-assert grants: both functions revoked from public/anon, granted to
--      authenticated. The authorization checks are INSIDE the functions.
--
-- What this migration deliberately does NOT do:
--   - Does NOT let ordinary users create regulator orgs (create_organization
--     still refuses regulator/platform; provision RPC requires a platform
--     platform-scoped member).
--   - Does NOT change bootstrap_first_regulator_admin eligibility (one-shot,
--     orgless-only, memberless-org-only — preserved verbatim).
--   - Does NOT grant the regulator blanket cross-tenant access (Phase 11
--     grant-gated RLS untouched; oversight still requires explicit grants).
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. At most ONE active regulator organization (database-enforced)
-- ---------------------------------------------------------------------------
create unique index if not exists organizations_single_active_regulator_uidx
    on public.organizations (org_type)
    where org_type = 'regulator' and status = 'active';

comment on index organizations_single_active_regulator_uidx is
    'Regulator lifecycle (session 20): at most one ACTIVE regulator organization may exist. Duplicate national regulators are prevented at the database level, not in the client.';

-- ---------------------------------------------------------------------------
-- 2. provision_regulator_organization — authorized platform provisioning ONLY
-- ---------------------------------------------------------------------------
create or replace function public.provision_regulator_organization(
    p_name   text,
    p_county text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_user   uuid := auth.uid();
    v_name   text;
    v_slug   text;
    v_org_id uuid;
    v_n      int := 1;
    v_max_len constant int := 40;
begin
    if v_user is null then
        raise exception 'P0001: authentication required';
    end if;

    -- AUTHORIZATION: the caller must be an ACTIVE member of a PLATFORM
    -- organization holding a platform-scoped role. Regulator provisioning is
    -- never self-service (REGULATOR_ORGANIZATION_LIFECYCLE §4).
    if not exists (
        select 1
        from public.organization_members m
        join public.organizations o on o.id = m.organization_id
        join public.roles r on r.code = m.role
        where m.user_id = v_user
          and m.status = 'active'
          and o.org_type = 'platform'
          and o.status = 'active'
          and r.scope = 'platform'
    ) then
        raise exception 'P0001: only an authorized platform administrator may provision a regulator organization';
    end if;

    -- Validate name (same rules as create_organization)
    v_name := trim(coalesce(p_name, ''));
    if v_name is null or length(v_name) = 0 then
        raise exception 'P0001: regulator organization name is required';
    end if;
    if length(v_name) > 120 then
        raise exception 'P0001: regulator organization name must be 120 characters or fewer';
    end if;

    -- Uniqueness guard with a clean message (the partial unique index is the
    -- real arbiter; this raises before the confusing unique_violation).
    if exists (
        select 1 from public.organizations
        where org_type = 'regulator' and status = 'active'
    ) then
        raise exception 'P0001: an active regulator organization already exists; it cannot be duplicated';
    end if;

    -- Collision-safe slug (same algorithm as create_organization)
    v_slug := lower(regexp_replace(v_name, '[^a-zA-Z0-9]+', '-', 'g'));
    v_slug := trim(both '-' from v_slug);
    if v_slug is null or length(v_slug) = 0 then
        v_slug := 'regulator';
    end if;
    if length(v_slug) > v_max_len then
        v_slug := trim(both '-' from left(v_slug, v_max_len));
    end if;

    loop
        begin
            insert into public.organizations (slug, name, org_type, county, status, created_by)
            values (v_slug, v_name, 'regulator', p_county, 'active', v_user)
            returning id into v_org_id;
            exit;
        exception when unique_violation then
            v_n := v_n + 1;
            if v_n > 50 then
                raise exception 'P0001: could not allocate a unique slug; try a different name';
            end if;
            v_slug := trim(both '-' from left(lower(regexp_replace(v_name, '[^a-zA-Z0-9]+', '-', 'g')), v_max_len)) || '-' || v_n::text;
        end;
    end loop;

    -- Deliberately NO owner membership and NO subscription row: the regulator
    -- organization is provisioned EMPTY. Government officials claim it via
    -- bootstrap_first_regulator_admin (first, orgless user) or are added by
    -- the regulator admin (regulator_update_user_role) afterwards. The
    -- organizations INSERT/DELETE is captured by trg_audit_organizations with
    -- actor = auth.uid().
    return jsonb_build_object('organization_id', v_org_id, 'slug', v_slug);
end;
$$;

comment on function public.provision_regulator_organization(text, text) is
    'Regulator lifecycle (session 20): authorized platform administrators provision THE national regulator organization (max one active — enforced by organizations_single_active_regulator_uidx). Created empty: no owner, no subscription. Government officials onboard via bootstrap_first_regulator_admin / regulator role management. Actor derived from auth.uid(); never client-supplied.';

revoke all on function public.provision_regulator_organization(text, text) from public;
revoke all on function public.provision_regulator_organization(text, text) from anon;
grant execute on function public.provision_regulator_organization(text, text) to authenticated;

-- ---------------------------------------------------------------------------
-- 3. regulator_claim_status — UI state resolver (what can this user see?)
-- ---------------------------------------------------------------------------
create or replace function public.regulator_claim_status()
returns table (
    state          text,
    organization_id uuid,
    name           text,
    county         text,
    org_status     text
)
language plpgsql
stable
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        return;  -- unauthenticated: empty result; the gate handles sign-in
    end if;

    -- Caller holds ANY active membership → not eligible to claim (the …091
    -- one-shot guard mirrors this server-side; here it only drives the UI).
    if exists (
        select 1 from public.organization_members
        where user_id = auth.uid() and status = 'active'
    ) then
        return;
    end if;

    -- Claimable: an active regulator org with zero active members.
    return query
    select 'claimable'::text, o.id, o.name, o.county, o.status
    from public.organizations o
    where o.org_type = 'regulator'
      and o.status = 'active'
      and not exists (
          select 1 from public.organization_members m
          where m.organization_id = o.id and m.status = 'active'
      )
    order by o.created_at asc
    limit 1;

    -- Claimable org absent but an active regulator org exists (with members)
    -- → 'already_claimed' (contact the regulator administrator).
    if not found then
        if exists (
            select 1 from public.organizations o
            where o.org_type = 'regulator' and o.status = 'active'
              and exists (
                  select 1 from public.organization_members m
                  where m.organization_id = o.id and m.status = 'active'
              )
        ) then
            return query
            select 'already_claimed'::text, o.id, o.name, o.county, o.status
            from public.organizations o
            where o.org_type = 'regulator' and o.status = 'active'
            order by o.created_at asc
            limit 1;
        else
            -- No regulator org exists at all → 'none_provisioned'
            return query
            select 'none_provisioned'::text,
                   null::uuid, null::text, null::text, null::text;
        end if;
    end if;
end;
$$;

comment on function public.regulator_claim_status() is
    'Regulator lifecycle (session 20): UI state resolver for the Government panel claim surface. Rows are returned only for users holding NO active membership. state: claimable | already_claimed | none_provisioned. The claim itself remains guarded server-side by bootstrap_first_regulator_admin (…090/…091).';

revoke all on function public.regulator_claim_status() from public;
revoke all on function public.regulator_claim_status() from anon;
grant execute on function public.regulator_claim_status() to authenticated;

commit;
