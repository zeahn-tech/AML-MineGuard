-- ============================================================================
-- 20260903000099_org_lifecycle.sql — Organization lifecycle (self-service
-- creation + ownership transfer), corrective work (session 18).
--
-- Forensic finding: bootstrap_first_owner() (…020) is a CLAIM mechanism for a
-- memberless seeded org — not a creation mechanism. Once every active org has
-- an owner it raises 'no claimable organization found…'. There was NO
-- self-service organization creation: organizations INSERT is default-deny for
-- authenticated (no INSERT policy), so the only paths were bootstrap claims or
-- direct service-role seeding.
--
-- This migration adds, additively (no existing policy/shape weakened):
--   1. org_type check extended with 'service_provider' (recreate constraint).
--   2. create_organization(p_name, p_org_type, p_county) — SECURITY DEFINER:
--      - requires a session (auth.uid())
--      - validates name (1..120 chars) + org_type
--      - public/self-service types: mining_company | contractor | service_provider
--        regulator/platform are NEVER creatable here (platform provisioning only)
--      - slug generated server-side from name, collision-safe (-2, -3, …);
--        name unique (lower(name)) violations surface as a clean error
--      - server UUID + timestamps; created_by = auth.uid()
--      - creator membership (role owner, status active, created_by auth.uid())
--        inserted ATOMICALLY in the same function body (single transaction)
--      - subscription initialized on the 'starter' plan (existing Phase 12
--        architecture; billing stays deferred; failure rolls everything back)
--      - audit: the existing trg_audit_organizations + trg_audit_organization_members
--        triggers capture both rows (actor = auth.uid())
--      - returns jsonb {organization_id, slug}
--   3. org_transfer_ownership(p_organization_id, p_new_owner_user_id) —
--      SECURITY DEFINER:
--      - requires session + current active OWNER of the org
--      - target must be an active member (any role) of the same org
--      - atomic swap: target → owner, current owner → admin (never memberless;
--      - creator cannot be re-assigned by client (ids derived server-side)
--      - audit rows captured by the membership trigger; role change audited
--   4. Both RPCs: revoke from public/anon, grant to authenticated.
--
-- Security notes:
--   - No client-supplied owner id / role / status / organization id is trusted.
--   - No new RLS policies; organizations INSERT stays default-deny — creation
--     is ONLY possible through the SECURITY DEFINER RPC.
--   - bootstrap_first_owner() remains for controlled first-deployment bootstrap.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. org_type: allow 'service_provider' (additive; keeps existing values)
-- ---------------------------------------------------------------------------
alter table public.organizations drop constraint organizations_org_type_check;
alter table public.organizations add constraint organizations_org_type_check
    check (org_type in ('mining_company', 'contractor', 'service_provider', 'regulator', 'platform'));

-- ---------------------------------------------------------------------------
-- 2. Self-service organization creation (atomic org + owner + subscription)
-- ---------------------------------------------------------------------------
create or replace function public.create_organization(
    p_name     text,
    p_org_type text default 'mining_company',
    p_county   text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_user      uuid := auth.uid();
    v_org_id    uuid;
    v_slug_base text;
    v_slug      text;
    v_n         int := 1;
    v_type      text := lower(coalesce(trim(p_org_type), 'mining_company'));
    v_name      text;
    v_max_len   constant int := 40;           -- slug length budget (before suffix)
begin
    if v_user is null then
        raise exception 'P0001: authentication required';
    end if;

    -- Validate name
    v_name := trim(coalesce(p_name, ''));
    if v_name is null or length(v_name) = 0 then
        raise exception 'P0001: organization name is required';
    end if;
    if length(v_name) > 120 then
        raise exception 'P0001: organization name must be 120 characters or fewer';
    end if;

    -- Organization type gate: public self-service covers operational/commercial
    -- types ONLY. Regulator and platform organizations are provisioned through
    -- authorized platform/government administration (bootstrap_first_platform_admin,
    -- regulator RPCs) — never through this public flow.
    if v_type not in ('mining_company', 'contractor', 'service_provider') then
        raise exception 'P0001: organization type % cannot be self-registered; contact the platform administrator', v_type;
    end if;

    -- Safe slug base: lowercase, alphanumerics and single hyphens.
    v_slug_base := lower(regexp_replace(v_name, '[^a-zA-Z0-9]+', '-', 'g'));
    v_slug_base := trim(both '-' from v_slug_base);
    if v_slug_base is null or length(v_slug_base) = 0 then
        v_slug_base := 'org';   -- name had no usable characters
    end if;
    if length(v_slug_base) > v_max_len then
        v_slug_base := left(v_slug_base, v_max_len);
        v_slug_base := trim(both '-' from v_slug_base);
    end if;

    -- Collision-safe slug: base, then -2, -3, … (unique index is the arbiter).
    v_slug := v_slug_base;
    loop
        begin
            insert into public.organizations (slug, name, org_type, county, status, created_by)
            values (v_slug, v_name, v_type, p_county, 'active', v_user)
            returning id into v_org_id;
            exit;
        exception when unique_violation then
            v_n := v_n + 1;
            if v_n > 50 then
                raise exception 'P0001: could not allocate a unique organization slug; try a different name';
            end if;
            v_slug := v_slug_base || '-' || v_n::text;
        end;
    end loop;

    -- Creator becomes the active OWNER (identity derived from auth.uid() —
    -- never from client-supplied ids/roles).
    insert into public.organization_members
        (organization_id, user_id, role, status, created_by)
    values
        (v_org_id, v_user, 'owner', 'active', v_user);

    -- Subscription initialization on the existing plan model (Phase 12).
    -- 'starter' is the seeded default tier; billing remains unwired.
    insert into public.subscriptions (organization_id, plan_code, status, changed_by)
    select v_org_id, p.code, 'active', v_user
    from public.plans p
    where p.code = 'starter'
    on conflict do nothing;

    return jsonb_build_object('organization_id', v_org_id, 'slug', v_slug);
end;
$$;

comment on function public.create_organization(text, text, text) is
    'Self-service organization creation (atomic): validates name/type, generates a collision-safe slug, inserts the org, makes the session user the active OWNER (auth.uid()-derived), and initializes a starter subscription. regulator/platform types are rejected. Audit via existing triggers.';

revoke all on function public.create_organization(text, text, text) from public;
revoke all on function public.create_organization(text, text, text) from anon;
grant execute on function public.create_organization(text, text, text) to authenticated;

-- ---------------------------------------------------------------------------
-- 3. Ownership transfer (current-owner-only, atomic swap, audited)
-- ---------------------------------------------------------------------------
create or replace function public.org_transfer_ownership(
    p_organization_id   uuid,
    p_new_owner_user_id uuid
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_me      uuid := auth.uid();
    v_current uuid;
begin
    if v_me is null then
        raise exception 'P0001: authentication required';
    end if;
    if p_new_owner_user_id is null then
        raise exception 'P0001: new owner user id is required';
    end if;
    if p_new_owner_user_id = v_me then
        raise exception 'P0001: you already own this organization';
    end if;

    -- Only the CURRENT ACTIVE OWNER may initiate a transfer. Admins cannot
    -- seize ownership (org_update_member_role separately blocks re-roleing
    -- the owner; this function is the only sanctioned transfer path).
    select m.user_id into v_current
    from public.organization_members m
    where m.organization_id = p_organization_id
      and m.role = 'owner' and m.status = 'active'
      and m.user_id = v_me;
    if v_current is null then
        raise exception 'P0001: only the current organization owner may transfer ownership';
    end if;

    -- Target must be an ACTIVE member of the SAME org (any non-owner role).
    if not exists (
        select 1 from public.organization_members m
        where m.organization_id = p_organization_id
          and m.user_id = p_new_owner_user_id
          and m.status = 'active'
          and m.role <> 'owner'
    ) then
        raise exception 'P0001: the new owner must be an active member of this organization';
    end if;

    -- Atomic swap: exactly one active owner at any instant.
    update public.organization_members
       set role = 'admin', updated_at = now(), created_by = v_me
     where organization_id = p_organization_id and user_id = v_me;

    update public.organization_members
       set role = 'owner', updated_at = now(), created_by = v_me
     where organization_id = p_organization_id and user_id = p_new_owner_user_id;
end;
$$;

comment on function public.org_transfer_ownership(uuid, uuid) is
    'Ownership transfer: current active owner promotes an active member to owner and steps down to admin. Atomic single-owner invariant; audit via the membership trigger; admins cannot self-seize.';

revoke all on function public.org_transfer_ownership(uuid, uuid) from public;
revoke all on function public.org_transfer_ownership(uuid, uuid) from anon;
grant execute on function public.org_transfer_ownership(uuid, uuid) to authenticated;

commit;
