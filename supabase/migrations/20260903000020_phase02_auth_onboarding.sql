-- ============================================================================
-- MINEGUARD LIBERIA — Phase 02: Auth + identity onboarding support
-- Target database: Supabase (PostgreSQL 15+)
--
-- Adds the server-side half of the Phase 02 onboarding flow:
--   1. bootstrap_first_owner() — SECURITY DEFINER RPC. A brand-new
--      authenticated user with no memberships may claim the FIRST active
--      mining_company organization that has zero active members, becoming its
--      owner. This implements the "first owner" onboarding documented in
--      SESSION_HANDOFF.md (ArcelorMittal Liberia is seeded as tenant #1 and
--      becomes claimable until an owner exists). Once any org has an active
--      owner/admin, the function raises and membership management moves to
--      org-admin/invite flows (Phase 04).
--   2. Narrow self-service membership policies — an authenticated user may
--      INSERT only their OWN row in an inert 'member'/'invited' state and may
--      UPDATE it only to withdraw ('removed'). It is impossible to grant
--      yourself 'owner'/'admin' or 'active' standing through RLS: activation
--      is exclusively the product of bootstrap_first_owner() (definer) or,
--      later, org-admin actions (Phase 04/06). RLS remains the boundary.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. First-owner bootstrap RPC
-- ---------------------------------------------------------------------------
create or replace function public.bootstrap_first_owner()
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org_id uuid;
    v_user   uuid := auth.uid();
begin
    if v_user is null then
        raise exception 'authentication required';
    end if;

    -- Claim the oldest active mining_company org with no active members.
    -- Regulator/platform orgs are never claimable by random sign-ups.
    select o.id into v_org_id
    from public.organizations o
    where o.org_type = 'mining_company'
      and o.status  = 'active'
      and not exists (
          select 1
          from public.organization_members m
          where m.organization_id = o.id
            and m.status = 'active'
      )
    order by o.created_at asc
    limit 1
    for update of o skip locked;

    if v_org_id is null then
        raise exception 'no claimable organization found: an owner already exists for every active organization';
    end if;

    insert into public.organization_members
        (organization_id, user_id, role, status, created_by)
    values
        (v_org_id, v_user, 'owner', 'active', v_user)
    on conflict (organization_id, user_id) do update
        set role = 'owner', status = 'active', created_by = excluded.created_by, updated_at = now();

    return v_org_id;
end;
$$;

comment on function public.bootstrap_first_owner() is
    'Phase 02 onboarding: grants OWNER of the first active mining_company org that has no active members. Raises once any org is owned. SECURITY DEFINER — never grant to anon.';

revoke all on function public.bootstrap_first_owner() from public;
revoke all on function public.bootstrap_first_owner() from anon;
grant execute on function public.bootstrap_first_owner() to authenticated;

-- ---------------------------------------------------------------------------
-- 2. Self-service membership policies (own rows only, inert states only)
-- ---------------------------------------------------------------------------
-- A signed-in user may create exactly their own membership row, in the inert
-- 'member'/'invited' state (no tenant access). Activation happens through
-- bootstrap_first_owner() or org-admin flows (Phase 04). INSERT policies use
-- WITH CHECK so a client can never smuggle a different user_id/role/status.
drop policy if exists "members_insert_self_invited" on public.organization_members;
create policy members_insert_self_invited on public.organization_members
    for insert
    to authenticated
    with check (
        user_id = auth.uid()
        and role = 'member'
        and status = 'invited'
        and created_by = auth.uid()
    );

-- A user may withdraw (soft-remove) their own invite; anything else touching
-- memberships (promote/demote/activate/suspend/assign) is Phase 04 org-admin
-- territory and stays default-deny today.
drop policy if exists "members_update_self_invited" on public.organization_members;
create policy members_update_self_invited on public.organization_members
    for update
    to authenticated
    using (user_id = auth.uid())
    with check (
        user_id = auth.uid()
        and role = 'member'
        and status in ('invited', 'removed')
        and created_by = auth.uid()
    );

-- DELETE of own membership rows stays default-deny: deletes on join tables are
-- an audit concern; Phase 04 defines the org-admin removal/leave flows.

commit;
