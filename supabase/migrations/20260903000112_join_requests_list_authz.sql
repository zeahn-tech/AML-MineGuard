-- ============================================================================
-- 20260903000112_join_requests_list_authz.sql — session 21 security fix.
--
-- Forensic finding: organization_join_requests_list() (…110) is SECURITY
-- DEFINER but performed NO authorization check — the org-admin UI gated it
-- client-side only. Any authenticated user could call it with an arbitrary
-- organization_id and enumerate that org's join requests (requester emails,
-- statuses) — a cross-tenant information disclosure.
--
-- Fix: re-publish the function with an explicit require_org_admin() gate
-- (Phase 04 helper, the same server-side guard used by every other
-- org-admin RPC). Behavior for legitimate callers is unchanged.
-- ============================================================================

begin;

create or replace function public.organization_join_requests_list(p_organization_id uuid)
returns table (
    id             uuid,
    user_id        uuid,
    email          text,
    requested_role text,
    status         text,
    created_at     timestamptz
)
language plpgsql
stable
security definer
set search_path = public
as $$
begin
    -- Server-side authorization: caller must hold an active owner/admin
    -- membership in the TARGET organization (not merely any org).
    perform public.require_org_admin(p_organization_id);

    return query
    select r.id, r.user_id, u.email, r.requested_role, r.status, r.created_at
    from public.organization_join_requests r
    left join auth.users u on u.id = r.user_id
    where r.organization_id = p_organization_id
    order by (r.status = 'pending') desc, r.created_at desc
    limit 100;
end;
$$;

comment on function public.organization_join_requests_list(uuid) is
    'Session 21 (fixed in …112): org-scoped join-request list for the admin review card. SECURITY DEFINER with an explicit require_org_admin(p_organization_id) gate — cross-tenant enumeration is denied server-side (the …110 version relied on the client gate only).';

revoke all on function public.organization_join_requests_list(uuid) from public;
grant execute on function public.organization_join_requests_list(uuid) to authenticated;

commit;
