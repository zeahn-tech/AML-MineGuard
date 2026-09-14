-- ============================================================================
-- 20260903000115_join_requests_list_email_cast.sql — Approve-button hotfix.
--
-- Forensic finding (session 22): organization_join_requests_list() as shipped
-- by …112 selects `u.email` — auth.users.email is varchar(255) — into a TVF
-- column declared `text`. Postgres requires RETURN QUERY column types to
-- match exactly (no implicit cast), so EVERY call fails with 42804:
--   "Returned type character varying(255) does not match expected type text
--    in column 3."
-- The admin review card's error path silently rendered nothing, so owners
-- never saw the Approve/Reject buttons for genuinely pending requests.
-- This is the same varchar→text class of defect fixed for org_list_members
-- in Phase 04 (email cast to text there), reintroduced by the …112
-- re-publish without the cast.
--
-- Fix: re-publish with `u.email::text`. Authorization (require_org_admin),
-- ordering, limit, and grants are unchanged from …112.
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
    select r.id, r.user_id, u.email::text, r.requested_role, r.status, r.created_at
    from public.organization_join_requests r
    left join auth.users u on u.id = r.user_id
    where r.organization_id = p_organization_id
    order by (r.status = 'pending') desc, r.created_at desc
    limit 100;
end;
$$;

comment on function public.organization_join_requests_list(uuid) is
    'Session 22 hotfix (…115): email cast to text — the …112 body selected auth.users.email (varchar(255)) into a text TVF column, so every call failed with 42804 and the admin review card silently rendered no Approve/Reject buttons. Authorization unchanged (require_org_admin).';

revoke all on function public.organization_join_requests_list(uuid) from public;
grant execute on function public.organization_join_requests_list(uuid) to authenticated;

commit;
