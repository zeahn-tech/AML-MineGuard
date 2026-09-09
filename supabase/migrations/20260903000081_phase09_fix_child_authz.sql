-- ============================================================================
-- MINEGUARD LIBERIA — Phase 09 fix: escalation + responder authorization
--
-- Probe-driven fix (verify-phase09.mjs):
--   1. auth_user_can_update_emergency_child only resolved acknowledge at ORG
--      scope, so a site-only supervisor (site-scope acknowledge per the Phase 03
--      catalog) could not escalate or update responders on their own site's
--      event. The helper now accepts site-scope emergency.acknowledge too.
--   2. Re-applies migration …080's helper verbatim with the widened gate so
--      policy references stay in sync.
-- ============================================================================

begin;

create or replace function public.auth_user_can_update_emergency_child(p_event_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.emergency_events e
        where e.id = p_event_id
          and public.auth_user_has_site_access(e.organization_id, e.site_id)
          and (
              public.auth_user_has_permission(e.organization_id, 'emergency.resolve')
              -- org-scope acknowledge OR site-scope acknowledge (site-only responders)
              or public.auth_user_has_permission(e.organization_id, 'emergency.acknowledge')
              or public.auth_user_has_site_permission(e.organization_id, e.site_id, 'emergency.acknowledge')
          )
    );
$$;

comment on function public.auth_user_can_update_emergency_child(uuid) is
    'Phase 09: can the current user insert/update escalations or responders on this event? emergency.resolve holders plus acknowledge at org scope or the event''s site scope (site-only supervisors/responders).';

revoke all on function public.auth_user_can_update_emergency_child(uuid) from public;
grant execute on function public.auth_user_can_update_emergency_child(uuid) to anon, authenticated;

commit;
