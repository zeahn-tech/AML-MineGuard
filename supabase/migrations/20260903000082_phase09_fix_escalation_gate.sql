-- ============================================================================
-- MINEGUARD LIBERIA — Phase 09 fix 2: escalation role gate
--
-- Probe-driven fix (verify-phase09.mjs): the widened child helper let plain
-- workers escalate (they hold emergency.acknowledge). Per RLS_MATRIX §1.2
-- (emergency_acks/escalations row) workers hold "I(own ack)" only; escalation
-- INSERT belongs to the response chain (supervisor and above at org or site
-- scope). Responders keep the acknowledge-based gate (dispatch/disposition is
-- responder work).
-- ============================================================================

begin;

-- Escalation gate: response-chain roles at org or the event's site scope
create or replace function public.auth_user_can_escalate_emergency(p_event_id uuid)
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
              public.auth_user_effective_role(e.organization_id)
                  in ('owner', 'admin', 'safety_manager', 'safety_officer', 'site_manager', 'supervisor')
              or public.auth_user_site_effective_role(e.organization_id, e.site_id)
                  in ('site_manager', 'supervisor')
          )
    );
$$;

comment on function public.auth_user_can_escalate_emergency(uuid) is
    'Phase 09: can the current user record an escalation on this event? Response-chain roles (supervisor and above) at org scope or the event''s site scope; workers hold ack-only (RLS_MATRIX §1.2).';

revoke all on function public.auth_user_can_escalate_emergency(uuid) from public;
grant execute on function public.auth_user_can_escalate_emergency(uuid) to anon, authenticated;

-- escalation INSERT policy now uses the dedicated role gate
drop policy if exists emergency_esc_insert on public.emergency_escalations;
create policy emergency_esc_insert on public.emergency_escalations
    for insert to authenticated
    with check (public.auth_user_can_escalate_emergency(event_id));

commit;
