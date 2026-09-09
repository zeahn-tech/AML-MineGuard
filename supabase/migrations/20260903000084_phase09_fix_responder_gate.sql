-- ============================================================================
-- MINEGUARD LIBERIA — Phase 09 fix 4: responder authorization gate
--
-- Probe-driven fix (verify-phase09.mjs): responder policies used
-- auth_user_can_update_emergency_child(), which granted dispatch/disposition
-- to acknowledge holders — including plain workers (their bundle includes
-- emergency.acknowledge). Responder management is response-chain work:
-- supervisor and above at org or site scope (same gate as escalations).
-- The child helper becomes unused and is dropped.
-- ============================================================================

begin;

drop policy if exists emergency_resp_insert on public.emergency_responders;
create policy emergency_resp_insert on public.emergency_responders
    for insert to authenticated
    with check (public.auth_user_can_escalate_emergency(event_id));

drop policy if exists emergency_resp_update on public.emergency_responders;
create policy emergency_resp_update on public.emergency_responders
    for update to authenticated
    using (public.auth_user_can_escalate_emergency(event_id))
    with check (public.auth_user_can_escalate_emergency(event_id));

drop function if exists public.auth_user_can_update_emergency_child(uuid);

commit;