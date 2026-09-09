-- ============================================================================
-- MINEGUARD LIBERIA — Phase 09 fix 3: child guard column mismatch
--
-- Probe-driven fix (verify-phase09.mjs): trg_emergency_child_guard() set
-- created_by for emergency_responders rows, but that table has no created_by
-- column → 42703 "record \"new\" has no field \"created_by\"" on every responder
-- insert. The guard now sets created_by only for emergency_escalations.
-- ============================================================================

begin;

create or replace function public.trg_emergency_child_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    select organization_id, site_id into new.organization_id, new.site_id
    from public.emergency_events where id = new.event_id;
    if new.organization_id is null then
        raise exception 'emergency event does not exist';
    end if;

    if tg_table_name = 'emergency_acknowledgements' then
        if new.acked_by is not null and auth.uid() is not null
           and new.acked_by <> auth.uid() then
            raise exception 'acked_by must be the current user';
        end if;
        if new.acked_by is null and auth.uid() is not null then
            new.acked_by := auth.uid();
        end if;
    end if;

    if tg_table_name = 'emergency_escalations' then
        if new.created_by is null and auth.uid() is not null then
            new.created_by := auth.uid();
        end if;
    end if;
    return new;
end;
$$;

comment on function public.trg_emergency_child_guard() is
    'Phase 09: mirrors org/site from the parent emergency event; pins acked_by to auth.uid() on acknowledgements; sets created_by on escalations (responders carry no created_by column).';

commit;
