-- ============================================================
-- Phase 05 cutover fix — policy/permission alignment for
-- safety notices (probe-driven, convention of Phases 08–12).
--
-- Findings from scripts/verify-phase05.mjs (first run):
--   F1. The migration's INSERT/UPDATE policies gate on the
--       permission code 'notices.manage', which does NOT exist
--       in the Phase 03 catalog. The catalog defines
--       notices.view / notices.create / notices.update /
--       notices.delete (owner/admin/safety_manager: full set;
--       safety_officer: create+update+view). Policies referencing
--       a nonexistent code silently deny every notice write.
--   F2. audit_log.organization_id FK is ON DELETE RESTRICT for
--       this trigger's insert path order: deleting an
--       organization before its audit rows made cleanup fail
--       (23503). The Phase 06 convention (…051/…052) nulls the
--       org scope when the referenced org no longer exists.
--       Apply the same semantics to the dedicated notices audit
--       trigger (org-delete cascade path).
--   F3. Soft-delete via a direct PATCH {deleted:true} is
--       impossible over PostgREST: it re-checks the SELECT
--       policy (deleted = false) on the UPDATE returning row and
--       raises 42501 even when the UPDATE itself is allowed —
--       the same class of finding recorded in Phase 07 for
--       Prefer: return=representation. The production removal
--       path is therefore a SECURITY DEFINER RPC gated on the
--       catalog's notices.delete permission (owner/admin/
--       safety_manager), matching the project's RPC-only-write
--       convention for gated operations.
-- ============================================================

-- ---- F3: SECURITY DEFINER soft-delete RPC (the only removal path) ----

create or replace function public.notice_soft_delete(p_notice_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org uuid;
begin
    select organization_id into v_org
    from public.safety_notices where id = p_notice_id;
    if v_org is null then
        raise exception 'P0001: notice not found';
    end if;
    if not public.auth_user_has_permission(v_org, 'notices.delete') then
        raise exception 'P0001: notices.delete permission required';
    end if;
    update public.safety_notices
    set deleted = true, updated_at = now()
    where id = p_notice_id and deleted = false;
end;
$$;

revoke all on function public.notice_soft_delete(uuid) from public;
grant execute on function public.notice_soft_delete(uuid) to authenticated;

-- ---- F1: align policies with the real permission catalog ----

drop policy if exists safety_notices_select on public.safety_notices;
create policy safety_notices_select on public.safety_notices
    for select to authenticated
    using (
        deleted = false
        and public.auth_user_has_org_access(organization_id)
        and (
            site_id is null
            or public.auth_user_has_site_access(organization_id, site_id)
            or public.auth_user_has_permission(organization_id, 'notices.view')
        )
    );

drop policy if exists safety_notices_insert on public.safety_notices;
create policy safety_notices_insert on public.safety_notices
    for insert to authenticated
    with check (
        public.auth_user_has_permission(organization_id, 'notices.create')
    );

drop policy if exists safety_notices_update on public.safety_notices;
create policy safety_notices_update on public.safety_notices
    for update to authenticated
    using (
        public.auth_user_has_permission(organization_id, 'notices.update')
    )
    with check (
        public.auth_user_has_permission(organization_id, 'notices.update')
    );

drop policy if exists safety_notice_acks_select on public.safety_notice_acks;
create policy safety_notice_acks_select on public.safety_notice_acks
    for select to authenticated
    using (
        user_id = auth.uid()
        or public.auth_user_has_permission(organization_id, 'notices.view')
    );

drop policy if exists safety_notice_acks_insert on public.safety_notice_acks;
create policy safety_notice_acks_insert on public.safety_notice_acks
    for insert to authenticated
    with check (
        user_id = auth.uid()
        and public.auth_user_has_org_access(organization_id)
    );

-- ---- F2: org-delete cascade survival for the notices audit trigger ----

create or replace function public.trg_audit_notices_capture()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    if tg_table_name = 'safety_notices' then
        insert into public.audit_log
            (organization_id, actor_user_id, actor_name, action, resource, resource_id, metadata, source)
        values
            (case
                when tg_op = 'DELETE' and not exists (
                    select 1 from public.organizations o
                    where o.id = old.organization_id
                ) then null
                else coalesce(new.organization_id, old.organization_id)
             end,
             auth.uid(),
             (select email::text from auth.users where id = auth.uid()),
             tg_op || '.' || tg_table_name,
             tg_table_name,
             coalesce(new.id, old.id)::text,
             jsonb_build_object(
                 'title', coalesce(new.title, old.title),
                 'notice_type', coalesce(new.notice_type, old.notice_type),
                 'pinned', coalesce(new.pinned, old.pinned),
                 'deleted', coalesce(new.deleted, old.deleted),
                 'site_id', coalesce(new.site_id, old.site_id)),
             'trigger');
    else -- safety_notice_acks
        insert into public.audit_log
            (organization_id, actor_user_id, actor_name, action, resource, resource_id, metadata, source)
        values
            (case
                when not exists (
                    select 1 from public.organizations o
                    where o.id = coalesce(new.organization_id, old.organization_id)
                ) then null
                else coalesce(new.organization_id, old.organization_id)
             end,
             auth.uid(),
             (select email::text from auth.users where id = auth.uid()),
             tg_op || '.' || tg_table_name,
             tg_table_name,
             coalesce(new.id, old.id)::text,
             jsonb_build_object(
                 'notice_id', coalesce(new.notice_id, old.notice_id),
                 'user_id', coalesce(new.user_id, old.user_id)),
             'trigger');
    end if;
    return coalesce(new, old);
end;
$$;
