-- ============================================================================
-- MINEGUARD LIBERIA — Phase 06 fix: org-delete audit path (append-only safety)
--
-- Problem found during Phase 06 verification: the Phase 06 audit trigger
-- (trg_audit_capture) fires AFTER DELETE on organizations and inserts an
-- audit row whose organization_id = OLD.id — but that row is gone by then, so
-- the INSERT violates audit_log_organization_id_fkey and the DELETE of ANY
-- organization always fails (23503). This broke the verify probe's own
-- self-cleaning and any future org hard-delete.
--
-- Fix (two parts):
--   1. Trigger: when TG_OP = 'DELETE' on organizations, null the tenant scope
--      of the audit row (the org no longer exists to reference).
--   2. FK: audit_log.organization_id now ON DELETE SET NULL (instead of
--      CASCADE) so the org's existing audit history is RETAINED (org_id null)
--      when the org is hard-deleted, preserving the tamper-resistant trail.
-- ============================================================================
begin;

-- 1. Guard the trigger so deleting an organization succeeds.
create or replace function public.trg_audit_capture()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org_id      uuid;
    v_resource_id text;
    v_meta        jsonb := '{}'::jsonb;
    v_actor_name  text;
begin
    case tg_table_name
        when 'organization_members' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.user_id, old.user_id)::text;
            v_meta := jsonb_build_object(
                'role', coalesce(new.role, old.role),
                'status', coalesce(new.status, old.status),
                'role_previous', old.role,
                'status_previous', old.status);
        when 'site_members' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.user_id, old.user_id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'role', coalesce(new.role, old.role),
                'status', coalesce(new.status, old.status),
                'role_previous', old.role,
                'status_previous', old.status);
        when 'organizational_units' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'name', coalesce(new.name, old.name),
                'unit_type', coalesce(new.unit_type, old.unit_type),
                'site_id', coalesce(new.site_id, old.site_id),
                'code', coalesce(new.code, old.code),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status);
        when 'workers' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'full_name', coalesce(new.full_name, old.full_name),
                'employee_id', coalesce(new.employee_id, old.employee_id),
                'site_id', coalesce(new.site_id, old.site_id),
                'department_id', coalesce(new.department_id, old.department_id),
                'classification', coalesce(new.classification, old.classification),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status);
        when 'org_invites' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            -- token is deliberately NOT audited (one-time secret)
            v_meta := jsonb_build_object(
                'email', coalesce(new.email, old.email),
                'role', coalesce(new.role, old.role),
                'status', coalesce(new.status, old.status),
                'site_id', coalesce(new.site_id, old.site_id));
        when 'organizations' then
            v_org_id      := coalesce(new.id, old.id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'slug', coalesce(new.slug, old.slug),
                'name', coalesce(new.name, old.name),
                'county', coalesce(new.county, old.county),
                'org_type', coalesce(new.org_type, old.org_type),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status);
        else
            return null;
    end case;

    -- When the organization row itself is being deleted, the new audit row
    -- cannot reference it (it no longer exists). Null the tenant scope so the
    -- append-only org-delete record is still written (retained with org_id null).
    if tg_table_name = 'organizations' and tg_op = 'DELETE' then
        v_org_id := null;
    end if;

    if auth.uid() is not null then
        select email into v_actor_name from auth.users where id = auth.uid();
    end if;

    insert into public.audit_log
        (organization_id, actor_user_id, actor_name, action, resource,
         resource_id, metadata, source)
    values
        (v_org_id, auth.uid(), v_actor_name,
         tg_table_name || '.' || lower(tg_op),
         tg_table_name, v_resource_id, v_meta, 'trigger');
    return null; -- AFTER trigger: result unused
end;
$$;

comment on function public.trg_audit_capture() is
    'Phase 06: server-side audit capture for tenant-management tables. Actor = auth.uid() (null under service-role writes). Append-only: inserts into audit_log only; never raises. Org deletes write the record with organization_id null (the org row is gone).';

-- 2. Retain audit history on org hard-delete (SET NULL instead of CASCADE).
alter table public.audit_log drop constraint if exists audit_log_organization_id_fkey;
alter table public.audit_log add constraint audit_log_organization_id_fkey
    foreign key (organization_id) references public.organizations(id) on delete set null;

commit;