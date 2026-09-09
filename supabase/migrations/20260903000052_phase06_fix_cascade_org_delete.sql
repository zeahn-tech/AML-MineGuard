-- ============================================================================
-- MINEGUARD LIBERIA — Phase 06 fix (2): generalize org-delete audit safety
--
-- The first fix (20260903000051) handled the organizations table's own
-- AFTER-DELETE trigger, but NOT the audit triggers on child tables
-- (organization_members, site_members, organizational_units, workers,
-- org_invites). When an organization is deleted, ON DELETE CASCADE removes its
-- child rows, which fires each child table's AFTER-DELETE audit trigger; those
-- try to INSERT an audit row with organization_id = the now-deleted org →
-- 23503, so deleting ANY organization still failed (confirmed by the
-- verify-rbac/verify-phase04 probe cleanups).
--
-- Generalized rule: an audit row may only carry organization_id when that org
-- still exists. If it does not (the org is being cascade-deleted), null the
-- tenant scope so the append-only records are still written (retained with
-- organization_id null, matching the first fix). SECURITY DEFINER bypasses RLS
-- for the existence check; volume is tiny (tenant-management writes only).
-- ============================================================================
begin;

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

    -- Tenant scope is only valid while the org exists. When the org is being
    -- removed (its own delete, or the cascade-delete of its child rows), null
    -- it so the append-only audit record is still written and never violates
    -- the FK. Retained as platform-scope history (organization_id = null).
    if v_org_id is not null
       and not exists (select 1 from public.organizations where id = v_org_id) then
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
    'Phase 06: server-side audit capture for tenant-management tables. Actor = auth.uid() (null under service-role writes). Append-only: inserts into audit_log only; never raises. organization_id is nulled when the referenced org no longer exists (org deletion / cascade), preserving the record with platform scope.';

commit;