-- ============================================================================
-- 20260903000111_join_request_audit_cases.sql — companion to …110.
--
-- trg_audit_capture() (Phase 06, last fully defined in …090) dispatches on
-- tg_table_name and had no case for the new organization_join_requests /
-- notifications tables, so rows written by the …110 triggers were silently
-- dropped (v_org_id null → early-exit, no audit row). Additive fix: this
-- migration re-publishes the …090 definition VERBATIM (all existing cases
-- byte-identical, verified by scripts/check-111-fidelity.mjs) plus exactly
-- two new cases. No authorization change: SECURITY DEFINER unchanged,
-- audit_log remains append-only with its existing RLS.
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
        when 'sites' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'name', coalesce(new.name, old.name),
                'location', coalesce(new.location, old.location),
                'county', coalesce(new.county, old.county),
                'status', coalesce(new.status, old.status),
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
        when 'incidents' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'severity', coalesce(new.severity, old.severity),
                'severity_previous', old.severity,
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'type', coalesce(new.incident_type, old.incident_type),
                'client_id', coalesce(new.client_id, old.client_id),
                'deleted', coalesce(new.deleted, old.deleted),
                'deleted_previous', old.deleted,
                'reporter_user_id', coalesce(new.reported_by_user_id, old.reported_by_user_id));
        when 'incident_evidence' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'incident_id', coalesce(new.incident_id, old.incident_id),
                'kind', coalesce(new.kind, old.kind),
                'content_type', coalesce(new.content_type, old.content_type),
                'size_bytes', coalesce(new.size_bytes, old.size_bytes),
                'sha256', coalesce(new.sha256, old.sha256));
        when 'incident_witnesses' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'incident_id', coalesce(new.incident_id, old.incident_id),
                'full_name', coalesce(new.full_name, old.full_name),
                'badge', coalesce(new.badge, old.badge));
        when 'inspections' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'inspector_id', coalesce(new.inspector_id, old.inspector_id),
                'inspection_type', coalesce(new.inspection_type, old.inspection_type),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'score', coalesce(new.score, old.score),
                'client_id', coalesce(new.client_id, old.client_id));
        when 'corrective_actions' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'source_type', coalesce(new.source_type, old.source_type),
                'incident_id', coalesce(new.incident_id, old.incident_id),
                'inspection_id', coalesce(new.inspection_id, old.inspection_id),
                'priority', coalesce(new.priority, old.priority),
                'priority_previous', old.priority,
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'assigned_to', coalesce(new.assigned_to, old.assigned_to),
                'client_id', coalesce(new.client_id, old.client_id));
        when 'jsas' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'task', coalesce(new.task, old.task),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'site_id', coalesce(new.site_id, old.site_id),
                'approved_by', coalesce(new.approved_by, old.approved_by),
                'deleted', coalesce(new.deleted, old.deleted),
                'deleted_previous', old.deleted,
                'client_id', coalesce(new.client_id, old.client_id));
        when 'jsa_steps' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'jsa_id', coalesce(new.jsa_id, old.jsa_id),
                'step_number', coalesce(new.step_number, old.step_number),
                'hazard', coalesce(new.hazard, old.hazard),
                'severity_label', coalesce(new.severity_label, old.severity_label));
        when 'emergency_events' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'site_id', coalesce(new.site_id, old.site_id),
                'category', coalesce(new.category, old.category),
                'severity', coalesce(new.severity, old.severity),
                'severity_previous', old.severity,
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'client_id', coalesce(new.client_id, old.client_id),
                'deleted', coalesce(new.deleted, old.deleted),
                'deleted_previous', old.deleted,
                'activated_by', coalesce(new.activated_by, old.activated_by),
                'resolved_by', coalesce(new.resolved_by, old.resolved_by));
        when 'emergency_acknowledgements' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'event_id', coalesce(new.event_id, old.event_id),
                'acked_by', coalesce(new.acked_by, old.acked_by),
                'channel', coalesce(new.channel, old.channel));
        when 'emergency_escalations' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'event_id', coalesce(new.event_id, old.event_id),
                'level', coalesce(new.level, old.level),
                'escalated_to', coalesce(new.escalated_to, old.escalated_to),
                'reason', coalesce(new.reason, old.reason));
        when 'emergency_responders' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'event_id', coalesce(new.event_id, old.event_id),
                'responder_user', coalesce(new.responder_user, old.responder_user),
                'role', coalesce(new.role, old.role),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status);
        when 'emergency_log' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'event_id', coalesce(new.event_id, old.event_id),
                'entry_type', coalesce(new.entry_type, old.entry_type),
                'actor_user_id', coalesce(new.actor_user_id, old.actor_user_id));
        when 'government_grants' then
            v_org_id      := coalesce(new.regulator_org_id, old.regulator_org_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'regulator_org_id', coalesce(new.regulator_org_id, old.regulator_org_id),
                'regulator_user_id', coalesce(new.regulator_user_id, old.regulator_user_id),
                'target_org_id', coalesce(new.target_org_id, old.target_org_id),
                'site_id', coalesce(new.site_id, old.site_id),
                'scope', coalesce(new.scope, old.scope),
                'regulator_role', coalesce(new.regulator_role, old.regulator_role),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'expires_at', coalesce(new.expires_at, old.expires_at)::text);
        when 'organization_join_requests' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'requested_role', coalesce(new.requested_role, old.requested_role),
                'status', coalesce(new.status, old.status),
                'status_previous', old.status,
                'requested_by', coalesce(new.user_id, old.user_id),
                'reviewed_by', new.reviewed_by);
        when 'notifications' then
            v_org_id      := coalesce(new.organization_id, old.organization_id);
            v_resource_id := coalesce(new.id, old.id)::text;
            v_meta := jsonb_build_object(
                'kind', coalesce(new.kind, old.kind),
                'recipient', coalesce(new.user_id, old.user_id));
        else
            return null;
    end case;

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
    return null;
end;
$$;

comment on function public.trg_audit_capture() is
    'Phase 06 generic audit capture (session 21: + organization_join_requests, + notifications). Server-side, append-only; secrets/tokens never recorded.';

commit;
