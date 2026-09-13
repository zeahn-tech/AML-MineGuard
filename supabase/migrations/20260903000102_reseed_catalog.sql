-- ============================================================================
-- 20260903000102_reseed_catalog.sql — RESTORE the RBAC catalog rows.
--
-- FINDING (session 20, verified live via a SECURITY DEFINER bypass of RLS):
-- the catalog tables `roles`, `permissions`, `role_permissions` and `plans`
-- are EMPTY on the live project even though the migrations that seed them
-- (…030 Phase 03, …094 Phase 12) are recorded in supabase_migrations. Their
-- data rows are gone (schema intact, constraints intact). Whatever removed
-- them, the platform cannot function without the catalog:
--   * auth_user_has_permission / auth_user_permissions return empty sets →
--     every permission-gated RPC/UI surface degrades,
--   * provision_regulator_organization (…100) authorizes via roles.scope,
--   * regulator grant issuing / role management joins roles.scope.
--
-- This migration re-inserts ALL catalog rows VERBATIM from the authoritative
-- seed blocks (…030 §1–§3, …073 §1 permission additions, …094 plans),
-- idempotently (on conflict do nothing). It is a data restoration, not a
-- schema or authorization change. Source fidelity is verified by
-- scripts/check-reseed-fidelity.mjs (block-scoped exact-set comparison).
--
-- Rows: 16 roles + 61 permissions (59 …030 + 2 …073) + 3 plans +
-- the full role_permissions bundle (426 pairs).
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. Permissions — VERBATIM from …030 §1 (59 rows)
-- ---------------------------------------------------------------------------
insert into public.permissions (code, domain, description) values
    ('organizations.view',        'organizations', 'View organization profile, status, branding'),
    ('organizations.manage',      'organizations', 'Edit organization profile/settings; manage lifecycle'),
    ('users.view',                'users',         'View organization members/worker accounts'),
    ('users.create',              'users',         'Invite/create user accounts in the organization'),
    ('users.update',              'users',         'Update user account details/roles'),
    ('users.suspend',             'users',         'Suspend/reactivate user accounts'),
    ('sites.view',                'sites',         'View sites of the organization'),
    ('sites.create',              'sites',         'Create new sites'),
    ('sites.update',              'sites',         'Update site details'),
    ('sites.delete',              'sites',         'Soft-delete sites'),
    ('incidents.view',            'incidents',     'View incident reports in scope'),
    ('incidents.create',          'incidents',     'Submit incident reports'),
    ('incidents.update',          'incidents',     'Update incident reports in scope'),
    ('incidents.delete',          'incidents',     'Soft-delete incident reports in scope'),
    ('incidents.resolve',         'incidents',     'Resolve/close incident reports'),
    ('incidents.export',          'incidents',     'Export incident data (CSV/report)'),
    ('jsas.view',                 'jsas',          'View JSAs in scope'),
    ('jsas.create',               'jsas',          'Create JSA assessments'),
    ('jsas.update',               'jsas',          'Update JSA assessments in scope'),
    ('jsas.approve',              'jsas',          'Approve JSA assessments'),
    ('inspections.view',          'inspections',   'View inspections in scope'),
    ('inspections.create',        'inspections',   'Start inspections'),
    ('inspections.update',        'inspections',   'Update inspections in scope'),
    ('inspections.complete',      'inspections',   'Complete/close inspections'),
    ('hazards.view',              'hazards',       'View hazard registers in scope'),
    ('hazards.create',            'hazards',       'Log hazards'),
    ('hazards.update',            'hazards',       'Update hazards in scope'),
    ('corrective_actions.view',   'corrective_actions', 'View corrective actions in scope'),
    ('corrective_actions.create', 'corrective_actions', 'Create corrective actions'),
    ('corrective_actions.update', 'corrective_actions', 'Update corrective actions in scope'),
    ('corrective_actions.close',  'corrective_actions', 'Close/verify corrective actions'),
    ('emergency.view',            'emergency',     'View emergency events in scope'),
    ('emergency.activate',        'emergency',     'Activate an emergency/SOS event'),
    ('emergency.acknowledge',     'emergency',     'Acknowledge an emergency event'),
    ('emergency.resolve',        'emergency',     'Resolve/stand down an emergency event'),
    ('notices.view',              'notices',       'View safety notices in scope'),
    ('notices.create',            'notices',       'Create safety notices'),
    ('notices.update',            'notices',       'Update safety notices in scope'),
    ('notices.delete',            'notices',       'Soft-delete safety notices in scope'),
    ('reports.view',              'reports',       'View safety/compliance reports'),
    ('reports.export',            'reports',       'Export reports (CSV/PDF)'),
    ('analytics.view',            'analytics',     'View analytics dashboards in scope'),
    ('documents.view',            'documents',     'View organization documents in scope'),
    ('documents.upload',          'documents',     'Upload documents/evidence'),
    ('documents.delete',          'documents',     'Delete documents in scope'),
    ('training.view',             'training',      'View training records'),
    ('training.manage',           'training',      'Manage training programs/records'),
    ('certificates.view',         'certificates',  'View certificates/competencies'),
    ('certificates.issue',        'certificates',  'Issue certificates'),
    ('equipment.view',            'equipment',     'View equipment register'),
    ('equipment.manage',          'equipment',     'Manage equipment records'),
    ('equipment.inspect',         'equipment',     'Record equipment inspections'),
    ('settings.view',             'settings',      'View organization settings'),
    ('settings.manage',           'settings',      'Edit organization settings'),
    ('audit_logs.view',           'audit',         'View audit logs in scope'),
    ('billing.view',              'billing',       'View subscription/plan/usage'),
    ('billing.manage',            'billing',       'Manage subscription/billing'),
    ('workers.view',              'workers',       'View worker registry in scope'),
    ('workers.manage',            'workers',       'Manage worker registry'),
    ('workers.suspend',           'workers',       'Suspend worker accounts')
on conflict (code) do nothing;

-- …073 §1 additions (2 rows)
insert into public.permissions (code, domain, description) values
    ('inspections.delete',        'inspections',        'Hard delete inspections (admin only)'),
    ('corrective_actions.delete', 'corrective_actions', 'Hard delete corrective actions (admin only)')
on conflict (code) do nothing;

-- ---------------------------------------------------------------------------
-- 2. Roles — VERBATIM from …030 §2 (16 rows)
-- ---------------------------------------------------------------------------
insert into public.roles (code, name, scope, description) values
    ('platform_super_admin',     'Platform Super Administrator', 'platform',     'Owns the platform instance: tenants, org lifecycle, platform ops, emergency support'),
    ('platform_support_admin',   'Platform Support Administrator', 'platform',    'Tiered support access; no data modification outside audited support playbooks'),
    ('platform_auditor',         'Platform Auditor',              'platform',     'Read-only access to audit logs and platform telemetry across tenants'),
    ('national_regulatory_admin', 'National Regulatory Administrator', 'government', 'Configures the regulator org; manages inspector accounts and grants'),
    ('government_safety_inspector', 'Government Safety Inspector', 'government',  'Conducts inspections and reviews authorized org data'),
    ('government_compliance_officer', 'Government Compliance Officer', 'government', 'Monitors compliance/notices/corrective actions on authorized orgs'),
    ('government_analyst',       'Government Analyst',            'government',   'Read-only national analytics and reporting'),
    ('owner',                    'Organization Owner',            'organization', 'Owns the org account, billing/plan, transfers ownership'),
    ('admin',                    'Organization Administrator',    'organization', 'Full org administration: members, sites, roles, settings, data'),
    ('safety_manager',           'Safety Manager',                'organization', 'Manages safety programs org-wide: JSAs, inspections, CAPAs, notices, metrics'),
    ('safety_officer',           'Safety Officer',                'organization', 'Day-to-day safety ops: incident triage, JSA review, inspections, notices'),
    ('site_manager',             'Site Manager',                  'organization', 'Manages a site, its workers and site-level safety operations'),
    ('supervisor',               'Supervisor',                    'organization', 'Approves crew JSAs, reports hazards/incidents, enforces PPE/controls'),
    ('worker',                   'Worker',                        'organization', 'Submits own reports/JSAs, views targeted notices, acknowledges emergencies'),
    ('contractor',               'Contractor',                    'organization', 'Same as worker, contractor-scoped'),
    ('member',                   'Member',                        'organization', 'Legacy inert membership (Phase 02 invites); no active standing by itself')
on conflict (code) do nothing;

-- ---------------------------------------------------------------------------
-- 3. Plans — VERBATIM from …094 (3 rows)
-- ---------------------------------------------------------------------------
insert into public.plans (code, name, max_sites, max_users, features, sort_order) values
    ('starter',    'Starter',           3,  25, '{"jsa":true,"incidents":true,"emergency":true,"notices":true}', 0),
    ('enterprise', 'Enterprise',        null, null, '{"jsa":true,"incidents":true,"emergency":true,"notices":true,"analytics":true,"api":true}', 1),
    ('government', 'Government',        null, null, '{"jsa":true,"incidents":true,"emergency":true,"notices":true,"analytics":true,"grants":true}', 2)
on conflict (code) do nothing;

-- ---------------------------------------------------------------------------
-- 4. Role → permission bundles — VERBATIM from …030 §3 (+ …073 owner/admin
--    additions covered by the "all" / "all except billing.manage" queries).
--    `on conflict do nothing` added for idempotent re-application.
-- ---------------------------------------------------------------------------

-- Platform
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'platform_super_admin'
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'platform_support_admin' and p.code in (
    'organizations.view','users.view','sites.view','incidents.view','jsas.view',
    'inspections.view','hazards.view','corrective_actions.view','emergency.view',
    'notices.view','reports.view','documents.view','analytics.view','audit_logs.view',
    'settings.view','equipment.view','training.view','certificates.view','workers.view')
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'platform_auditor' and p.code in (
    'organizations.view','users.view','sites.view','incidents.view','jsas.view',
    'inspections.view','hazards.view','corrective_actions.view','emergency.view',
    'notices.view','reports.view','documents.view','analytics.view','audit_logs.view',
    'settings.view')
on conflict do nothing;

-- Government
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'national_regulatory_admin' and p.code in (
    'organizations.view','organizations.manage','users.view','users.create','users.update',
    'sites.view','incidents.view','jsas.view','inspections.view','inspections.create',
    'inspections.update','inspections.complete','hazards.view','corrective_actions.view',
    'emergency.view','notices.view','reports.view','reports.export','analytics.view',
    'documents.view','audit_logs.view','settings.view')
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'government_safety_inspector' and p.code in (
    'sites.view','incidents.view','jsas.view','inspections.view','inspections.create',
    'inspections.update','inspections.complete','hazards.view','corrective_actions.view',
    'emergency.view','notices.view','reports.view','documents.view')
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'government_compliance_officer' and p.code in (
    'sites.view','incidents.view','jsas.view','inspections.view','hazards.view',
    'corrective_actions.view','emergency.view','notices.view','reports.view',
    'reports.export','analytics.view','documents.view')
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'government_analyst' and p.code in (
    'sites.view','incidents.view','jsas.view','inspections.view','hazards.view',
    'corrective_actions.view','emergency.view','notices.view','reports.view',
    'reports.export','analytics.view','documents.view')
on conflict do nothing;

-- Organization
-- owner: every permission in the catalog (incl. …073 additions).
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'owner'
on conflict do nothing;

-- admin: everything except billing.manage (org-wide minus billing).
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'admin' and p.code <> 'billing.manage'
on conflict do nothing;

-- safety_manager: org-wide safety program management (no user suspension, no billing, no audit).
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'safety_manager' and p.code in (
    'sites.view','users.view','workers.view','incidents.view','incidents.create',
    'incidents.update','incidents.delete','incidents.resolve','incidents.export',
    'jsas.view','jsas.create','jsas.update','jsas.approve',
    'inspections.view','inspections.create','inspections.update','inspections.complete',
    'hazards.view','hazards.create','hazards.update',
    'corrective_actions.view','corrective_actions.create','corrective_actions.update','corrective_actions.close',
    'emergency.view','emergency.activate','emergency.acknowledge','emergency.resolve',
    'notices.view','notices.create','notices.update','notices.delete',
    'reports.view','reports.export','analytics.view',
    'documents.view','documents.upload','documents.delete',
    'training.view','training.manage','certificates.view','certificates.issue',
    'equipment.view','equipment.manage','equipment.inspect','settings.view')
on conflict do nothing;

-- safety_officer: site-scoped day-to-day ops (no deletes, no approvals/close).
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'safety_officer' and p.code in (
    'sites.view','users.view','incidents.view','incidents.create','incidents.update',
    'jsas.view','jsas.create','jsas.update',
    'inspections.view','inspections.create','inspections.update',
    'hazards.view','hazards.create','hazards.update',
    'corrective_actions.view','corrective_actions.create','corrective_actions.update',
    'emergency.view','emergency.activate','emergency.acknowledge',
    'notices.view','notices.create','notices.update',
    'reports.view','analytics.view','documents.view','documents.upload',
    'equipment.view','settings.view')
on conflict do nothing;

-- site_manager: site-scoped management of its own site (no org-level create/delete).
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'site_manager' and p.code in (
    'sites.view','sites.update','users.view','workers.view',
    'incidents.view','incidents.create','incidents.update',
    'jsas.view','jsas.create','jsas.update',
    'inspections.view','inspections.create','inspections.update','inspections.complete',
    'hazards.view','hazards.create','hazards.update',
    'corrective_actions.view','corrective_actions.create','corrective_actions.update',
    'emergency.view','emergency.activate','emergency.acknowledge',
    'notices.view','notices.create','notices.update',
    'reports.view','documents.view','documents.upload','equipment.view')
on conflict do nothing;

-- supervisor: crew-level (approves crew JSAs; assigned corrective actions).
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'supervisor' and p.code in (
    'sites.view','incidents.view','incidents.create','incidents.update',
    'jsas.view','jsas.create','jsas.update','jsas.approve',
    'inspections.view','inspections.create','inspections.update',
    'hazards.view','hazards.create','hazards.update',
    'corrective_actions.view','corrective_actions.create','corrective_actions.update',
    'emergency.view','emergency.acknowledge',
    'notices.view','notices.create','notices.update','documents.view')
on conflict do nothing;

-- worker / contractor: own reports + targeted notices/emergency/assigned documents.
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code in ('worker', 'contractor') and p.code in (
    'incidents.view','incidents.create','jsas.view','jsas.create',
    'emergency.view','emergency.acknowledge','notices.view','documents.view',
    'certificates.view')
on conflict do nothing;

-- member: legacy inert role — read-only view scope only.
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'member' and p.code in (
    'incidents.view','jsas.view','notices.view','emergency.view')
on conflict do nothing;

commit;

-- Post-condition guard: the catalog must now be non-empty.
do $$
declare
    v_roles int; v_perms int; v_bundles int; v_plans int;
begin
    select count(*) into v_roles from public.roles;
    select count(*) into v_perms from public.permissions;
    select count(*) into v_bundles from public.role_permissions;
    select count(*) into v_plans from public.plans;
    if v_roles < 16 or v_perms < 61 or v_bundles < 400 or v_plans < 3 then
        raise exception 'catalog reseed incomplete: roles=% permissions=% bundles=% plans=%',
            v_roles, v_perms, v_bundles, v_plans;
    end if;
end $$;
