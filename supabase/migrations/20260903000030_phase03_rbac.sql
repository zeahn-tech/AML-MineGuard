-- ============================================================================
-- MINEGUARD LIBERIA — Phase 03: RBAC + permissions
-- Target database: Supabase (PostgreSQL 15+)
--
-- Implements the RBAC model documented in docs/engineering/RBAC_MODEL.md:
--   * permissions      — the granular permission catalog (60 codes across
--                         domains, from RBAC_MODEL §2)
--   * roles            — named role definitions scoped to platform /
--                         government / organization (RBAC_MODEL §1); system
--                         roles are seeded here, per-org custom roles land in
--                         Phase 12 (SaaS administration)
--   * role_permissions — which role holds which permission (RBAC_MODEL §3
--                         default bundles; owner/admin receive the full org
--                         bundle so Phase 01 helpers keep working unchanged)
--   * organization_members.role is expanded from (owner/admin/member) to the
--     full organization role set. Org role codes in `roles` EXACTLY match the
--     membership role values so helpers can join roles by code.
--
-- Authz helpers added (SECURITY DEFINER, fixed search_path — same pattern as
-- the Phase 01 helpers so Phase 06 RLS policies can call them without
-- recursion/leakage):
--   * auth_user_effective_role(org_id)     -> text | null
--   * auth_user_has_permission(org_id, perm) -> boolean
--   * auth_user_permissions(org_id)        -> setof text
--
-- Phase 03 lands the MODEL + helpers. The full per-table RLS_MATRIX policy
-- set (which calls these helpers) lands in Phase 06; until then all tenant
-- writes remain default-deny and only memberships/org SELECT policies exist.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. Permission catalog
-- ---------------------------------------------------------------------------
create table public.permissions (
    id          uuid primary key default gen_random_uuid(),
    code        text not null unique,          -- e.g. 'incidents.create'
    domain      text not null,                 -- e.g. 'incidents'
    description text,
    created_at  timestamptz not null default now()
);

comment on table public.permissions is
    'Granular permission catalog (RBAC_MODEL §2). Codes are stable API tokens; '
    'role_permissions maps roles to these. Not tenant-scoped — system reference data.';

create index permissions_domain_idx on public.permissions (domain);

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
    ('emergency.resolve',         'emergency',     'Resolve/stand down an emergency event'),
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

-- ---------------------------------------------------------------------------
-- 2. Roles
-- ---------------------------------------------------------------------------
create table public.roles (
    id              uuid primary key default gen_random_uuid(),
    code            text not null unique,     -- stable token; org-role codes equal organization_members.role values
    name            text not null,
    scope           text not null default 'organization'
                    check (scope in ('platform', 'government', 'organization')),
    is_system       boolean not null default true,   -- false => per-org custom role (Phase 12)
    organization_id uuid references public.organizations(id) on delete cascade, -- set only for custom org roles
    description     text,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    check (organization_id is null or scope = 'organization')
);

comment on table public.roles is
    'Named role definitions (RBAC_MODEL §1). Organization role codes are the '
    'canonical values used in organization_members.role. Site-scoped resolution '
    'reuses the same org role codes against site_members (Phase 04).';

create index roles_scope_idx on public.roles (scope);

drop trigger if exists trg_roles_updated_at on public.roles;
create trigger trg_roles_updated_at
    before update on public.roles
    for each row execute function public.set_updated_at();

insert into public.roles (code, name, scope, description) values
    -- Platform
    ('platform_super_admin',     'Platform Super Administrator', 'platform',     'Owns the platform instance: tenants, org lifecycle, platform ops, emergency support'),
    ('platform_support_admin',   'Platform Support Administrator', 'platform',    'Tiered support access; no data modification outside audited support playbooks'),
    ('platform_auditor',         'Platform Auditor',              'platform',     'Read-only access to audit logs and platform telemetry across tenants'),
    -- Government (Liberia regulatory platform, Phase 11)
    ('national_regulatory_admin', 'National Regulatory Administrator', 'government', 'Configures the regulator org; manages inspector accounts and grants'),
    ('government_safety_inspector', 'Government Safety Inspector', 'government',  'Conducts inspections and reviews authorized org data'),
    ('government_compliance_officer', 'Government Compliance Officer', 'government', 'Monitors compliance/notices/corrective actions on authorized orgs'),
    ('government_analyst',       'Government Analyst',            'government',   'Read-only national analytics and reporting'),
    -- Organization (values used by organization_members.role)
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
-- 3. Role -> permission mapping
-- ---------------------------------------------------------------------------
create table public.role_permissions (
    role_id       uuid not null references public.roles(id) on delete cascade,
    permission_id uuid not null references public.permissions(id) on delete cascade,
    granted_at    timestamptz not null default now(),
    primary key (role_id, permission_id)
);

comment on table public.role_permissions is
    'Which role holds which permission (RBAC_MODEL §3). Administrator-customizable '
    'per-org role bundles land with custom roles in Phase 12; until then this is '
    'the seeded system mapping.';

create index role_permissions_permission_id_idx on public.role_permissions (permission_id);

-- Platform
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'platform_super_admin';
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'platform_support_admin' and p.code in (
    'organizations.view','users.view','sites.view','incidents.view','jsas.view',
    'inspections.view','hazards.view','corrective_actions.view','emergency.view',
    'notices.view','reports.view','documents.view','analytics.view','audit_logs.view',
    'settings.view','equipment.view','training.view','certificates.view','workers.view');
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'platform_auditor' and p.code in (
    'organizations.view','users.view','sites.view','incidents.view','jsas.view',
    'inspections.view','hazards.view','corrective_actions.view','emergency.view',
    'notices.view','reports.view','documents.view','analytics.view','audit_logs.view',
    'settings.view');

-- Government
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'national_regulatory_admin' and p.code in (
    'organizations.view','organizations.manage','users.view','users.create','users.update',
    'sites.view','incidents.view','jsas.view','inspections.view','inspections.create',
    'inspections.update','inspections.complete','hazards.view','corrective_actions.view',
    'emergency.view','notices.view','reports.view','reports.export','analytics.view',
    'documents.view','audit_logs.view','settings.view');
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'government_safety_inspector' and p.code in (
    'sites.view','incidents.view','jsas.view','inspections.view','inspections.create',
    'inspections.update','inspections.complete','hazards.view','corrective_actions.view',
    'emergency.view','notices.view','reports.view','documents.view');
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'government_compliance_officer' and p.code in (
    'sites.view','incidents.view','jsas.view','inspections.view','hazards.view',
    'corrective_actions.view','emergency.view','notices.view','reports.view',
    'reports.export','analytics.view','documents.view');
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'government_analyst' and p.code in (
    'sites.view','incidents.view','jsas.view','inspections.view','hazards.view',
    'corrective_actions.view','emergency.view','notices.view','reports.view',
    'reports.export','analytics.view','documents.view');

-- Organization
-- owner: every permission in the catalog.
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'owner';
-- admin: everything except billing.manage (org-wide minus billing).
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'admin' and p.code <> 'billing.manage';
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
    'equipment.view','equipment.manage','equipment.inspect','settings.view');
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
    'equipment.view','settings.view');
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
    'reports.view','documents.view','documents.upload','equipment.view');
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
    'notices.view','notices.create','notices.update','documents.view');
-- worker / contractor: own reports + targeted notices/emergency/assigned documents.
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code in ('worker', 'contractor') and p.code in (
    'incidents.view','incidents.create','jsas.view','jsas.create',
    'emergency.view','emergency.acknowledge','notices.view','documents.view',
    'certificates.view');
-- member: legacy inert role — read-only view scope only.
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'member' and p.code in (
    'incidents.view','jsas.view','notices.view','emergency.view');

-- ---------------------------------------------------------------------------
-- 4. organization_members.role: expand the allowed organization roles
-- ---------------------------------------------------------------------------
alter table public.organization_members
    drop constraint if exists organization_members_role_check;

alter table public.organization_members
    add constraint organization_members_role_check
    check (role in (
        'owner', 'admin', 'safety_manager', 'safety_officer', 'site_manager',
        'supervisor', 'worker', 'contractor', 'member'
    ));

-- ---------------------------------------------------------------------------
-- 5. Authorization helpers (Phase 03 RBAC layer)
-- ---------------------------------------------------------------------------
create or replace function public.auth_user_effective_role(p_organization_id uuid)
returns text
language sql
stable
security definer
set search_path = public
as $$
    select m.role
    from public.organization_members m
    where m.organization_id = p_organization_id
      and m.user_id = auth.uid()
      and m.status = 'active'
    limit 1;
$$;

comment on function public.auth_user_effective_role(uuid) is
    'Phase 03 RBAC: the current user''s active role in the organization, or null.';

create or replace function public.auth_user_has_permission(p_organization_id uuid, p_permission text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.organization_members m
        join public.roles r          on r.code = m.role
        join public.role_permissions rp on rp.role_id = r.id
        join public.permissions p    on p.id = rp.permission_id
        where m.organization_id = p_organization_id
          and m.user_id = auth.uid()
          and m.status = 'active'
          and p.code = p_permission
    );
$$;

comment on function public.auth_user_has_permission(uuid, text) is
    'Phase 03 RBAC: true when the current user''s active org role holds the permission. '
    'This is the primitive Phase 06 RLS policies and future RPCs call.';

create or replace function public.auth_user_permissions(p_organization_id uuid)
returns setof text
language sql
stable
security definer
set search_path = public
as $$
    select distinct p.code
    from public.organization_members m
    join public.roles r          on r.code = m.role
    join public.role_permissions rp on rp.role_id = r.id
    join public.permissions p    on p.id = rp.permission_id
    where m.organization_id = p_organization_id
      and m.user_id = auth.uid()
      and m.status = 'active'
$$;

comment on function public.auth_user_permissions(uuid) is
    'Phase 03 RBAC: the current user''s permission codes within the organization (for UI mirroring).';

revoke all on function public.auth_user_effective_role(uuid) from public;
revoke all on function public.auth_user_has_permission(uuid, text) from public;
revoke all on function public.auth_user_permissions(uuid) from public;
grant execute on function public.auth_user_effective_role(uuid) to anon, authenticated;
grant execute on function public.auth_user_has_permission(uuid, text) to anon, authenticated;
grant execute on function public.auth_user_permissions(uuid) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- 6. RLS on RBAC catalogs
-- ---------------------------------------------------------------------------
-- roles/permissions/role_permissions hold system reference data (no tenant
-- rows until Phase 12 custom org roles). Any authenticated user may read the
-- catalogs; writes remain default-deny (managed by migrations/service role).
alter table public.permissions      enable row level security;
alter table public.roles            enable row level security;
alter table public.role_permissions enable row level security;

drop policy if exists "permissions_select_authenticated" on public.permissions;
create policy permissions_select_authenticated on public.permissions
    for select to authenticated using (true);

drop policy if exists "roles_select_authenticated" on public.roles;
create policy roles_select_authenticated on public.roles
    for select to authenticated using (true);

drop policy if exists "role_permissions_select_authenticated" on public.role_permissions;
create policy role_permissions_select_authenticated on public.role_permissions
    for select to authenticated using (true);

-- ---------------------------------------------------------------------------
-- 7. Privileges (Supabase convention: base privileges + RLS for row filtering)
-- ---------------------------------------------------------------------------
grant select on table public.permissions, public.roles, public.role_permissions
    to anon, authenticated;
grant insert, update, delete on table public.permissions, public.roles, public.role_permissions
    to authenticated;

commit;