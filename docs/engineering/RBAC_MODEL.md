# MineGuard Liberia — RBAC Model

| Field | Value |
|---|---|
| Doc status | **IMPLEMENTED (Phases 03–04 + 06–09 + 11–12)** — catalogs + helpers live in `20260903000030_phase03_rbac.sql`; site-scoped resolution landed with Phase 04; Phase 06 RLS enforcement over tenant-management tables; safety-domain policies live via Phases 07–09; **Phase 11 (2026-09-09)**: government role family live — regulator users hold government role codes in `organization_members`, grant-gated permission checks evaluated at the regulator org (verified 48/48). **Phase 12 (2026-09-09)**: platform administration flows live via RPC — `bootstrap_first_platform_admin` (one-shot, any active membership disqualifies), `platform_list_organizations` + `platform_update_organization_status` gated on active platform-scope membership (explicit P0001 for others per fix …095); enterprise permission codes `sites.create/update/delete`, `settings.manage`, `billing.manage` now enforced server-side by Phase 12 RPCs. Still open: per-org custom roles (role bundles remain the seeded system mapping), platform role UI surfaces. |
| Last updated | 2026-09-09 |

## 1. Role families

Roles are scoped: **platform**, **government**, **organization**, **site**. A user holds memberships
(`organization_members` / `site_members` / government grants); role = named set of permissions
(`role_permissions`). Granular permission checks are preferred over role-name checks in server logic;
roles are convenience bundles that administrators can also customize per org.

> Phase 03/04 implementation notes: system roles are seeded in the `roles` table (scope platform /
government / organization). Organization role codes are the exact values used by
> `organization_members.role` AND `site_members.role` (owner, admin, safety_manager,
> safety_officer, site_manager, supervisor, worker, contractor, member) so authorization helpers
> join by code. Permission checks go through `auth_user_has_permission(org_id, permission)` (org
> scope, widened by the user's site roles when they hold an org membership),
> `auth_user_has_site_permission(org, site, permission)` (max(org role, site role) at one site),
> `auth_user_site_effective_role` and `auth_user_permissions` — SECURITY DEFINER helpers in the
> database. A user with ONLY site memberships (no org membership) is site-scoped: site helpers
> resolve their access and org-scope helpers return false (no privilege escalation via site rows).

### 1.1 Platform roles
| Role | Purpose |
|---|---|
| Platform Super Administrator | Owns the platform instance: tenants, org lifecycle, platform ops, emergency support |
| Platform Support Administrator | Tiered support access, no data modification outside support playbooks (audited) |
| Platform Auditor | Read-only access to audit logs and platform telemetry across tenants |

### 1.2 Government roles (Liberia regulatory platform)
| Role | Purpose |
|---|---|
| National Regulatory Administrator | Configures regulator org, manages inspector accounts and grants |
| Government Safety Inspector | Conducts inspections and reviews authorized org data |
| Government Compliance Officer | Monitors compliance/notices/corrective actions on authorized orgs |
| Government Analyst | Read-only national analytics and reporting |

### 1.3 Organization roles (per tenant org)
| Role | Typical | Purpose |
|---|---|---|
| Organization Owner | GM / MD | Owns the org account, billing/plan, transfers ownership |
| Organization Administrator | Safety director / IT | Full org administration: members, sites, roles, settings, data |
| Safety Manager | Site/regional safety lead | Manages safety programs org-wide: JSAs, inspections, CAPAs, notices, metrics |
| Safety Officer | Site safety officer | Day-to-day safety ops: incident triage, JSA approval, inspections, notices |
| Site Manager | Mine manager | Manages a site, its workers and site-level safety operations |
| Supervisor | Crew supervisor | Approves crew JSAs, reports hazards/incidents, enforces PPE/controls |
| Worker | Crew member | Submits own reports/JSAs, views targeted notices, acknowledges emergencies |
| Contractor | Contractor staff | Same as worker, organization/contractor-scoped |

### 1.4 Site roles
Site Manager / Supervisor / Worker / Contractor as above but resolved against `site_members`;
Safety Officer can be site-scoped instead of org-wide.

### 1.5 Role inheritance (org → site)
Membership at organization scope implies the same role's capabilities across the org's sites unless
explicitly narrowed by site membership. Permission checks always resolve effective permission
= max(org role, site role). No transitive cross-org inheritance ever.

## 2. Permission catalog (proposed seed)

| Domain | Permissions |
|---|---|
| organizations | `organizations.view`, `organizations.manage` |
| users | `users.view`, `users.create`, `users.update`, `users.suspend` |
| sites | `sites.view`, `sites.create`, `sites.update`, `sites.delete` |
| incidents | `incidents.view`, `incidents.create`, `incidents.update`, `incidents.delete`, `incidents.resolve`, `incidents.export` |
| jsas | `jsas.view`, `jsas.create`, `jsas.update`, `jsas.approve` |
| inspections | `inspections.view`, `inspections.create`, `inspections.update`, `inspections.complete` |
| hazards | `hazards.view`, `hazards.create`, `hazards.update` |
| corrective actions | `corrective_actions.view`, `corrective_actions.create`, `corrective_actions.update`, `corrective_actions.close` |
| emergency | `emergency.view`, `emergency.activate`, `emergency.acknowledge`, `emergency.resolve` |
| notices | `notices.view`, `notices.create`, `notices.update`, `notices.delete` |
| reports | `reports.view`, `reports.export` |
| analytics | `analytics.view` |
| documents | `documents.view`, `documents.upload`, `documents.delete` |
| training/certs | `training.view`, `training.manage`, `certificates.view`, `certificates.issue` |
| equipment | `equipment.view`, `equipment.manage`, `equipment.inspect` |
| settings | `settings.view`, `settings.manage` |
| audit | `audit_logs.view` |
| billing | `billing.view`, `billing.manage` |
| workers | `workers.view`, `workers.manage`, `workers.suspend` |

## 3. Default role → permission mapping (seed; custom per-org later)

- **Platform Super Admin / Platform Auditor**: all permissions at platform scope (auditor: read-only set).
- **National Regulatory Administrator**: grants above + regulator org management.
- **Inspector / Compliance Officer**: read scopes on authorized orgs + inspections.create/update/complete,
  reports.view/export, notices.view.
- **Government Analyst**: analytics.view, reports.view/export, incidents.view (authorized scope).
- **Organization Owner**: everything in the org incl. billing.manage, users.suspend, audit_logs.view.
- **Organization Admin**: org-wide minus billing.manage (settings.manage yes); can manage roles.
- **Safety Manager**: incidents/jsa/inspections/capa/notices/docs manage within org; reports/analytics; no user
  suspension, no billing.
- **Safety Officer**: site-scoped version of manager minus approvals/close where org policy restricts.
- **Site Manager**: sites/manage own site, incidents update, workers.view/update (site).
- **Supervisor**: incidents.create/update (own crew), jsas.approve (crew), notices.view/create(site scope),
  hazards.create.
- **Worker / Contractor**: incidents.create (own), jsas.create (own), emergency.acknowledge, notices.view
  (targeted), documents.view (assigned), own profile/certs view.

Exact matrix lives with RLS_MATRIX.md; enforcement tests in TESTING_STRATEGY.md.
