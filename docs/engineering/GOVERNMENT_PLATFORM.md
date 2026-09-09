# MineGuard Liberia — Government Regulatory Platform

| Field | Value |
|---|---|
| Doc status | **IMPLEMENTED (Phase 11, 2026-09-09) — live-verified on `vuniwebbrvpgxscdsfei` (`verify-phase11.mjs` 48/48 PASS).** The §2 grant model, §3 command-center surfaces (grant-scoped org/site drill-down over incidents + emergency; aggregates server-side views deferred to Phase 12), and §5 enforcement model (grant intersection + role + permission; revocation immediate; audit captured) are live. §4 inspection workflows remain Phase 08/11 target (org inspection flows live via Phase 08; regulator-led inspection authoring not yet surfaced). |
| Last updated | 2026-09-09 |

## 1. Principles

1. Government access is **explicitly authorized and scoped**, never implicit: a regulator user sees only the
   orgs/sites granted to them (role + grant records, audited).
2. Government users authenticate like everyone else; "government" is a role family with its own permission
   set, not a bypass of tenant isolation.
3. Drill-down hierarchy: Liberia → County → Company (org) → Site → Department → Work Zone → Event.
4. All government data and analytics come from authorized backend queries of tenant data, never from client
   copies or screenshots; every regulator access to sensitive records is auditable.
5. The platform supports both national roll-ups (aggregate statistics across authorized orgs) and
   record-level inspection workflows.

## 2. Regulator tenant space

- `organizations` row(s) of type REGULATOR (e.g., Ministry/Mining regulator) managed by
  National Regulatory Administrator.
- `government_grants`: (regulatorOrgId | userId) → (orgId, siteId?, scope, permissions, grantedBy, at,
  expiresAt?) — the explicit authorization record behind every cross-org access.
- Role family: National Regulatory Administrator, Government Safety Inspector, Government Compliance
  Officer, Government Analyst (see RBAC_MODEL.md). Roles resolve to permissions like
  `inspections.create/complete`, `incidents.view` (grant-scope), `reports.export`, `analytics.view`.

## 3. Government command center (target surfaces)

- **National safety overview**: org counts, sites, active critical incidents, open CAPAs, overdue
  inspections, compliance summaries — authorized aggregate roll-ups with drill-down.
- **Mining companies & sites directory** (from grants): company profile, sites, status.
- **Incident trends**: by type, severity, time; critical incidents; recurring-hazard views; per-org/site
  trends (record-level detail only within grant scope).
- **Open corrective actions / overdue inspections / notice & emergency visibility**: aggregated + drill-down.
- **High-risk operations** & worker-safety statistics where org consents / regulation requires.
- **Regulatory reports**: incident statistics, severity/type trends, site safety performance, inspection and
  CAPA compliance, training compliance, emergency statistics, high-risk areas, recurring hazards
  (reports built server-side from authorized queries — REPORTS/analytics formulas documented per
  PROJECT_MASTER non-negotiable #7).

## 4. Inspection & compliance workflows (target, Phase 08/11)

- Government Safety Inspector conducts inspections on an authorized site using org inspection templates or
  regulator templates; findings can raise CAPAs owned by the org; digital sign-off; history retained.
- Compliance monitoring: compare inspection findings vs. org CAPA closure; overdue inspection schedules;
  notice/emergency reporting completeness.
- Reporting duty: orgs can submit required reports (or regulator pulls from authorized data) with audit.

## 5. Enforcement model

- RLS/policy checks combine: regulator grant (org/site scope) + permission + role. Every query is scoped by
  the intersection of (user's regulator grants) with (record's organization_id).
- National roll-ups are computed server-side over the union of the user's granted orgs only; counts must
  never leak another org's presence via error channels.
- Grant lifecycle: issued/revoked with audit; expiry supported; granting requires
  `organizations.manage`-level privilege in the regulator org and is recorded in both orgs' audit views.
- Cross-org access tests (both directions, unauthorized government access denied, revocation effective
  immediately) are required in TESTING_STRATEGY.md §2.
