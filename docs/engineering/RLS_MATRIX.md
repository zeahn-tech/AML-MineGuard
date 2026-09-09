# MineGuard Liberia — RLS Matrix (tenant & role access per table)

| Field | Value |
|---|---|
| Doc status | **Phase 12 LANDED (2026-09-09, project `vuniwebbrvpgxscdsfei`)** — SaaS layer: `plans` readable by anon+authenticated (public pricing), `subscriptions` SELECT gated to the owning org's members (anon = 0 rows, probe-verified); site/settings/subscription/platform writes are RPC-only (SECURITY DEFINER, permission-gated server-side, no direct table grants beyond SELECT). **Phase 11 LANDED + LIVE-VERIFIED** — government grant-gated regulator SELECT (16 policies: incidents/evidence/witnesses/jsas/inspections/CAPA/emergency×5/sites/units/workers/org-members/audit_log; every policy requires an active `government_grants` row covering (org, site); permission checks evaluated at the REGULATOR org per fix …091; verify-phase11 48/48 PASS). Phases 06–10 LANDED as previously recorded. Enforcement backend (ADR-008): **Supabase PostgreSQL RLS**. Remaining: §1.5 notices, §1.7 documents (Phase 10+). |
| Last updated | 2026-09-09 |

Legend: **S**elect · **I**nsert · **U**pdate · **D**elete (soft-delete flag); hard purge is a separate,
audited, admin-only permission. Scope prefix: `org:` = records of user's organization; `site:` = records of
user's site(s); `granted:` = org/site explicitly granted to the role (e.g., regulator authorization).

Placeholder users: `SYS` platform admin · `GOV` government roles · `OWN` org owner/admin · `SMGR` safety
manager · `SOFF` safety officer · `SM` site manager · `SUP` supervisor · `WRK` worker · `CTR` contractor.

## 1. Core matrices (target)

### 1.1 Tenancy & identity tables

Phase 04 concrete state: `organization_members` (owner/admin S,I,U via RPC; others S own+org),
`site_members` (S own row or org member; assign/remove via RPC by owner/admin or that site's
site_manager), `organizational_units` (S org member; create/update/soft-delete via RPC gated on
`organizational_units.create/.update` or org admin), `workers` (S org member; add/update/remove via RPC
gated on `workers.manage` or org admin), `org_invites` (S org member; send/revoke via RPC by
owner/admin; accept by the invited email).

| Table | SYS | GOV | OWN | SMGR | SOFF | SM | SUP | WRK/CTR |
|---|---|---|---|---|---|---|---|---|
| organizations | S (all) | S (authorized) | S,I,U (own) | – | – | – | – | – |
| organization_members | S,I,U | – | S,I,U (own) | S (org) | – | – | – | – |
| sites | S | S (authorized) | S,I,U (own) | S | S | S,U (site) | S | S (assigned site) |
| departments/teams | S | S (auth) | S,I,U (own) | S,I,U | S,U | S,U (site) | S | S (own team) |
| roles/permissions | S,I,U,D | – | S (org roles) | S | – | – | – | – |
| users | S | S (auth) | S,I,U (org members) | S | S | S | S | – |

### 1.2 Safety domain (rows carry organization_id; workers additionally site/team-bound)

| Table | SYS | GOV | OWN/ORG-ADMIN | SAFETY MGR | SAFETY OFFICER | SITE MGR | SUPERVISOR | WORKER/CONTRACTOR |
|---|---|---|---|---|---|---|---|---|
| incidents (org) | S | S,I(create ref.) | S,I,U,D | S,I,U,D | S,I,U | S,I,U(site) | I,U(site, own reports) | I(own), S(own + site-notice scope) |
| incident_evidence/photo refs | S | S | S,I,U,D | S,I,U,D | S,I,U | S,I,U | I(own) | I(own) |
| incident witnesses/injuries | S | S | S,I,U | S,I,U | S,I,U | S,U | I,U(own) | I(own) |
| jsas | S | S | S,I,U,D | S,I,U,D,approve | S,I,U | S,I,U | S,I,U,approve(crew) | I(own), S(own) |
| inspections (+templates/items) | S | S,I(finding) | S,I,U,D | S,I,U,D | S,I,U,D | S,I,U,D | S,I,U | – (attend) |
| corrective_actions | S | S | S,I,U,D,close | S,I,U,D,close | S,I,U,verify | S,I,U | I,U(assigned) | – |
| notices | S | S | S,I,U,D | S,I,U,D | S,I,U | S,I,U | I,U (target scope) | S (targeted), ack |
| notice_acks/reads | S | S | S | S | S | S | S | I(own) |
| documents | S | S (auth) | S,I,U,D | S,I,U,D | S,I,U | S,I,U (site) | S (assigned) | S (assigned docs only) |
| risk_matrices | S | S | S,U (org) | S,U | S | S | – | – |
| emergency_events | S | S | S,I,U,D(close) | S,I,U | S,I,U(activate) | S,I,U | S,I(alert) | S (site alert), ack |
| emergency_acks/escalations | S | S | S | S | S,I,U | S | S,I | I(own ack) |
| equipment/training certs | S | S | S,I,U,D | S,I,U,D | S,I,U | S,I,U | S | S (own cert) |

### 1.3 Governance tables

| Table | SYS | GOV | OWN | Others |
|---|---|---|---|---|
| audit_log | S | S (authorized scope) | S (own org) | – (never write from client) |
| subscriptions/plans/usage | S,I,U | – | S,U (own) | – |
| notifications | S | – | S,I (org) | S/I (own inbox), acks own |

## 2. Rules of thumb enforced server-side

1. Every query/mutation is implicitly constrained to the actor's org scope first (equivalent of
   `WHERE organization_id = authUserOrgScope(uid)`), except explicit cross-org grants.
2. Site-scoped access never exceeds org scope; role in org hierarchy implies role in all child sites unless
   overridden to narrower.
3. Workers see only: their own submitted records, targeted notices, active site emergency state, assigned
   training/certs. They never SELECT the full org incident/JSA pool.
4. Regulator/government access is per explicit, audited authorization (org or site grant); there is no
   "government sees everything by default" (see GOVERNMENT_PLATFORM.md).
5. Platform SYS access is used for operations support/audit only and is itself audited; it is not the model
   for normal users.
6. Hard DELETE/purge is not granted broadly: restricted to SYS/OWN with `documents.delete`-class permission
   and always audits; normal U/D rows use soft-delete semantics.
7. Client-side UI simply mirrors these rules; nothing depends on UI hiding for enforcement.

## 3. Testing requirement

Every cell above that grants access must have a positive test; every blank cell a negative test —
tenant isolation tests in `TESTING_STRATEGY.md` §2 prove Company A cannot S/I/U/D Company B rows,
files, realtime events, settings, or analytics, in both directions, plus same-org/different-site,
government-authorized and unauthorized, and platform-admin cases.
