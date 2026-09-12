# MineGuard — Supabase Backend (Phase 01 foundation)

Backend decision: **Supabase** (PostgreSQL + PostgREST + Auth + Storage), decided 2026-09-03 —
see `docs/engineering/DECISIONS.md` ADR-008. PostgREST's plain-HTTPS JSON API is reachable with
`fetch()` from the vanilla no-build PWA — consistent with the app's restricted-network requirement.

## Live status (2026-09-10)

Phase 05 cutover (fresh-start, ADR-014) is COMPLETE: migrations `…097_phase05_cutover_notices.sql`
(`safety_notices` + `safety_notice_acks` + 2 audit triggers → 23 total) and `…098` (probe-driven
`notice_soft_delete` SECURITY DEFINER RPC) applied 2026-09-10; `verify-phase05.mjs` 42/42 PASS
self-cleaning. The Firestore data import was WAIVED by the owner — tenants start with empty
safety-domain tables; the legacy Firestore channel is fallback-only (signed-out users).
Phase 13 (production hardening + security certification) is COMPLETE: migration
`…096_phase13_hardening.sql` (`site_create` max_sites enforcement + `regulator_expire_due_grants()`
audited expiry sweep) applied 2026-09-10; `verify-phase13.mjs` 27/27 PASS self-cleaning; full suite:
`npm test` (security scan + all live probes).
Phase 12 (SaaS + enterprise administration) is COMPLETE — see
`docs/engineering/IMPLEMENTATION_STATUS.md` §Phase 12. Migrations `…094` (plans/subscriptions,
site/settings/subscription/platform/grant-expiry RPCs, `gov_national_overview()`, subscriptions audit
trigger — 21 total) and probe-driven fix `…095` (grant-issue result capture, audit_log column names,
platform-list explicit gate, legacy 4-arg grant overload dropped for PostgREST PGRST203 resolution)
applied; `verify-phase12.mjs` 31/31 PASS self-cleaning. Phase 11 (Government regulatory command
center) is COMPLETE — migrations `…090`–`…093` applied; `verify-phase11.mjs` 48/48 PASS. Phase 10
(offline-first sync), Phase 09 (emergency + SOS), Phase 08 (JSA + inspection + CAPA), Phase 07
(incidents + evidence), and Phase 06 (RLS + security) all COMPLETE.

**Security note (Phase 13):** `scripts/run-probes.sh` previously hard-coded the service-role key + DB
password (now removed; env-injected). Those credentials MUST be rotated in the Supabase dashboard —
see `docs/engineering/SECURITY_CERTIFICATION.md` §2.
Phase 05 (data migration) prep remains PARTIALLY COMPLETE: nothing has been imported; prep artifacts live in two GITIGNORED dirs (they
contain worker names/badges/incident data — never push them):

- `supabase/legacy-inventory/` — read-only Firestore snapshot (all 5 collections; photos retained) via
  `node scripts/phase05-inventory.mjs`.
- `supabase/migration-prep/` — target payloads (`payloads/*.ndjson`), photo storage manifest,
  `mapping-report.json` (validation baseline) and `review-lists.json` via `node scripts/phase05-map.mjs`.
  Org-owner review answers go in `supabase/migration-prep/overrides.json`; re-runs are deterministic.

Applied and smoke-verified on project `vuniwebbrvpgxscdsfei`:
- Migrations `20260903000000_tenant_foundation.sql` (Phase 01 tenancy) +
  `20260903000010_grant_standard_privileges.sql` (standard grants) +
  `20260903000020_phase02_auth_onboarding.sql` (auth onboarding) +
  `20260903000030_phase03_rbac.sql` (RBAC) +
  `20260903000040_phase04_site_hierarchy.sql` + `20260903000041_phase04_fixes.sql`
  (Phase 04 hierarchy) — all pushed via Supabase CLI (Management API).
- Seed applied (ArcelorMittal Liberia tenant #1 + Nimba Mine / Port Operations sites + Liberia regulator
  placeholder org).
- Phase 01: RLS enabled on tenancy tables; anon SELECT → 200 with **0 rows**;
  `auth_user_has_org_access(anon)` → `false`; elevated queries confirm seed rows.
- Phase 02: `bootstrap_first_owner()` + self-service membership policies live-verified with a probe user.
- Phase 03: RBAC catalogs (`permissions` 60 / `roles` 16 / `role_permissions` seeded) +
  `auth_user_has_permission` / `auth_user_effective_role` / `auth_user_permissions` helpers;
  anon RPCs → false/null; full owner/worker/outsider probe matrix PASS (30/30) via
  `scripts/verify-rbac.mjs` (self-cleaning).
- Phase 04: `organizational_units` / `site_members` / `workers` / `org_invites` +
  site-scoped helpers (`auth_user_site_effective_role` / `auth_user_has_site_access` /
  `auth_user_has_site_permission`); `auth_user_has_permission` upgraded to max(org role,
  site role) for org members; org-admin/site-manager SECURITY DEFINER RPCs (members,
  invites, units, workers); permission catalog 60 → 62. Probe matrix 58/58 PASS via
  `scripts/verify-phase04.mjs` (self-cleaning).
- Phase 06: `sites`/`organizational_units` site-scope SELECT (`auth_user_has_site_access`),
  least-privilege `workers` SELECT (`workers.view`/`users.view`), `organizations` UPDATE
  gate (owner/admin), and an append-only server-side `audit_log` — SELECT for org members
  with `audit_logs.view`, DML revoked, SECURITY DEFINER trigger `trg_audit_capture()` on
  all 7 tenant-management tables incl. `sites` (migrations `…050`–`…053`; actor =
  `auth.uid()`, invite tokens never mirrored, org-delete/cascade rows retained as
  platform-scope history). RLS/audit probe all-PASS via `scripts/verify-phase06.mjs`;
  org cascade-delete regression all-PASS via `scripts/verify-phase06-cascade.mjs`.
- Re-run checks anytime: `scripts/verify-supabase.mjs` (non-mutating),
  `scripts/verify-rbac.mjs` (Phase 03 probe), `scripts/verify-phase04.mjs` (Phase 04
  probe), `scripts/verify-phase06.mjs` (Phase 06 RLS/audit probe),
  `scripts/verify-phase06-cascade.mjs` (org cascade-delete + audit-retention regression)
  `scripts/verify-phase07.mjs` (Phase 07 incidents + evidence + witnesses RLS matrix,
  storage authorization, tenant isolation, audit, cleanup),
  `scripts/verify-phase08.mjs` (Phase 08 JSA/inspections/CAPA RLS matrix, tenant isolation,
  audit, cleanup) and `scripts/verify-phase09.mjs` (Phase 09 emergency/SOS RLS matrix,
  lifecycle guards, ack idempotency, append-only emergency_log, tenant isolation, audit,
  cleanup) — each live probe creates +
  removes its own scratch org/users; needs `SUPABASE_ACCESS_TOKEN`. URL/anon key fall back
  to `config.js` (public by design); the access token is never read from the repo.

Do not edit already-applied migrations (checksum drift) — append new ones.

## Layout

```
supabase/
├── migrations/
│   ├── 20260903000000_tenant_foundation.sql             ← Phase 01 DDL (tenancy, apply first)
│   ├── 20260903000010_grant_standard_privileges.sql     ← Phase 01 follow-up (base grants)
│   ├── 20260903000020_phase02_auth_onboarding.sql       ← Phase 02 (bootstrap owner + membership RLS)
│   ├── 20260903000030_phase03_rbac.sql                  ← Phase 03 (permissions/roles/role_permissions + authz helpers)
│   ├── 20260903000040_phase04_site_hierarchy.sql        ← Phase 04 (site_members/units/workers/invites + RPCs + RLS)
│   ├── 20260903000041_phase04_fixes.sql                 ← Phase 04 fix (core-only invite tokens; email::text cast)
│   ├── 20260903000050_phase06_rls_audit.sql             ← Phase 06 (site-scope SELECT matrix + org UPDATE gate + audit_log + audit triggers)
│   ├── 20260903000051_phase06_fix_org_delete_audit.sql  ← Phase 06 fix (org-delete audit path: SET NULL + nulled scope)
│   ├── 20260903000052_phase06_fix_cascade_org_delete.sql← Phase 06 fix (cascade-delete audit rows, org_id null)
│   ├── 20260903000053_phase06_add_sites_audit.sql       ← Phase 06 fix (sites audit trigger — gap closed)
│   ├── 20260903000060_phase07_incidents.sql              ← Phase 07 (incidents/evidence/witnesses + RLS + audit triggers)
│   ├── 20260903000061_phase07_storage_evidence.sql      ← Phase 07 (incident-evidence private bucket + storage.objects policies)
│   ├── 20260903000070_phase08_jsas.sql                  ← Phase 08 (jsas + jsa_steps + RLS + audit triggers)
│   ├── 20260903000071_phase08_inspections_capa.sql       ← Phase 08 (inspections + corrective_actions + RLS + audit triggers)
│   ├── 20260903000072_phase08_fix_select_policies.sql    ← Phase 08 fix (inspection SELECT restriction + CAPA site-member SELECT)
│   ├── 20260903000073_phase08_fix_delete_and_update_policies.sql ← Phase 08 fix (delete permissions + CAPA update for site members)
│   ├── 20260903000080_phase09_emergency_sos.sql          ← Phase 09 (emergency_events/acks/escalations/responders/log + lifecycle + RLS + audit)
│   ├── 20260903000081_phase09_fix_child_authz.sql        ← Phase 09 fix (site-scope acknowledge for child ops)
│   ├── 20260903000082_phase09_fix_escalation_gate.sql    ← Phase 09 fix (dedicated escalation role gate)
│   ├── 20260903000083_phase09_fix_child_guard.sql        ← Phase 09 fix (child guard — no created_by on responders)
│   └── 20260903000084_phase09_fix_responder_gate.sql     ← Phase 09 fix (responder gate = response chain; helper dropped)
├── seed.sql                                              ← tenant #1 (AML) + regulator placeholder (idempotent)
└── README.md
```

Phase mapping (docs/engineering/IMPLEMENTATION_STATUS.md): 02 auth/identity COMPLETE · 03 RBAC COMPLETE ·
04 site hierarchy COMPLETE · 05 data migration from Firestore PARTIALLY_COMPLETE (prep: measured volumes
+ mapping/validation baseline; import gated on the durable user-owned export/backup ADR-003, target
safety-domain tables from Phases 08–09, and org-owner review sign-off) · 06 RLS + security enforcement
COMPLETE (Phases 01–04 tables + audit foundation; live-verified) · 07 incident + evidence management
COMPLETE (live-verified 2026-09-04: `…060`/`…061` applied; `verify-phase07.mjs` all-PASS;
Phase 06 regression green) · 08 JSA + inspection + corrective actionsCOMPLETE (live-verified 2026-09-04: `…070`–`…073` applied; `verify-phase08.mjs` all-PASS;
Phase 06/07 regression green) · 09 Emergency response + SOS COMPLETE
(live-verified 2026-09-04: `…080`–`…084` applied; `verify-phase09.mjs` all-PASS;
Phase 06/07/08 regression green) · 10+ remaining safety-domain tables (notices,
documents, …) with their RLS.

## Environment variables (managed env — set in Settings → Environment / Keys)

| Var | Used for | Public? |
|---|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | PostgREST/Auth base URL in the client | public |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Client `apikey` header (RLS does the security). New-format key: `sb_publishable_…` | public |
| `SUPABASE_SERVICE_ROLE_KEY` | Verification/admin ops (never ship to client). New-format key: `sb_secret_…` | **secret** |
| `SUPABASE_DB_URL` | Direct SQL apply/verify (`postgresql://…` with password) | **secret** |
| `SUPABASE_ACCESS_TOKEN` | (optional) `supabase` CLI link + `db push` (personal token `sbp_…`) | **secret** |

## Apply & verify (needs project credentials)

Option A — Supabase CLI against the project:
```bash
npx supabase db push --db-url "$SUPABASE_DB_URL"     # applies supabase/migrations/*
psql-like apply of seed.sql via SQL editor or:        # seed
npx supabase db push --db-url "$SUPABASE_DB_URL" --include-all  # (or paste seed.sql in the SQL editor)
```

Option B — paste `20260903000000_tenant_foundation.sql` then `seed.sql` into the
Supabase **SQL editor**.

Smoke checks (SQL editor):
```sql
select slug, name, org_type from public.organizations;            -- expect AML tenant #1 + regulator
select count(*) from public.sites;                                 -- expect 2 for AML
select public.auth_user_has_org_access('00000000-0000-0000-0000-000000000000');  -- expect false (no session)
```

RLS check (must run as an authenticated user, e.g. from the app after Phase 02 auth):
Company-A member selecting org B's rows must return zero rows.

## Client conventions (Phase 02+)

- Plain `fetch` to `${NEXT_PUBLIC_SUPABASE_URL}/rest/v1/…` with headers
  `apikey: <anon key>`, `Authorization: Bearer <session token>`.
- Server-side enforcement is RLS — never client filtering. Queries still scope by
  `organization_id` so RLS and indexes agree (per `docs/engineering/RLS_MATRIX.md`).
- Do not commit real keys; keep the anon key out of git history once live.

## Hard rules

1. Never put the service-role key or DB URL in client code or commit them.
2. Phase 01 gating: migrations applied + RLS smoke-tested on the live project BEFORE
   Phase 02 consumes this schema. Until then this schema is authored-but-UNVERIFIED.
3. All safety-domain tables follow the org-scoped conventions in this migration.
