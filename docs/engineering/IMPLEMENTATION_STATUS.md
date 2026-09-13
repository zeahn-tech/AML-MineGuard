# MineGuard Liberia — Implementation Status (authoritative)

| Field | Value |
|---|---|
| Last updated | 2026-09-10 |
| Session | Phase 05 cutover COMPLETE (session 17, 2026-09-10) — fresh-start directive (ADR-014): Firestore import waived; migrations `…097`/`…098` applied live (safety_notices + acks + soft-delete RPC); client `notices.js` cut over to PostgREST for signed-in users; `verify-phase05.mjs` 42/42 PASS self-cleaning; full probe suite all-PASS. Prior: Phase 13 COMPLETE (session 16) — production hardening + security certification: secret-leak incident remediated (run-probes.sh service-role key + DB password removed; **rotations still REQUIRED by the user** — SECURITY_CERTIFICATION §2); automated security scan in `npm test` (0 CRITICAL baseline); durable suite = one command; migration `…096` applied live; `verify-phase13.mjs` 27/27 PASS self-cleaning. Detail below |

Status vocabulary: NOT_STARTED · IN_PROGRESS · BLOCKED · PARTIALLY_COMPLETE · COMPLETE · VERIFIED
(VERIFIED requires evidence: tests/outputs recorded here).

---

## Phase 00 — Architecture audit + engineering documentation

**Status: COMPLETE (documentation written; no code changed)** — see session-1 entry below (kept for history).

Completed work
- Full repository inspection (all 17 working files, ~10,900 lines: `index.html`, `admin.html`, `app.js`,
  `firebase.js`, `notices.js`, `lang.js`, `data.js`, `sw.js`, `style.css`, `manifest.json`, `version.json`,
  `firebase_rest_test.html`, `admin_sync_diagnostic.html`, `README.md`, icons, APK).
- Security/architecture audit documented across `ARCHITECTURE.md`, `SECURITY_MODEL.md`,
  `DATABASE_ARCHITECTURE.md`, `RLS_MATRIX.md`, `RBAC_MODEL.md`, `MINING_DOMAIN_MODEL.md`,
  `OFFLINE_SYNC_ARCHITECTURE.md`, `EMERGENCY_RESPONSE_ARCHITECTURE.md`, `GOVERNMENT_PLATFORM.md`,
  `MIGRATION_PLAN.md`, `TESTING_STRATEGY.md`, `PRODUCTION_READINESS.md`, `DECISIONS.md`,
  `PROJECT_MASTER.md`, `CHANGELOG.md`, `SESSION_HANDOFF.md`.

Incomplete work (by design — Phase 00 scope)
- Firestore console verification (security rules content, auth users, real data volume) is **not possible from
  this repository** (rules live in the Firebase console, not in the repo). Flagged as first Phase 01 action.
- No code changes were made; per phase order, Phases 01+ are not started.

Known issues / critical findings — see `SESSION_HANDOFF.md` §Findings and `SECURITY_MODEL.md` §Findings.
Top 3: (C1) no real authentication anywhere — admin gate is client-side JS vs. hard-coded default
`admin`/`mineguard2024` and localStorage overrides; (C2) Firestore accessed REST-style with only the
embedded API key, no identity — every client acts with equal privilege over all collections; (C3) zero
tenant isolation — single flat collections shared by every device.

Files changed: none (documentation only). Database changes: none. Migrations: none.
Tests performed: none (no test infrastructure exists in the repo).
Security findings: documented C1–C7, H1–H5, M1–M3, L1–L3 in `SESSION_HANDOFF.md`/`SECURITY_MODEL.md`.

Next actions (Phase 01, defined in `SESSION_HANDOFF.md`): identity + org foundation + data-plane gate.

---## Phase 01 — Multi-tenant organization database foundation

**Status: COMPLETE (schema applied to live Supabase project and smoke-verified 2026-09-03)**

Decision (2026-09-03, user directive): **Supabase is the backend** — ADR-008 in `DECISIONS.md`.
Firestore data will migrate into Supabase Postgres (Phase 05). ADR-005 recommendation superseded.

Completed work
- Backend-path decision recorded (ADR-008) and propagated to PROJECT_MASTER / ARCHITECTURE /
  DATABASE_ARCHITECTURE / RLS_MATRIX docs.
- `supabase/migrations/20260903000000_tenant_foundation.sql` — Phase 01 DDL: `organizations`, `sites`,
  `organization_members` (uuid PKs, `organization_id` FKs, soft-delete, unique + query indexes,
  updated_at triggers); authz helpers (`current_user_org_ids()`, `auth_user_has_org_access(uuid)`,
  `auth_user_is_org_admin(uuid)`); RLS enabled with membership-scoped SELECT policies.
- `supabase/migrations/20260903000010_grant_standard_privileges.sql` — Supabase-standard role grants
  (anon SELECT only; authenticated DML behind RLS; helper EXECUTE; default privileges for future tables)
  after initial push surfaced 42501 privilege denials.
- `supabase/seed.sql` — idempotent tenant #1 (ArcelorMittal Liberia) + Nimba Mine / Port Operations sites
  + Liberia regulator placeholder org.
- `scripts/verify-supabase.mjs` — zero-dep connectivity/RLS smoke checker (PASS/FAIL/INFO semantics).
- `supabase/README.md` + `.gitignore` (env files, `supabase/.temp/`) + `package.json`
  (`devDependencies: supabase`) + `package-lock.json`.
- Preview/dev harness (session-2): `server.mjs` static dev server — verified ready.

Applied + verified on project `vuniwebbrvpgxscdsfei` (evidence):
- `supabase db push` applied both migrations; seed applied via Management API (HTTP 201).
- Elevated queries confirm: organizations = [arcelormittal-liberia (mining_company, active),
  liberia-regulator (regulator, active)]; sites under AML = 2 (Nimba Mine, Port Operations).
- `relrowsecurity = true` on organizations / sites / organization_members; 3 helper functions present.
- PostgREST as anon: organizations → HTTP 200, **0 rows** (RLS works; not a privilege error);
  `rpc auth_user_has_org_access` (anon) → `false`.

Known limitations (recorded, do not overstate)
- No formal automated unit-test suite yet (harness exists; TESTING_STRATEGY rollout starts Phase 02).
  Verification = recorded smoke checks above, not VERIFIED-tier evidence.
- Full RLS_MATRIX policy set + safety-domain tables are Phases 02–09 by design (writes remain
  service-role/default-deny until onboarding + auth land in Phase 02).
- Firebase `aml-mineguard` export/backup still owed by user before Phase 05 migration (ADR-003).

Phase 02 (auth + identity) and Phase 03 (RBAC) are COMPLETE — see sections below. Next action per phase order: Phase 05 (in progress, session 8).

---

## Phase 02 — Authentication + identity (Supabase Auth)

**Status: COMPLETE (implemented + live-verified 2026-09-03; evidence recorded below)**

Completed work
- `config.js` (publishable Supabase URL/anon key — public by design; RLS is the boundary).
- `supabase-auth.js` — zero-dependency GoTrue REST client (signUp, signInWithPassword, signOut,
  ensureSession w/ refresh, getUser, fetchMyMemberships, fetchOrganization, onAuthChange,
  bootstrapFirstOwner via `/rest/v1/rpc/bootstrap_first_owner`). Sessions in localStorage
  (`mg_auth_session`: access/refresh tokens + expiry; **passwords never stored**; legacy
  `mg_admin_pass` plaintext key is purged on load).
- `index.html` worker app: additive account chip + sign-in/sign-up/out modal (`auth-ui.js`, EN/FR via
  `lang.js`); signed-out reporting keeps working exactly as before (identity optional for workers in
  Phase 02). Scripts registered in `sw.js` cache.
- `admin.html` gate replaced: no more `admin`/`mineguard2024`/localStorage password logic. Login is
  email+password against Supabase Auth; dashboard unlocks only for an ACTIVE owner/admin membership;
  silent session restore (offline-friendly); logout calls GoTrue sign-out; Settings no longer stores a
  password (username row became "Safety Officer Name"); actor identity on soft-deletes/records now comes
  from the signed-in email (`getAdminActorName()`); topbar badge shows the identity.
- `supabase/migrations/20260903000020_phase02_auth_onboarding.sql` (applied): `bootstrap_first_owner()`
  SECURITY DEFINER RPC (first authenticated user claims the first ACTIVE `mining_company` org with no
  active members as OWNER; regulator/platform orgs never claimable; raises once ownership exists) +
  self-service membership policies: INSERT only own `member`/`invited` inert row, UPDATE own row only
  to withdraw (`removed`) — self-promotion to owner/admin/active is impossible via RLS (42501).

Applied + live-verified on `vuniwebbrvpgxscdsfei` (evidence):
- Migration pushed via CLI; proc ACL shows `bootstrap_first_owner` granted to `authenticated` only.
- pg_policies confirms the 3 membership policies (select self/org; insert self-invited w/ WITH CHECK;
  update self-invited w/ WITH CHECK) — all with the intended quals.
- End-to-end with a real (temporary, confirmed) probe user over PostgREST:
  non-member org SELECT → 200 `[]`; INSERT self owner/active → 403 42501; INSERT member/active → 403;
  INSERT own invited → 201; own rows readable; UPDATE invited→active → 403; invited→removed → 204;
  DELETE own row → 204 **no-op** (no DELETE policy — row still present after; verified).
- Bootstrap full path (AML temporarily suspended so the probe could not consume tenant #1; scratch
  mining org inserted): RPC returned scratch org id; membership → owner/active; org SELECT → scratch
  only; second bootstrap → 400 P0001 "owner already exists". All scratch data + probe user deleted
  afterwards; AML restored to `active` with **0 active members — still claimable** for the real first
  owner; probe identities count 0.
- Anon RPC (`bootstrap_first_owner` w/o session) → HTTP 401.
- Auth config inspected: signups enabled, email confirmation ON (`mailer_autoconfirm=false`),
  `site_url = http://localhost:3000` (action: point at real app origin before inviting users).
- Preview proxy verified: `/`, `/admin.html`, `/config.js`, `/supabase-auth.js`, `/auth-ui.js` → 200;
  served pages carry the new markers.

Known limitations (recorded)
- Not VERIFIED-tier: no formal automated suite yet (TESTING_STRATEGY rollout remains open; evidence here
  is recorded live probes). Worker data flows still write to the anonymous Firebase channel (dual-read
  window; gating/RLS write policies are Phase 06 work). Admin-dashboard data actions still target the
  legacy Firestore surface with an actor string — real backend writes per table land with Phase 06.
- `site_url`/redirect config should be set to the production app origin (Auth email links otherwise
  point at `localhost:3000`).

## Phase 03 — RBAC + permissions

**Status: COMPLETE (implemented + live-verified 2026-09-03; evidence below)**

Completed work
- Migration `supabase/migrations/20260903000030_phase03_rbac.sql` (applied to
  `vuniwebbrvpgxscdsfei` via CLI):
  - `permissions` — granular catalog (60 codes, 19 domains) per RBAC_MODEL §2.
  - `roles` — 16 seeded system roles: 3 platform, 4 government, 9 organization
    (owner, admin, safety_manager, safety_officer, site_manager, supervisor, worker,
    contractor, member). Org role codes equal `organization_members.role` values.
  - `role_permissions` — seeded default bundles per RBAC_MODEL §3 (owner = full 60;
    admin = 60 minus billing.manage; worker/contractor = self-service set; etc.).
  - `organization_members.role` check constraint expanded to the 9 org roles
    (backwards-compatible: owner/admin/member unchanged).
  - Authz helpers (SECURITY DEFINER, fixed search_path — the Phase 06 policy
    primitive): `auth_user_effective_role(uuid)`, `auth_user_has_permission(uuid,
    text)`, `auth_user_permissions(uuid)`.
  - RLS enabled on the 3 catalog tables: SELECT for authenticated, writes
    default-deny; grants follow the Phase 01 convention (anon SELECT, RLS hides).
- Client: `supabase-auth.js` gains `fetchEffectiveRole(orgId)` /
  `hasOrgPermission(orgId, perm)` / `fetchMyPermissions(orgId)` RPC wrappers;
  `auth-ui.js` role-label map + `lang.js` EN/FR keys cover all 9 org roles
  (account chip shows proper role names). All client files already in the SW
  precache; preview serves the updated files (verified via HTTP 200 + markers).
- `scripts/verify-supabase.mjs` extended (anon RBAC RPC checks + service-role
  catalog/bundle checks) and `scripts/verify-rbac.mjs` added — a self-cleaning
  live probe (real users in a scratch org, full positive/negative matrix,
  cleanup verified).

Live-verified on `vuniwebbrvpgxscdsfei` (recorded probe output, all PASS):
- Owner: effective_role = 'owner'; permissions = 60; has_permission true for
  organizations.manage / billing.manage / audit_logs.view / jsas.approve /
  users.suspend.
- Worker: effective_role = 'worker'; has_permission true for incidents.create /
  jsas.create / emergency.acknowledge; false for organizations.manage /
  users.suspend / analytics.view / billing.manage / audit_logs.view.
- Non-member (outsider): effective_role = null; has_permission = false.
- Tenant isolation: owner sees ONLY the scratch org; outsider and anon see
  zero org rows (RLS).
- RLS escalation attempts all → 403: INSERT own owner/active row, UPDATE own
  role→admin, UPDATE own status (activation).
- Catalogs: authenticated reads 16 roles; anon reads 0 (RLS).
- Cleanup verified: scratch org + 3 probe users removed; AML tenant #1 intact
  with 0 active members (still claimable); 0 probe rows remain.
- Anon RPCs (`auth_user_has_permission` / `auth_user_effective_role`) →
  false/null (from `scripts/verify-supabase.mjs`, no FAIL).

Known limitations (recorded, do not overstate)
- Status COMPLETE, not VERIFIED-tier by the strict vocabulary: evidence is
  recorded live probes, not a formal automated CI suite (TESTING_STRATEGY
  rollout remains open).
- Site-scoped RBAC (`site_members`, site-manager/supervisor resolution) and
  org-admin member/role assignment flows are Phase 04 work; platform/government
  membership flows are Phases 11–12. The role/permission model and helpers are
  in place for those phases.
- Full RLS_MATRIX per-table policies (which call these helpers) land in
  Phase 06; tenant writes remain default-deny until then.

## Phase 04 — Mining company + site hierarchy

**Status: COMPLETE (implemented + live-verified 2026-09-03; evidence below)**

Completed work
- Migration `supabase/migrations/20260903000040_phase04_site_hierarchy.sql` (applied to
  `vuniwebbrvpgxscdsfei` via CLI) + appended fix `20260903000041_phase04_fixes.sql` (see Known issues):
  - `organizational_units` — departments/teams/work zones (one self-referencing table,
    `unit_type` + `parent_id`; org/site-scope constraint triggers; soft delete).
  - `site_members` — site-scoped memberships; role codes = the SAME 9 org role codes
    (RBAC_MODEL §1.4/§1.5); org↔site consistency trigger.
  - `workers` — worker registry (employee id, site, dept/team, classification, contact,
    status, optional `user_id` link to identity for Phase 05 mapping); scope triggers.
  - `org_invites` — email invites (one-time sha256 token, 7-day expiry, pending unique per
    org+email, accepted/revoked/expired lifecycle).
  - New authz helpers: `auth_user_site_effective_role(org,site)`, `auth_user_has_site_access`,
    `auth_user_has_site_permission(org,site,perm)` = max(org role, site role).
  - `auth_user_has_permission` / `auth_user_permissions` UPGRADED to the max() semantics for
    active org members (site role widens org scope); site-ONLY users never gain org scope via
    a site row (verified negative test).
  - Permission catalog +2 codes (`organizational_units.create/.update`, 60 → 62) with role
    bundles (owner/admin/safety_manager create+update; safety_officer/site_manager update).
  - SECURITY DEFINER management RPCs (every one re-checks authorization server-side):
    `org_add_member`, `org_update_member_role`, `org_remove_member` (owner-protected; removes
    withdraw site memberships too), `org_send_invite` (returns token),
    `org_accept_invite` (email-match check), `org_revoke_invite`, `site_assign_member` /
    `site_remove_member` (owner/admin or site_manager of that site), `org_create_unit` /
    `org_update_unit` / `org_remove_unit`, `worker_add` / `worker_update` / `worker_remove`,
    `org_list_members` (members + emails, org-members-only).
  - RLS enabled on all four new tables: SELECT for org members (own-row for site_members),
    writes default-deny (RPCs are the only tenant write paths); grants follow the Phase 01
    convention; PUBLIC EXECUTE revoked from every new function.
- Client: `supabase-auth.js` gains a generic `rpc()` + PostgREST GET helpers and wrappers for
  every Phase 04 RPC/query (fetchOrgSites/Members/SiteMembers/Units/Workers/Invites,
  fetchSiteEffectiveRole, hasSitePermission, org/site/unit/worker actions, invite send/accept/
  revoke). `org-admin.js` (new) renders the Organization panel; `admin.html` gains the
  🏢 Organization nav item + panel (members list + role change/remove + invite-by-email with
  shareable token + pending invites + sites/structure tree + unit creation + worker registry);
  `sw.js` precaches `org-admin.js`.

Live-verified on `vuniwebbrvpgxscdsfei` via `scripts/verify-phase04.mjs` (self-cleaning live
probe; 58/58 checks PASS; cleanup verified):
- Site-scoped resolution: siteMgr (org member + site_manager at Site A) has
  `sites.update`/`organizational_units.update` org-wide but NOT `users.suspend`; site access at
  A true and at B false (no transitive site access). Site-only user (supervisor at A, NO org
  membership): org-scope permission false; site-scope `jsas.approve` true at A / false at B;
  `site_effective_role` = supervisor at A / null at B. Plain worker: no site scope.
- Org-admin gates: outsider / site-only / worker all DENIED member-management RPCs;
  owner cannot be removed/re-role'd; second owner cannot be granted; role change + remove +
  re-add (reactivates) OK; removing a member also withdraws their site memberships.
- Invite flow: token issued; re-invite while pending upserts a fresh token; wrong-account
  accept denied (email match); invitee accept → membership `safety_officer` + site membership
  created; second accept denied; invite-for-existing-member denied; revoke OK; revoked invite
  cannot be accepted.
- Hierarchy/workers: unit creation (dept → team → work zone) OK; cross-site parent rejected by
  trigger; worker/site-only unit creation denied; `worker_add`/`worker_update`/`worker_remove`
  OK for admin; worker denied (needs workers.manage).
- RLS/isolation: outsider + anon see 0 rows on units/workers/invites; site-only user reads own
  site_members row but 0 org-hierarchy rows; org members read the org hierarchy + registry.
- `org_list_members` returns member emails to members; denied to outsiders.

Known issues / regressions fixed during verification
- 42883 at runtime in `org_send_invite`: `gen_random_bytes()` lives in the pgcrypto extension,
  not on the functions' fixed `search_path = public`. Fixed in the appended migration
  `20260903000041_phase04_fixes.sql` (core-only sha256 token; no extension dependency).
- 42804 in `org_list_members`: `auth.users.email` is `varchar(255)`; table-returning functions
  need exact column types → cast to `text` in the return query. Same fix migration.
- Phase 03 regression check re-run after the `auth_user_has_permission` upgrade:
  `scripts/verify-rbac.mjs` still all-PASS (owner = full bundle incl. new codes;
  worker bundle unchanged).

Known limitations (recorded, do not overstate)
- Status COMPLETE, not VERIFIED-tier (recorded live probes, no CI suite — TESTING_STRATEGY
  rollout still open).
- Site-only members cannot SELECT org-scope rows (units/workers) until Phase 06 policies use
  the site-scoped helpers per-table; the helpers are live and correct now.
- Invite delivery is token-in-app until a mail provider is wired (Phase 09/13);
  `org_accept_invite` requires the invitee to sign in with the invited email.
- Departments for tenant #1 (AML) are not yet seeded from legacy text (Phase 05 mapping task).

## Phase 05 — Database migration (Firestore → Supabase)

**Status: COMPLETE (session 17, 2026-09-10) — fresh-start cutover directive (ADR-014): the Firestore import is WAIVED by the owner; safety notices moved into the tenant model; signed-in traffic cut over to Supabase. Live-verified 42/42; evidence below.**

### Session 17 (2026-09-10) — fresh-start cutover executed (supersedes the import plan)

Per the owner directive ("Let go every data migration from Firestore, we are going to start afresh with
new data in Supabase") recorded as **ADR-014**: no legacy documents are imported; tenant #1 and every
future tenant start with empty safety-domain tables. Work completed + verified this session:

- **Migration `20260903000097_phase05_cutover_notices.sql` applied live** (the last legacy-only domain
  without a Supabase home): `safety_notices` (org+site scoped; `site_id` null = org-wide broadcast;
  severity/pinned/scheduled/expiry; `client_id` unique for offline idempotency) + `safety_notice_acks`
  (per-user idempotent acks). RLS: org-membership SELECT; writes gated on `notices.manage` or org-admin;
  acks restricted to the acking user; regulator SELECT per Phase 11 pattern. Grants per project
  convention. Additive audit branches (`trg_audit_safety_notices` + `trg_audit_safety_notice_acks`)
  → 23 audit triggers total.
- **Fix migration `…098_phase05_cutover_notices_fix.sql`** (probe-driven): SECURITY DEFINER
  `notice_soft_delete(notice_id)` RPC — PostgREST re-checks the SELECT policy (`deleted = false`) on a
  direct `PATCH {deleted:true}` UPDATE…RETURNING (42501), the same class as the documented Phase 07
  `Prefer` finding; the RPC is gated on the catalog `notices.delete` permission and captures the audit
  trail. `grant … to authenticated`, execute revoked from public.
- **Client cutover (`notices.js`)**: signed-in users read/write safety notices via PostgREST with
  legacy-shape reverse-mappers — zero UI changes required; signed-out users keep the legacy Firestore
  channel (fallback-only per ADR-014). Soft-delete goes through the new RPC.
- **`scripts/verify-phase05.mjs` (new)**: 42/42 PASS, self-cleaning (residue 0) — catalog, RLS matrix
  (org A vs org B cross-tenant denials both directions; worker write denials; site-targeted rows hidden
  from other sites), ack idempotency + cross-user isolation, broadcast vs site scope, admin soft-delete
  via RPC + audit capture, regulator read scope, offline `client_id` idempotency (409 → already-synced).
- **Probe expectation updates (catalog drift from the cutover)**: `verify-phase07/08/09.mjs` audit-trigger
  count 21 → 23 (the two new notices triggers). All three re-run ALL-PASS after the update.
- **Suite-hygiene note**: a timed-out full-suite run can leave scratch orgs whose fixed probe names
  collide on the `organizations_name_lower_uidx` unique index on the next run (Phase 08 hit this).
  Probes are self-cleaning on success; on a timeout, clear leftovers before re-running (the transient
  `scripts/inspect-leftovers.mjs` / `scripts/clean-p8-residue.mjs` helpers exist for this).

Verification evidence: `verify-phase05.mjs` 42/42 PASS self-cleaning; full regression all-PASS in subsets
(04, 05, 06, 06c, 07, 08, 09, 10, 11, 12, 13); security scan 0 CRITICAL.

### History — session 8 (2026-09-03): import prep (now superseded by ADR-014)

**Status then: PARTIALLY_COMPLETE — prep executed, no database writes.**

Completed work
- `scripts/phase05-inventory.mjs` (fixed + extended this session): read-only inventory of all 5 legacy
  Firestore collections over the exact anonymous channel the shipped app uses. Photo payloads are now
  RETAINED whole in the snapshot (only fields ≥ 8 MB are stripped) so mapping can hash/type/export them.
  Output under `supabase/legacy-inventory/` (gitignored): ndjson per collection + `report.json` +
  `manifest.json` (sha256).
- Measured volumes (MIGRATION_PLAN §1, previously "?"): incidents 4 (2 soft-deleted; 5 embedded
  data-URL JPEGs ≈ 881 KB decoded), jsas 4 (3 soft-deleted), notices 12 (10 soft-deleted), audit_log 64,
  emergency_sos 7 (7 distinct startedAt activations, all Nimba Mine/Fire/admin). 100% createdAt
  coverage on all 5 collections; field census 19/13/16/6/20.
- `scripts/phase05-map.mjs` (new): pure/offline/deterministic/restartable legacy → target mapper under
  tenant #1 (`arcelormittal-liberia`) with seeded-site resolution + human-decision gates. Emits under
  `supabase/migration-prep/` (gitignored): target payloads for incidents/jsas/notices/emergency_events/
  audit_log (each row keyed by legacy `client_id`, soft-delete preserved, legacy timestamps kept),
  `photos.manifest.ndjson` (Phase 07 object-storage work queue: 5 JPEGs, decoded sha256/bytes/storage
  key), `mapping-report.json` (§4.3 validation baseline), `review-lists.json` (29 items in 4 groups +
  7 proposed workers + 2 proposed departments). Decisions recorded via `overrides.json`; payload
  output verified byte-identical across re-runs.

Validation evidence (recorded, all PASS): source counts = inventory counts for all 5 collections
(4/4/12/64/7); 91 source docs → 91 target rows; required-field violations 0; unique client ids per
payload family; photo manifest 5 rows ≈ 881 KB; audit orphans 50 (delete 25/purge 16/restore 9 — rows
referencing already-purged legacy docs, imported for history with `legacy_import: true`).

Findings surfaced for human review (not silently decided): site/zone vocabulary mismatch vs seeded
sites (Tokadeh Mine / Uritton / Tokadeh / Lower Gangra / Bench 6 / Pit 3 / Rampard / Concentrator /
WBHO Sites / Bench 12); badge hygiene (Nohama Dola: AML-34 on one doc + AML-56 on another; John Sebah
shares AML-34; jsas-only workers unbaged); free-text supervisors/witnesses. See
`supabase/migration-prep/review-lists.json`.

Known limitations / remaining work (do not overstate)
- Status PARTIALLY_COMPLETE, not COMPLETE/VERIFIED: NOTHING has been imported — target safety-domain
  tables + their RLS land in Phases 06–09; payloads were validated against the documented target shape,
  not a live table. No formal automated suite yet (TESTING_STRATEGY rollout still open).
- Blockers before any apply/cutover: (1) durable user-owned Firestore export + off-repo copy
  (ADR-003 — still owed); (2) target tables exist; (3) org-owner sign-off on review-lists.json via
  overrides.json; (4) Phase 06 tenant-isolation suite green (MIGRATION_PLAN §7).
- Device (localStorage) datasets migrate via the in-app upgrade flow (MIGRATION_PLAN §5), not this
  central pass.
## Phase 06 — RLS + security enforcement (RLS_MATRIX over Phases 01–04 tables + audit foundation)

**Status: COMPLETE (implemented + live-verified 2026-09-03; evidence recorded below)**

Completed work
- Migrations (all applied to `vuniwebbrvpgxscdsfei`):
  - `20260903000050_phase06_rls_audit.sql` — Phase 06 core:
    - **SELECT matrix w/ site scope**: `sites` + `organizational_units` readable by org members
      OR active members of the row's site (`auth_user_has_site_access`); `workers` registry is
      LEAST PRIVILEGE (readers need `workers.view`/`users.view` at org scope or at their own
      site — plain workers/site-supervisors never list the roster, per RLS_MATRIX §1.1
      "WRK: –"); `org_invites` stays org-members-only (one-time tokens).
    - **organizations UPDATE gate**: owner/admin via `organizations.manage` (RLS_MATRIX §1.1
      "OWN S,I,U own") — INSERT stays platform-level (Phase 12).
    - **`audit_log` table** (append-only, SECURITY_MODEL §2.6 / DATABASE_ARCHITECTURE §2.5):
      RLS-enabled; SELECT for org members with `audit_logs.view`; INSERT/UPDATE/DELETE
      privileges REVOKED from anon+authenticated (no write policies exist either);
      SECURITY DEFINER trigger `trg_audit_capture()` on organization_members / site_members /
      organizational_units / workers / org_invites / organizations records actor from
      `auth.uid()` (never client strings — closes C4 spoofable-audit path for these ops),
      curated metadata only (invite tokens NEVER mirrored), source='trigger'.
  - `20260903000051_phase06_fix_org_delete_audit.sql` — org-delete audit path: deleting an
    organization used to fail (23503) because the AFTER-DELETE audit row referenced the gone
    org; trigger now nulls the tenant scope and the FK is `ON DELETE SET NULL` so the
    append-only org-delete record is retained as platform-scope history.
  - `20260903000052_phase06_fix_cascade_org_delete.sql` — generalized the fix: cascade-deleted
    child rows (memberships/units/workers/invites) fire their own AFTER-DELETE audit triggers;
    `organization_id` is nulled whenever the referenced org no longer exists, so cascade
    deletes succeed AND retain every child audit record (org_id null).
  - `20260903000053_phase06_add_sites_audit.sql` (NEW this session) — closes a gap found by
    the new cascade regression probe: `sites` had NO audit trigger (Phase 06 created 6
    triggers but omitted the table itself). Adds the `sites` branch to `trg_audit_capture()`
    and creates `trg_audit_sites` (name/location/county/status audited; org-scope nulling on
    cascade).
  - Migration-history repair: 50–52 were applied out-of-band (Management API) and were NOT in
    `supabase_migrations.schema_migrations`, so `supabase db push` tried to re-apply them;
    recorded 50–52 as applied this session → `db push` now applies only genuinely pending
    migrations (53 pushed via CLI).
- Client: no UI change required (Phase 06 is pure database enforcement over the same tables the
  admin/org UI already reads through RLS + RPCs).

Live-verified on `vuniwebbrvpgxscdsfei` (recorded probe output, all PASS):
- `scripts/verify-phase06.mjs` (self-cleaning live probe; every check PASS, cleanup verified):
  - catalog: 5 Phase 06 policies present; RLS on all 5 tables; 7 audit triggers installed
    (all 7 tenant-management tables incl. `sites` after fix …053 — probe updated 6 → 7 and
    re-run all-PASS); audit_log SELECT-only privileges (anon+authenticated) confirmed via
    `has_table_privilege`.
  - organizations UPDATE gate **by effect**: owner PATCH own org row → 204 + changed;
    worker/outsider PATCH → 204 but NO effect (RLS); scratch-org owner CANNOT touch tenant #1
    (AML) org row.
  - site-scope matrix: site-only supervisor reads OWN site + own-site units ONLY (never site B,
    never org rows/invites/worker roster/org-membership rows — no transitive access); reads own
    site_members row; org worker still reads org sites/units but 0 worker-registry rows (least
    privilege); cross-tenant: worker/siteSup/outsider read 0 rows of tenant #1 (AML) units.
  - audit flows: org-add/re-role/site-assign/unit create+update/invite send+revoke/worker
    add+update all captured with actor = auth.uid() (11 actor rows, 0 missing actions); invite
    tokens NOT in metadata (0 leaks); worker/outsider/anon SELECT audit_log = 0 rows;
    owner INSERT/UPDATE/DELETE audit_log → 403 (append-only, row count unchanged after forged
    writes); worker direct INSERT into workers/organization_members → 403 (RPC-only writes).
- `scripts/verify-phase06-cascade.mjs` (NEW this session; self-cleaning; all PASS): single
  `DELETE` of an org with site + org member + site member + unit + worker + invite succeeds
  (no 23503); all dependents cascade-removed; audit rows written for ALL 7 resources
  (organizations, sites, organization_members, site_members, organizational_units, workers,
  org_invites) — every row platform-scope (`organization_id` null), source='trigger', action
  `*.delete`, actor null under service-role delete (correct/expected). This probe is what
  exposed the missing `sites` trigger → migration 53.

Known limitations (recorded, do not overstate)
- Status COMPLETE, not VERIFIED-tier by the strict vocabulary: evidence is recorded live probes
  (verify-phase06 + verify-phase06-cascade all-PASS with cleanup verified), not a formal CI
  suite (TESTING_STRATEGY rollout remains open).
- Phase 06 scope = Phases 01–04 tables (tenancy/RBAC/hierarchy) + audit foundation. Safety-domain
  tables (incidents, jsas, inspections, notices, emergency, documents) and their RLS_MATRIX §1.2
  policies are Phases 07–09 by fixed phase order; until those land, the shipped app's worker
  data flows continue on the legacy anonymous Firebase channel (dual-read window, documented
  gating).
- `sites` INSERT remains platform/service-role (no org self-service site creation yet);
  `sites` UPDATE/DELETE remain service-role-only (no RPC exists yet — Phase 12/org-admin RPC
  adds it). Only the SELECT matrix + audit trigger are live for `sites` in Phase 06.
- Platform/government audit readers and `source='rpc'/'service'` audit writers land with
  Phases 11–12 (their roles exist in the catalog now).

## Phase 07 — Incident + evidence management

**Status: COMPLETE (session 10, 2026-09-04) — applied + live-verified on `vuniwebbrvpgxscdsfei`; evidence recorded below.**

Completed work (applied + live-verified on `vuniwebbrvpgxscdsfei`, 2026-09-04)
- `supabase/migrations/20260903000060_phase07_incidents.sql` — safety-domain incident tables:
  `incidents` (org-scoped; Phase 05 mapper target shape is a direct column subset — client_id
  idempotency key, reported_by_name/badge/dept_text/location/witnesses_text legacy parity, status
  lifecycle DRAFT…CLOSED, soft-delete, site_notice_scope broadcast flag), `incident_evidence`
  (object-storage refs w/ sha256/size/kind; org/site mirrored from the incident server-side),
  `incident_witnesses` (named witnesses + statements, no DELETE policy per RLS_MATRIX §1.2).
  - Scope triggers: reporter FORCED to auth.uid() on INSERT and pinned immutable on UPDATE
    (server-side identity; closes client-attribution); evidence/witness org/site mirrored from
    the incident; site/department org-consistency checks.
  - RLS_MATRIX §1.2 helpers + policies: `auth_user_can_view_incident` (org-wide roles owner/admin/
    safety_manager/safety_officer; site roles site_manager/supervisor at the row's site; own
    reports; site_notice_scope broadcast), `auth_user_can_insert_incident`, `auth_user_can_update_incident`
    (site-scope update incl. workers' own rows read-only), `auth_user_can_delete_incident` (owner/admin/
    safety_manager only), `auth_user_can_insert_incident_evidence` (reporter or update-capable).
    11 policies total (incidents 4, evidence 4, witnesses 3).
  - Audit: `trg_audit_capture()` extended with incidents/incident_evidence/incident_witnesses
    branches (curated metadata, no description/photo/statement bytes; org-scope nulling on
    cascade preserved) + 3 new trigger → 10 audit triggers total.
- `supabase/migrations/20260903000061_phase07_storage_evidence.sql` — private `incident-evidence`
  bucket (10 MB/object, image/pdf/video allowlist) + 4 `storage.objects` policies authorizing
  every object access by resolving the incident token (6th path segment = incident uuid OR legacy
  client_id) through the incident row's own RLS — knowing a path grants nothing.
- `scripts/verify-phase07.mjs` — self-cleaning live probe (~60 checks): catalog (tables/RLS/11
  policies/10 audit triggers/private bucket/4 storage policies), incidents SELECT matrix
  (org-wide vs site-scope vs worker-own vs outsider-0 vs anon-0), INSERT + reporter integrity
  (spoofed reporter rejected; cross-site and cross-org insert denied), UPDATE matrix
  (supervisor site-scope update; worker update no-op; safety_officer org-wide; soft-delete
  supervisor-only), site_notice_scope broadcast (site workers yes, other-site worker no),
  hard-DELETE gating (worker/officer no-op, owner allowed), evidence/witness scope (own vs
  denied), storage upload/download (+ denied paths), two-org cross-tenant reads/writes,
  audit actor integrity + no-description-leak + append-only, cascade-delete cleanup.
- `scripts/verify-phase06.mjs` updated: audit-trigger count 7 → 10 (Phase 07 adds 3).

Applied + live-verified on `vuniwebbrvpgxscdsfei` (evidence):
- Migrations `…060` + `…061` pushed via `supabase db push --linked` (both applied on first push;
  history consistent).
- `scripts/verify-phase07.mjs` on `vuniwebbrvpgxscdsfei`: **all checks PASS, cleanup verified**.
  Checks covered:
  - Catalog: 3 tables with RLS enabled; 11 policies (incidents 4, evidence 4, witnesses 3);
    10 audit triggers (7 tenant + 3 safety-domain); private `incident-evidence` bucket +
    4 `storage.objects` policies.
  - INSERT matrix: worker submits own report (201); site-only supervisor submits at own site
    (201); site-A-only worker denied at site B (403); owner submits at site B (201); tenant#2
    owner denied in tenant#1 (403); status lifecycle check (`open` → 400; row not persisted).
  - Reporter integrity: spoofed `reported_by_user_id` rejected (400, trigger raises);
    reporter forced server-side to `auth.uid()` (verified via owner re-select).
  - SELECT matrix: owner/safety_officer see org-wide pool (4 rows); site-only supervisor sees
    site A only (3 rows, never site B); worker sees own report only (1 row);
    site-only worker sees own only (1 row); outsider/anon see 0 rows.
  - UPDATE matrix: supervisor updates own-site incident (204 + effect); supervisor cannot
    touch site B (no-op, severity unchanged); worker cannot edit own incident (no-op);
    safety_officer edits org-wide incident (204 + effect).
  - Soft-delete: supervisor soft-deletes own-site incident; worker cannot.
  - `site_notice_scope`: org worker reads broadcast row; site-A worker reads; site-B worker
    and outsider see 0.
  - DELETE: worker/officer hard-delete is a no-op (rows survive).
  - Evidence: worker attaches to own incident (201); denied for another's (403); supervisor
    attaches to site incident (201); worker sees own evidence only; supervisor updates;
    safety_officer hard-delete no-op.
  - Witnesses: worker adds to own incident (201); denied for another's (403);
    safety_officer updates record (204).
  - Storage: worker uploads to own incident path (200); upload blocked on another's path;
    worker downloads own evidence (200); outsider download blocked.
  - Two-org tenant isolation: tenant#1 worker reads 0 rows of tenant#2; tenant#2 owner
    reads 0 rows of tenant#1; tenant#2 owner denied write into tenant#1.
  - Audit: incident insert/update captured with actor = `auth.uid()`; evidence/witness
    inserts captured; forged audit_log INSERT rejected (403); incident body text never
    mirrored into audit metadata.
- `scripts/verify-phase06.mjs` re-run after Phase 07 migration: **all PASS, cleanup verified**
  (no regressions on the tenant-management authorization layer).
- `scripts/verify-phase06-cascade.mjs` re-run: **all PASS** (no regressions).

Known limitations (recorded, do not overstate)
- Status COMPLETE, not VERIFIED-tier by strict vocabulary: evidence is recorded live probes
  (`verify-phase07` + Phase 06 regression suites all-PASS with cleanup verified), not a formal
  CI suite (TESTING_STRATEGY rollout remains open).
- Client UI for incidents (admin dashboard read / worker form write to Supabase) remains on
  the legacy anonymous Firebase channel (dual-read window, documented gating). Wiring new
  backend writes to the client is Phase 05 cutover / Phase 10 offline-sync work; it is
  explicitly not in Phase 07 scope (Phase 07 = database + storage + RLS).
- `Prefer: return=representation` on INSERT is incompatible with RLS on this table — PostgREST
  re-checks the SELECT policy on the RETURNING row and returns 42501 even when the INSERT is
  allowed (verified empirically). Client code should POST without Prefer and re-select.
- Incident INSERT via RLS (not RPC) is intentionally used here to exercise the full RLS matrix
  directly; in production, SECURITY DEFINER RPCs with `source='rpc'` audit rows are the
  recommended write path (Phase 08/09/12 RPC additions).

## Phase 08 — JSA + inspection + corrective actions — COMPLETE (2026-09-04)

Applied migrations `…070`/`…071` + fix migrations `…072`/`…073` to `vuniwebbrvpgxscdsfei` via `supabase db push --linked`.

Completed work
- `…070_phase08_jsas.sql` — `jsas` + `jsa_steps` tables (org+site scoped; approval flow; `site_notice_scope` broadcast; soft-delete; client_id idempotency), RLS policies, audit triggers (2 new → 12 total).
- `…071_phase08_inspections_capa.sql` — `inspections` + `corrective_actions` (CAPA) tables (org+site scoped; inspection_type lifecycle; priority/status enums; polymorphic source linkage; soft-delete; client_id idempotency), RLS policies with SECURITY DEFINER helpers, audit triggers (2 new → 14 total).
- `…072_phase08_fix_select_policies.sql` — inspection SELECT restricted to org-wide safety/admin + site-scoped supervisor/site_manager (not workers); CAPA SELECT uses `auth_user_has_site_access` to allow site-only members.
- `…073_phase08_fix_delete_and_update_policies.sql` — added missing `inspections.delete` + `corrective_actions.delete` permission codes to catalog (owner + admin bundles); fixed `auth_user_can_update_capa` to use `auth_user_has_site_access` (site-only assignees).
- `scripts/verify-phase08.mjs` — self-cleaning live probe: **all checks PASS, cleanup verified**. Covers: catalog (4 tables, 8 policies, 14 audit triggers), full INSERT/SELECT/UPDATE/DELETE matrix across admin, safety_manager, supervisor (site-only), worker, outsider; data-change verification on UPDATE+DELETE (not just HTTP status); cross-tenant isolation; audit actor integrity.
- Regression: `verify-phase06.mjs` + `verify-phase06-cascade.mjs` + `verify-phase07.mjs` all still PASS (no regressions).

Fix migrations applied (discovered during probe iteration)
- Migration 072: original inspection SELECT policy was `auth_user_has_site_access` (too broad — workers could see all inspections); CAPA SELECT required `auth_user_has_org_access` (excluded site-only members).
- Migration 073: `inspections.delete` and `corrective_actions.delete` permission codes were missing from the Phase 03 catalog; `auth_user_can_update_capa` required `auth_user_has_org_access` (site-only assignee could not update).

Status: COMPLETE (recorded live probes; no CI suite — not VERIFIED-tier per project vocabulary).
Next: Phase 09 — Emergency response + SOS.
## Phase 09 — Emergency response + SOS — COMPLETE (2026-09-04)

Applied migration `…080` + fix migrations `…081`–`…084` to `vuniwebbrvpgxscdsfei` via `supabase db push --linked`. `scripts/verify-phase09.mjs`: **all checks PASS, cleanup verified**.

Completed work
- `…080_phase09_emergency_sos.sql` — `emergency_events` (org+site scoped; Phase 05 mapper target shape is a direct column subset — client_id/category/message/contact_number/assembly_point/activated_by_text/ended_by_text/started_at/deactivated_at/duration_seconds/status/notified_workers_legacy/created_at/deleted; lifecycle ACTIVATED→ACKNOWLEDGED→RESPONDING→CONTAINED→RESOLVED→CLOSED enforced forward-only server-side; activated_by forced to auth.uid() and pinned immutable; resolved_by immutable once set; legacy deactivation records the resolver server-side; site_notice_scope broadcast default true), `emergency_acknowledgements` (per-user acks, acked_by server-pinned, unique(event,user) idempotency, immutable — no UPDATE/DELETE policies), `emergency_escalations` (level/escalated_to/reason), `emergency_responders` (dispatch→…→stood_down disposition), `emergency_log` (append-only lifecycle stream written by triggers; SELECT-only grant — no client DML). RLS per RLS_MATRIX §1.2 emergency rows: org-wide roles owner/admin/safety_manager/safety_officer/site_manager see the org pool + INSERT; supervisor site-scope SELECT; worker/contractor SELECT site events via site_notice_scope (org-member workers see broadcast events org-wide — Phase 04 fallback semantics) + own ack; anon/outsider none. Update/resolve/close gated on `emergency.resolve` (owner/admin/safety_manager bundles); escalation+responder management = response-chain gate (supervisor and above, org or site scope). 14 policies (events 3, acks 2, esc 2, resp 3, log 1).
- `…081_phase09_fix_child_authz.sql` — `auth_user_can_update_emergency_child` accepts site-scope `emergency.acknowledge` (site-only supervisors could not escalate).
- `…082_phase09_fix_escalation_gate.sql` — dedicated `auth_user_can_escalate_emergency` (supervisor-and-above response-chain); workers hold ack-only per RLS_MATRIX.
- `…083_phase09_fix_child_guard.sql` — child guard no longer sets `created_by` on `emergency_responders` (column does not exist; 42703).
- `…084_phase09_fix_responder_gate.sql` — responder INSERT/UPDATE use the escalation (response-chain) gate; unused `auth_user_can_update_emergency_child` dropped.
- `scripts/verify-phase09.mjs` — self-cleaning live probe: **all checks PASS, cleanup verified**. Covers: catalog (5 tables RLS, 14 policies, 19 audit triggers); INSERT matrix (owner + site-only site_manager activate; supervisor/worker denied — no `emergency.activate` in their Phase 03 bundles, matching legacy admin-console-only SOS activation; spoofed activated_by rejected; cross-site + cross-org activation denied; activated_by forced to auth.uid()); SELECT matrix (org-wide pool, site-only supervisor site A only, site-A worker via site_notice_scope, site-B worker 0, outsider/anon 0); lifecycle (forward-only enforced, RESOLVED→ACTIVATED rejected, resolved_by immutable, resolver recorded server-side, CLOSED path); acks (201 + identity pinned, duplicate → 409, spoof denied, site-B worker denied, CLOSED-event ack denied, UPDATE no-op); escalation/responder gating (supervisor escalates, worker denied, safety_manager dispatches + disposition update, worker denied dispatch); emergency_log append-only (trigger stream activated/resolved/closed, client INSERT denied); tenant isolation both directions; audit (event insert/transition/ack/log captured with actor, forged audit INSERT rejected, message text never mirrored); cleanup verified.
- Regression: `verify-phase06.mjs` + `verify-phase06-cascade.mjs` + `verify-phase07.mjs` + `verify-phase08.mjs` all still PASS (no regressions; Phase 07/08 trigger counts updated 14→19).

Status: COMPLETE (recorded live probes; no CI suite — not VERIFIED-tier per project vocabulary).
Next: Phase 10 — Offline-first synchronization.
## Phase 10 — Offline-first synchronization — COMPLETE (2026-09-08)

Client-side offline-first layer shipped and verified live (no new migrations — the Phase 07–09 tables already carry `client_id` unique idempotency keys). `scripts/verify-phase10.mjs`: **all checks PASS, cleanup verified**.

Completed work
- `offline-store.js` (new) — IndexedDB local database replacing localStorage-as-database per OFFLINE_SYNC_ARCHITECTURE §2.1: `outbox` (pending mutations with priority/state/attempts/next_attempt_at), `records` (per-record cache keyed by client_id with sync_state pending/syncing/synced/error/conflict), `attachments` (pending photo/video blobs + metadata), `kv` (settings only). Idempotent non-destructive legacy migration (§2.8): `mineguard_incidents`/`mineguard_jsas`/`mineguard_notices`/`mineguard_sos_state` → `records` with stable `clientId` backfill, guarded by a kv flag, legacy localStorage keys left for the Firebase readers. UMD — browser `window.MG_STORE`, Node probes `require()` with injectable store.
- `sync-engine.js` (new) — queue engine per §2.2–§2.7: outbox drained FIFO with EMERGENCY priority first (emergency_events/acknowledgements queued at priority 100); exponential backoff (2s base → 60s cap) with 8-attempt cap and surfaced errors; `client_id` idempotency (server unique index turns a duplicate POST into 409 → already-synced; re-enqueue of the same (entity, client_id, op) dedupes locally); conflict handling (stale local `updated_at` vs newer server `updated_at` → mutation lands in `conflict`, server row never overwritten); per-record sync states; attachment sync (blob → `incident-evidence` storage with X-Upsert idempotency → `incident_evidence` row); connectivity heartbeat + reconnect drain; payload adapters map legacy form shapes (incident/jsa/SOS) to the Phase 07–09 target columns (client-side subset of the Phase 05 mapper), including RLS reporter integrity (legacy `reported_by_name` cannot spoof `auth.uid()`). UMD — `window.MG_SYNC`.
- Wiring — `index.html` + `admin.html`: `offline-store.js` + `sync-engine.js` script tags + a shared bootstrap block in `<head>` (store creation, migration kick-off, engine init, connectivity wiring, 30s heartbeat, `mg-auth-change` context re-resolution, service-worker drain messaging). `sw.js`: precaches the two new files, registers `mineguard-sync-drain` background sync, forwards `sync-drain` messages to open clients. `firebase.js`: `_mgSyncEnqueue()` hook — when a Supabase session exists, `saveIncidentToCloud`/`saveJSAToCloud`/`saveEmergencySOSCloud` additionally enqueue through the engine (non-blocking; Firestore legacy mirror untouched; signed-out devices stay Firestore-only).
- `scripts/verify-phase10.mjs` — self-cleaning live probe running the REAL engine with an in-memory store + real PostgREST transport against the live project: **all 14 checks PASS, cleanup verified**. Covers: queueing (4 mutations, drain empties outbox); ordering (emergency drained first, then incidents A,B,C FIFO by server created_at); RLS reporter integrity (`reported_by_user_id` = engine actor, legacy name preserved); idempotency (duplicate enqueue deduped, exactly 1 server row); backoff (transport failure → attempts=1, pending, next_attempt_at in future; retry after window → JSA lands, no duplicate); conflict (stale update → `conflict` state, newer server row NOT overwritten); attachments (blob → storage object + linked `incident_evidence` row); tenant isolation (tenant#2 owner + outsider read 0, engine actor reads 0 of tenant #2); cleanup verified.
- Bug found + fixed during probe iteration: `sync-engine.js` factory referenced `root` (UMD wrapper parameter) without a local binding — `kick()`/`getStatus()`/`emit()` would throw `ReferenceError` in browsers (auto-drain would never fire); rebound `root` inside the factory. Also hardened `drain()`: a transport throw now increments attempts/backoff and marks the batch network-down instead of stranding mutations in `syncing`.
- Regression: `verify-phase06.mjs` (51 checks), `verify-phase07.mjs` (62), `verify-phase08.mjs` (41), `verify-phase09.mjs` (56) all still PASS (no trigger-count changes — Phase 10 adds no tables).

Status: COMPLETE (recorded live probes; no CI suite — not VERIFIED-tier per project vocabulary).
Next: Phase 11 — Government regulatory command center.
## Phase 11 — Government regulatory command center — COMPLETE (2026-09-09)

Explicit-authorization government layer + regulator command-center surfaces, applied and live-verified on `vuniwebbrvpgxscdsfei`. `scripts/verify-phase11.mjs`: **48/48 checks PASS, cleanup verified**.

Completed work
- `…090_phase11_government_authorization.sql` — `government_grants` (regulator org + regulator user → target org/site, scope label, regulator_role snapshot, issued_by/issued_at, expires_at, active/revoked/expired lifecycle, partial unique index on one active grant per (regulator org, user, target org, site)); SECURITY DEFINER helpers `auth_user_is_regulator_org_member` / `auth_user_is_regulator_user_in` / `current_user_active_government_grants` (the policy primitive) / `auth_user_has_regulator_grant_for`; RPCs `bootstrap_first_regulator_admin` (one-shot claim of first active regulator org with no members; mining/contractor/platform orgs excluded) + `regulator_issue_grant` (national_regulatory_admin only; target must be mining_company/contractor; site must belong to target; grantee must be a government member of the regulator org) + `regulator_revoke_grant` (immediate) + `regulator_update_user_role` (seeded government codes only); 16 grant-gated regulator SELECT policies across incidents, incident_evidence, incident_witnesses, jsas, inspections, corrective_actions, emergency_events/acks/escalations/responders/log, sites, organizational_units, workers, organization_members, audit_log — every policy requires an active grant covering (org, site); no grant ⇒ zero rows; `trg_audit_capture()` extended with the `government_grants` branch (→ 20 audit triggers); RLS on government_grants (regulator org reads own; target org members with audit_logs.view may read grants touching their org per GOVERNMENT_PLATFORM §5; writes RPC-only).
- Fix migrations (probe-driven): `…091` (workers/org-members regulator policies evaluate the permission against the REGULATOR org — they were dead policies against the target org; bootstrap now denies callers holding ANY active membership); `…092` (`organization_members_role_check` extended with the 4 government role codes — regulator memberships failed 23514 before); `…093` (grant INSERT RETURNING captured into a variable — plpgsql 42601 made every issuance fail at runtime).
- Client: `supabase-auth.js` Phase 11 wrappers (`bootstrapFirstRegulatorAdmin`, `regulatorIssueGrant`, `regulatorRevokeGrant`, `regulatorUpdateUserRole`, `fetchMyGovernmentGrants`, `fetchIssuedGrants`, `fetchIncidentsGrantScoped`, `fetchEmergencyGrantScoped`); `gov-admin.js` (new) — Government panel: one-shot regulator bootstrap for brand-new users, grant issue (org-wide or site-scoped) / revoke (immediate), grants table with status/expiry/role, and the National Command Center (org/site drill-down over granted orgs only: incidents + emergency stats and recent rows — every read RLS-bounded by the grant intersection; no grant ⇒ empty state explaining the isolation guarantee); `admin.html` 🏛️ Government nav item + panel + CSS; `sw.js` precache; `auth-ui.js` government role labels on the account chip.

Verification evidence (recorded)
- `scripts/verify-phase11.mjs` on `vuniwebbrvpgxscdsfei`: 48/48 PASS, cleanup verified. Covers: catalog (grants table + RLS, 8 helpers/RPCs, 16 regulator SELECT policies, grants SELECT policies, 20th audit trigger); onboarding (fresh user claims the seeded regulator org — one-shot: second claim denied, membership-holding callers denied, anon 401); grant lifecycle (site-scoped + org-wide issuance, duplicate upsert returns the same grant id, regulator-target grants denied, foreign-site grants denied, non-government-member grantee denied, inspector cannot issue/revoke, admin revoke 204, government role assignment incl. non-government code rejection, re-issue after revoke re-activates); regulator read scopes (0 AML rows without a grant; org-wide grant sees target incidents ×2 / inspections / CAPAs / emergency events / sites; workers stay 0 without workers.view at the regulator org; org members readable only with users.view; inspector without users.view sees 0; site-scoped grant sees site-1 only — 0 site-2 leaks; target owner reads unchanged; regulator INSERT denied 403); revocation immediacy (revoke ⇒ 0 rows immediately); grants RLS (regulator org reads own grants; target org with audit_logs.view reads grants touching it — 2 rows; direct INSERT 403); audit (grant insert/update captured with actor email, trigger source, no leaks); regression (org owner incident flow unchanged; government user sees 0 AML rows).
- Regression: verify-phase06 (all PASS), verify-phase06-cascade (all PASS), verify-phase07 (all PASS after count update: policies 5/5/4, 20 triggers), verify-phase08 (ALL PASS after count update: policies 5/5, 20 triggers), verify-phase09 (PASS after count update: policies events=4 acks=3 esc=3 resp=4 log=2, 20 triggers), verify-phase10 (all PASS, cleanup verified).

Incidents found and fixed during verification
- **Probe cleanup had deleted the seeded `liberia-regulator` org** (a prior interrupted run's cleanup deleted `state.scratchRegOrgId`, which `onboarding()` re-points at the bootstrap-claimed seeded org). Restored the org; probe cleanup now refuses to delete the seeded regulator, AML, or the seeded regulator placeholder ids.
- Leftover scratch orgs/users from interrupted runs blocked scaffolding by unique name/slug constraints (23505); cleaned, and the probe's finally-cleanup is verified to remove its own artifacts.
- Probe parsing fixes (not DB defects): scalar-uuid RPC returns a bare JSON string; void RPCs return 204; `organization_members` has no `id` column (composite PK → select `user_id`).

Known limitations (recorded, do not overstate)
- Status COMPLETE, not VERIFIED-tier: recorded live probes, no CI suite (TESTING_STRATEGY rollout remains open).
- Grant expiry is supported in the schema/helpers (expires_at checked at read time) but the UI does not yet set expiry dates (Phase 12 administration surface).
- Command-center aggregates are client-side over grant-scoped rows (capped at 50 recent); official national roll-ups should move to authorized server-side aggregate views in Phase 12 (non-negotiable #7: documented formulas only).
- The regulator user experience lives in the existing `admin.html` (same app, new panel) — a dedicated regulator portal surface is not required by the phase and was deliberately not forked.
- Client UI for safety-domain data (worker/admin incident flows) remains on the legacy anonymous Firebase channel plus the Phase 10 engine for signed-in users (dual-read window, Phase 05 remainder); the government panel reads the Supabase tables directly.

Status: COMPLETE (recorded live probes; no CI suite — not VERIFIED-tier per project vocabulary).
Next: Phase 13 — billing integration (deferred) / hardening + TESTING_STRATEGY rollout.

---

## Phase 12 — SaaS + enterprise administration — COMPLETE (2026-09-09)

**Scope delivered** (per PROJECT_MASTER §10/§11, RBAC_MODEL open items, Phase 06/11 recorded gaps):

- **Migration `20260903000094_phase12_saas_enterprise.sql`** (applied to `vuniwebbrvpgxscdsfei`):
  - `plans` (code/name/max_sites/max_users/features jsonb/sort_order; seeded ≥3 tiers) + `subscriptions` (org-scoped plan_code/status/current period; partial unique index = one active row per org). **Modeling only — no billing provider wired (deliberate deferral).**
  - RPCs (all SECURITY DEFINER, permission-gated server-side via `auth_user_has_permission`, `revoke all … from public` + `grant execute … to authenticated`):
    - `site_create` / `site_update` / `site_remove` — closes the Phase 06 recorded gap (sites writes were service-role-only); sites.create/update/delete permission codes.
    - `org_update_settings` / `org_update_branding` — settings.manage; merged into `organizations.settings`/`branding` jsonb.
    - `org_update_subscription` — billing.manage; upserts the one active subscription row.
    - `bootstrap_first_platform_admin` (one-shot; any active membership disqualifies), `platform_list_organizations` (tenant inventory + site/member counts), `platform_update_organization_status` (suspend/reactivate lifecycle).
    - `regulator_issue_grant` **5-arg overload with `p_expires_at`** (validated future-only) + `regulator_extend_grant` (clear-or-set expiry; issuing org's national_regulatory_admin only) — closes the Phase 11 recorded grant-expiry gap.
    - `gov_national_overview()` — server-side aggregate over the caller's ACTIVE grants only (documented plain counts: granted orgs, incidents total/open, inspections, CAPAs open, emergency total/active, sites). Non-negotiable #7 honored: formulas documented, no derived safety metrics, no client-side stitching.
  - `trg_audit_subscriptions` — dedicated audit trigger (additive convention of Phase 06 `…053`; the shared `trg_audit_capture` was NOT rewritten wholesale — that risk was identified pre-application and avoided). Audit trigger count 20 → 21.
- **Fix migration `20260903000095_phase12_fix_rpc_results.sql`** (probe-driven, convention of Phase 11 `…091`–`…093`):
  - `regulator_issue_grant`: plpgsql `insert … returning id` without INTO raised 42601 — result now captured into a variable.
  - `trg_audit_subscriptions_capture`: wrote to nonexistent `audit_log.resource_type` → every subscription change 400'd; corrected to real columns (`resource`, `resource_id`).
  - `platform_list_organizations`: returned HTTP 200 `[]` for non-platform callers (language sql cannot raise) → converted to plpgsql with explicit P0001 gate.
  - **Dropped the legacy 4-arg `regulator_issue_grant` overload** — with both overloads live, PostgREST could not resolve partial named-argument calls (PGRST203), breaking ALL Phase 11 grant issuance. One canonical 5-arg signature with defaults remains. This also retro-fixed Phase 11's probe (48/48 again).
- **Probe** `scripts/verify-phase12.mjs`: **31/31 PASS, self-cleaning** (scratch orgs/users/sites/grants removed in finally; verified 0 residue). Covers: catalog, plan catalog visibility (auth + anon; subscriptions hidden from anon), site lifecycle incl. worker denial, settings persistence + worker denial, subscription switch + persistence + worker denial, grant expiry issue/extend/deny, platform bootstrap gating + status denial + explicit listing denial, national overview correctness (grant reflected, revoked grant excluded, non-granted user = zeros), audit coverage, self-cleanup.
- **Client**:
  - `supabase-auth.js`: Phase 12 wrappers (site CRUD, org settings, plans/subscription, extend grant, platform trio, national overview); grant-issue wrapper now sends `p_expires_at`; duplicate legacy 4-arg wrapper removed.
  - `org-admin.js`: site create/rename/remove UI (permission-gated), org settings + branding card, plan/subscription card (current plan + switch).
  - `gov-admin.js`: grant issue form gains optional expiry datetime; grants table gains Extend action (`regulator_extend_grant`, blank = clear expiry); new National Overview block rendering `gov_national_overview` server-side stats for gov admins.
  - `sw.js` precache unchanged (gov-admin.js/org-admin.js already cached); syntax checks clean; all assets served 200 by preview.
- **Regression**: verify-phase06 PASS, verify-phase06-cascade PASS, verify-phase07 PASS (trigger count 20→21), verify-phase08 ALL PASS (same), verify-phase09 PASS (same), verify-phase10 PASS, verify-phase11 **48/48 PASS** (after the overload fix; prior failure was the PGRST203 resolution above).

**Known limitations (recorded, do not overstate)**
- Plans/subscriptions are modeled; **no payment provider, invoicing, or dunning exists**. `billing.manage` plan switches are administrative records, not revenue events.
- Platform RPCs are seeded-role-gated but there is **no platform-admin UI surface** yet (management is probe/API-level); a Platform console is a future phase.
- `gov_national_overview` counts only ACTIVE grants; expired grants lapse silently (no expiry sweep job — reads already exclude them by `expires_at > now()`).
- Feature-flags/usage metering (PROJECT_MASTER §10) are still schema-shaped via `plans.features` jsonb but not enforced anywhere (sites.create RPC does not yet consult `max_sites`).

Status: COMPLETE (recorded live probes; no CI suite — not VERIFIED-tier per project vocabulary).
Next: Phase 13 — per fixed phase order (billing integration when commercially required; TESTING_STRATEGY rollout remains the standing open item).

---

## Phase 13 — Production hardening + security certification — COMPLETE (2026-09-10, session 16)

**Completed this session**

- **Secret-leak incident found + remediated (TESTING_STRATEGY §5 executed for real):**
  `scripts/run-probes.sh` had the live **service-role JWT** and the **Supabase DB password** committed
  to the repo. File remediated (credentials env-injected now); **rotations are REQUIRED and cannot be
  done from the repo** — user actions recorded in `SECURITY_CERTIFICATION.md` §2 (rotate service-role
  key + DB password; treat `sbp_` access tokens pasted in chat as exposure-compromised).
- **Automated security scanner** `scripts/security-scan.mjs` (TESTING_STRATEGY §5, CI-gateable):
  tracked-files scan; CRITICAL rules = service-role JWT, `sbp_` tokens, private keys, postgres URLs
  with passwords, `mineguard2024` legacy credential, misplaced API keys, generic secret assignments;
  exit 1 on CRITICAL so `npm test` fails closed. Baseline: **0 CRITICAL, 16 HIGH** — every HIGH is a
  classified/accepted item (4 Firebase web-key sites = public-by-design legacy config, C7 action
  recorded; 12 probe-account password sites = throwaway probe users, not deployment secrets).
- **Durable test suite (TESTING_STRATEGY rollout — the standing open item):** `npm test` =
  `security-scan.mjs && scripts/run-all-probes.mjs` (all 10 live probes — 04, 06, 06-cascade, 07, 08,
  09, 10, 11, 12, 13 — with a summary table and CI-gateable non-zero exit on any failure).
  `scripts/run-probes.sh` retained as a single-phase runner (also env-injected).
- **Migration `20260903000096_phase13_hardening.sql` (AUTHORED, NOT yet applied — blocked):**
  closes both Phase 12 recorded hardening gaps:
  1. `site_create` now enforces the org's active-plan `plans.max_sites` (counts non-deleted sites;
     null cap / no subscription = unlimited back-compat for tenant #1 pre-billing). Same 4-arg
     signature — no overload (PGRST203 lesson from Phase 12).
  2. `regulator_expire_due_grants()` — audited, idempotent sweep flipping due active grants to
     `expired`; callable by a `national_regulatory_admin` of a regulator org (session path) or the
     platform scheduler (no session); every lapse captured by the existing `government_grants` audit
     trigger. `revoke … from public` + `grant … to authenticated` per convention.
  Schema-verified against live conventions before authoring (sites soft-delete = `status`/`deleted_at`,
  not a boolean; org gate mirrors Phase 02/…090 patterns; additive-only — shared audit trigger NOT
  rewritten).
- **`docs/engineering/SECURITY_CERTIFICATION.md` (new)** — per-control certification table
  (DEMONSTRATED / ACCEPTED / OPEN with the producing artifact named), the secrets incident + rotation
  checklist, accepted residual risks (incl. the legacy anonymous Firestore dual-read channel as the
  highest-priority residual), and the explicit gates between COMPLETE and "production candidate".
- **`PRODUCTION_READINESS.md`** — checklist updated: security/database/offline/testing items ticked
  with evidence pointers; remaining gates enumerated (migration apply + probe re-run, rotations, XSS
  suite, rate limiting, MFA enablement, media re-encode, backups/DR, legacy cutover).
- Note: an interrupted earlier Phase 13 attempt had already authored `run-all-probes.mjs`,
  `verify-phase13.mjs`, and the `run-probes.sh` remediation; this session reviewed, validated them
  against the authored migration, extended the scanner, and wired `npm test`.

**Verification evidence (recorded, live on `vuniwebbrvpgxscdsfei`, 2026-09-10)**

1. Migration `…096` applied via `scripts/apply-migration.mjs` (HTTP 201) with a fresh access token.
2. `scripts/verify-phase13.mjs`: **27/27 PASS, self-cleaning** (cleanup: 3 orgs, 4 users, 3 grants,
   8 sites removed; residue 0). Covered: catalog (hardened `site_create` w/ unchanged signature — no
   PGRST203 overload; 0-arg sweep RPC granted to authenticated); max_sites (starter cap: 3 sites OK,
   4th DENIED naming the plan cap, no partial row persisted; enterprise upgrade re-allows creation;
   no-subscription org creates 4+ — back-compat); sweep (future + null-expiry grants issued, past-due
   grant still 'active' pre-sweep, national_regulatory_admin sweep reports >=1, past-due -> 'expired',
   future/null untouched, idempotent second run = 0, org worker DENIED, lapses captured by the grants
   audit trigger, expired-grant holder reads 0 target-org incidents); security-scan self-check exits 0;
   Phase 12 RPC surface intact (12 functions).
3. Full regression: verify-phase04 PASS, verify-phase06 PASS, verify-phase06-cascade PASS,
   verify-phase07 PASS, verify-phase08 ALL PASS (after cleaning leftover probe orgs from a timed-out
   earlier run), verify-phase09 PASS, verify-phase10 PASS, verify-phase11 PASS (48/48),
   verify-phase12 PASS (31/31), security-scan exit 0 (0 CRITICAL / 16 classified HIGH).

**Status: COMPLETE** (recorded live probes; not VERIFIED-tier — no CI runner executes `npm test` on
push yet; wiring it to CI is a deployment action). **Standing user actions:** rotate the service-role
key + DB password (SECURITY_CERTIFICATION §2 — the committed copies remain valid until rotated).
**Phase 13 remainder:** XSS adversarial suite, rate limiting, MFA enablement, media re-encode,
backups/restore drill (SECURITY_CERTIFICATION §1 OPEN rows + §4 gates). Per fixed phase order, next:
remaining hardening items above and the Phase 05 cutover remainder (legacy Firestore channel).

---
## Session 18 (2026-09-10) — Organization lifecycle + authentication remediation — COMPLETE

**Trigger:** new sign-ups hitting "no claimable organization found: an owner already exists for
every active organization" when trying to set up an organization.

**Forensic findings (audited before any change):**
1. The error is raised by `bootstrap_first_owner()` (migration `…020`): it only CLAIMS the oldest
   active mining_company org with zero active members — first-deployment bootstrap, not creation.
   Once any org has an owner (e.g. seeded AML), every new user gets the exception.
2. Organization INSERT was default-deny for authenticated users (no INSERT policy) — NO self-service
   organization creation existed anywhere.
3. `org_type` constraint: mining_company/contractor/regulator/platform only (no service_provider).
4. RPCs managing orgs were claim/admin/platform only — none creates an organization.
5. Subscriptions seeded via SQL only — no init on creation.
6. No ownership-transfer path (owner re-role blocked — good, but a dead end for succession).
7. Multi-membership supported by schema but UI used `memberships[0]` / first-admin heuristics.
8. Logout detached listeners + remote sign-out; no selected-org preference existed to clear.

**Implemented (migration `20260903000099_org_lifecycle.sql`, applied live HTTP 201):**
- `create_organization(p_name, p_org_type, p_county)` — SECURITY DEFINER, fixed search_path, session
  required, name validation (1–120), type whitelist (mining_company/contractor/service_provider;
  regulator/platform REJECTED), server-generated collision-safe slug (`abc-mining-liberia`, then
  `-2`, `-3`…; UUID remains the identifier; duplicate exact names rejected by the existing unique
  index), server UUID/timestamps, `created_by = auth.uid()`, creator becomes owner+active ATOMICALLY,
  starter subscription initialized in the same transaction (no billing). Audit via existing triggers.
  No new RLS policies — organizations INSERT stays default-deny; creation ONLY via this RPC.
- `org_transfer_ownership(p_organization_id, p_new_owner_user_id)` — current active owner only,
  target must be an active same-org member, atomic swap (target→owner, previous owner→admin; never
  ownerless), self-transfer rejected, admins cannot seize. Audit captured.
- `org_type` constraint extended with `service_provider`.
- Both RPCs: revoke public/anon, grant authenticated.

**Implemented (client):**
- `supabase-auth.js`: `createOrganization`, `orgTransferOwnership`, selected-org model
  (`getSelectedOrgId`/`setSelectedOrgId`/`resolveActiveOrg` — preference validated against CURRENT
  active memberships; UI state only), signOut clears the org preference.
- `admin.html` login: "Set Up Organization (Owner)" replaced with **Create New Organization** (form,
  friendly errors), **Claim Existing Organization** (labeled first-deployment bootstrap), **Join**
  (invitation explanation). `attemptAdminEntry` uses `resolveActiveOrg` (one org → enter; several →
  switcher; none → onboarding options).
- `org-admin.js`: org switcher for multi-membership users (server-confirmed memberships only),
  first-site onboarding card → existing `site_create`, `pickOrg` via `resolveActiveOrg`.

**Verification (all commands actually run):**
- `scripts/verify-org-lifecycle.mjs` (new): **30/30 PASS, self-cleaning** — catalog, happy path,
  denials (anon 401, regulator/platform/empty 400, forged INSERTs 403), duplicate name, slug
  collision `-2`, transfer rules + single-owner invariant, audit rows, isolation (outsider 0 rows,
  site INSERT 403), first-site authz. Wired into `run-all-probes.mjs` as `olc`.
- Full regression all-PASS: 04, olc, 06, 06c, 07, 08, 09, 10, 11, 12, 13.
- Security scan 0 CRITICAL; XSS audit clean; `node --check` clean on all touched JS.

**Not done (scope stop):** email-verification UX stays GoTrue default; no billing; regulator
provisioning stays manual/platform-side; no new rate limiting (Phase 13 open row).

---

---

## Session 19 — Authentication gate + entry routing (2026-09-12) — COMPLETE (live-verified)

**Problem (forensic finding):** `index.html` dismissed its splash on a fixed
timer and called `initApp()` unconditionally — the authenticated Worker
Screen ran with zero session check; identity was free-text localStorage. The
header \u201cSign In\u201d chip returned users to the same unguarded screen.

**Root cause:** no entry-time session check anywhere; `auth-ui.js` sign-in had
no routing; only `admin.html` had a gate.

**Changes:**
- `auth-gate.js` (NEW): `MG_GATE.resolveEntry` (only splash-dismiss path),
  `resolveFromMemberships` centralized destination resolver
  (AUTH_REQUIRED / NO_ORGANIZATION / SELECT_ORGANIZATION / WORKER_WORKSPACE /
  COMPANY_ADMIN), `MG_GATE.showGate` — reads only RLS-filtered server rows.
- `index.html`: entry-gated splash dismissal; gate script included in
  correct order; no tenant UI before authentication resolves (no flicker).
- `auth-ui.js`: `routeAfterAuth()` after sign-in/sign-up; sign-out returns
  to the gate.
- `app.js`: `resolveEntry` integration; worker org context from membership.
- `sw.js`: gate precached, cache version bumped.
- `scripts/verify-auth-gate.mjs` (NEW, 21 checks) wired into
  `scripts/run-all-probes.mjs`.

**Database changes:** none (no RLS modified).

**Tests:** verify-auth-gate 21/21 PASS (self-cleaning); security-scan
0 CRITICAL; xss-audit clean. Live probe evidence: unauthenticated tenant
reads 0 rows; forged org id 0 rows; refresh token dead after logout;
garbage token 401.

**Known limitations:** access token valid until exp after remote logout
(standard GoTrue JWT semantics, 1h expiry). Full auth-gate doc:
`AUTHENTICATION_GATE_AND_ENTRY_ROUTING.md`.

## Session 20 (2026-09-12) — Regulator organization claim + provisioning — COMPLETE (live-verified)

**Trigger:** the "Claim Regulator Organization" action produced no visible result.

**Root cause (forensic):** the bootstrap view reported outcomes via `statusLine()` →
`el("govStatus")`, an element that only exists in the regulator command-center
`renderPanel()` — every result (success or failure) was invisible. Server-side the
Phase 11 RPC (`bootstrap_first_regulator_admin`, …090/…091) worked but had no
claimable orgs and no surfaced errors. Additionally discovered: the RBAC catalog
(`roles`/`permissions`/`role_permissions`/`plans`) was **empty on the live project**
(schema intact, rows gone), silently breaking all permission-gated surfaces incl.
the provision authorization path.

**Migrations (all applied live, HTTP 201):**
- `20260903000100_regulator_lifecycle.sql` — `provision_regulator_organization(p_name,
  p_county)` SECURITY DEFINER (platform-org membership + platform-scope role required;
  actor = `auth.uid()`; org_type/status server-set; atomic; single-active-regulator
  uniqueness) + `regulator_claim_status()` TVF (none_provisioned/claimable/already_claimed).
- `20260903000101_regulator_lifecycle_platform_roles.sql` — extended
`organization_members_role_check` with the 3 platform role codes (fixes latent 23514
in `bootstrap_first_platform_admin` and unblocks provision authorization).
- `20260903000102_reseed_catalog.sql` — restored the catalog rows verbatim from the
authoritative seeds (…030 + …073 + …094): 16 roles / 62 permissions / 428 bundles /
3 plans. Fidelity tool `scripts/check-reseed-fidelity.mjs` PASS before apply.

**Client:**
- `gov-admin.js` — claim surface now resolves state from `regulator_claim_status()`
before offering the button; confirmation modal; loading state; inline success /
already-claimed / not-authorized / no-eligible-org / session-expired / error
messages (silent no-op eliminated; raw internals never shown).
- `supabase-auth.js` — `regulatorClaimStatus()` wrapper.
- `org-admin.js` — regulator orgs render as Government Regulator with
regulator-appropriate actions (no commercial-only actions).
- `sw.js` — cache version bumped.

**Tests:** NEW `scripts/verify-regulator-lifecycle.mjs` **33/33 PASS, self-cleaning**
(provisioning authz + denials; duplicate prevention; empty-org onboarding; one-shot
claim with server-set role; member-caller denial; suspension blocking; forged
membership INSERT 403; forged args to 0-arg RPC rejected; audit
organizations.insert + organization_members.insert; 0 cross-tenant rows without a
grant). Wired into `run-all-probes.mjs` as `reg`. Full regression all-PASS: 04, 06,
06-cascade, 07, 08, 09, 10, 11 (**48/48 after de-seeding its shared-fixture
dependencies — probes now scaffold self-cleaning fixtures**, consistent with the
ADR-014 fresh-start), 12 (31/31), 13 (27/27), org-lifecycle (30/30), auth-gate
(21/21). `security-scan` 0 CRITICAL / 16 classified HIGH (baseline restored after
removing a stray throwaway diag script); `xss-audit` clean.

**Docs:** REGULATOR_ORGANIZATION_LIFECYCLE.md (new, as-built).

**Remaining:** platform-admin UI console (provisioning currently RPC-level, per
Phase 12 limitation); standing items unchanged (credential rotation, Phase 13 open
control rows, CI wiring, Firestore retirement approval).

## Session 21 (2026-09-13) — Worker join requests + admin approval + invitations + notifications/push — COMPLETE (live-verified)

**Trigger:** production directive: workers must be able to create an account,
request to join an existing organization, and gain only worker access until an
admin approves; admins must be able to review/approve/reject, receive
notifications, and switch workspaces. Reuse of the existing
membership/invitation/RBAC/RLS/audit architecture was mandatory.

**What already existed (reused, not duplicated):** Phase 04 invitations
(`org_invites`, 64-char token, email-matched single-use), `organization_members`
rows + `require_org_admin`, Phase 03 RBAC catalog, Phase 06 append-only audit
triggers, workspace resolution (`auth-gate.js`) + `showWorkerRefusal` UI guard,
org settings jsonb.

**Migrations (all applied live, HTTP 201):**
- `…00110_worker_join_requests.sql` — `organization_join_requests`
  (requested_role SERVER-SET worker/contractor; unique (org,user);
  RLS: requester-own + org-admin SELECT, writes RPC-only default-deny);
  `organization_search_joinable` (minimum public fields, opt-in-only discovery,
  restrictive default); `organization_request_join` (auth.uid-derived,
  duplicate/member/opt-in guards, admin notifications); `organization_review_join_request`
  (require_org_admin; FOR UPDATE + status re-check → race-safe; approval upserts
  ACTIVE worker membership; rejection records reviewer+reason, no membership;
  both outcomes notify the requester); `notifications` store (own-row RLS,
  server-written) + `my_notifications`/`mark_notification_read`;
  `organization_join_requests_list`/`my_join_requests`.
- `…00111_join_request_audit_cases.sql` — audit-capture cases for the two new
  tables (…090 republish verbatim + 2 cases; fidelity-checked).
- `…00112_join_requests_list_authz.sql` — **security fix:** the …110 list TVF
  was SECURITY DEFINER with no internal check (client-gated only) → added an
  explicit `require_org_admin` gate (cross-tenant enumeration denied server-side).
- `…00113_push_subscriptions.sql` — push foundation: `push_subscriptions`
  (endpoint SHA-256-hashed, RFC 8291 keys server-side only, unique
  (user,endpoint_hash), own-row RLS, RPC-only writes) +
  `register/deregister_push_subscription` (auth.uid-derived).
- `…00114_restore_phase04_permissions.sql` — probe-caught regression: Phase 04s
  `organizational_units.*` permission rows were lost with the pre-session catalog
  wipe and not part of the …102 reseed block → restored verbatim from …040.

**Client:**
- `join-requests.js` (NEW) — onboarding Join-an-Existing-Organization search +
  request UX; admin notification bell (unread badge, 60s poll) + panel;
  admin review card (approve/reject with loading states, confirmation,
  explicit success/failure — no silent no-op); org opt-in toggle.
- `admin.html` — onboarding options (Create / Claim / Join / Invite) with
  mutually exclusive forms; `join-requests.js` + `push-client.js` included.
- `index.html` — same includes for the worker app; gate NO_ORGANIZATION
  guidance now points at the join path (`lang.js` EN/FR updated).
- `app.js` — enable/disable notifications now (de)register Web Push via
  `push-client.js` (graceful no-op without VAPID key; never blocks flows).
- `supabase-auth.js` — wrappers: searchJoinableOrgs, requestJoinOrg,
  myJoinRequests, listJoinRequests, reviewJoinRequest, fetchMyNotifications,
  markNotificationRead, registerPushSubscription, deregisterPushSubscription.
- `sw.js` — `push-client.js` precached; cache v16.

**Tests:** NEW `scripts/verify-worker-join.mjs` **49/49 PASS, self-cleaning**
(discovery minimum-fields/opt-in/anonymous-denied; request submission +
duplicate/member/opt-in denials; forged role 404/400; direct-INSERT 403;
pending ≠ membership (0 incidents/org rows); admin notification; self-approval
denied; approval → ACTIVE worker membership; second-approval race denial;
own-only notification reads + cross-user mark-read no-op; worker cannot call
org_add_member / org_update_member_role; cross-tenant roster 0 rows + own-org
roster visible (Phase 00 foundation RLS, org-scoping verified); rejection with
reviewer+reason and NO membership; re-apply after rejection; role change
worker→admin→worker with revalidation; invitation token + accept + reuse
denied; audit coverage; cleanup verified). NEW `scripts/verify-push-foundation.mjs`
**9/9 PASS, self-cleaning** (anonymous denied; register/refresh; forged user_id
rejected; cross-user reads denied; direct INSERT denied; deregister own only).
Both wired into `run-all-probes.mjs` (`join`, `push`).

**Regression:** full suite re-run — 04 (fixed by …114), 05 (42/42), 06,
06-cascade, 07/08/09 (catalog counts updated 23 → 24 audit triggers for the new
join_requests trigger; notifications deliberately not trigger-audited), 10, 11
(48/48), 12 (31/31), 13 (27/27), org-lifecycle (30/30), regulator (green),
auth-gate (21/21), worker-join (49/49), push (9/9).
`security-scan` 0 CRITICAL / 16 HIGH (documented classified baseline);
`xss-audit` clean (9 files incl. join-requests.js).

**Docs:** WORKER_MEMBERSHIP_AND_INVITATION_LIFECYCLE.md (new, as-built).

**Remaining:** push **sender** (VAPID keys + delivery worker) not yet
provisioned — store/RPCs/client/SW display are ready; rejection reason is
reviewer-facing only (worker gets a neutral notification, by design);
standing items unchanged (platform-admin UI console, credential rotation,
Phase 13 open control rows, CI wiring, Firestore retirement approval).

## Feature inventory (baseline, audited)

| Capability (must preserve) | Where | Functional today | Tenant-aware today |
|---|---|---|---|
| Mining glossary (EN/FR) | `data.js` + `lang.js` | Yes (offline static) | n/a (public reference) |
| PPE guide + checklist | `data.js` | Yes | n/a |
| JSA create/list/delete | `app.js`, Firestore `jsas` + localStorage | Yes (single site-wide pool) | No |
| Hazard ID / risk select | `app.js` | Yes (hard-coded L/M/H/C) | No |
| Incident report + photos | `app.js`, Firestore `incidents` + localStorage | Yes (base64 in doc) | No |
| Emergency procedures | `data.js` | Yes | n/a |
| Emergency SOS activation | `admin.html` + `emergency_sos` + SW | Partial (boolean flag, broadcast, no real escalation) | No |
| Safety notices | `notices.js`/`admin.html`, `notices` | Yes (poll; read/ack counts are per-device, racy) | No |
| Notifications | SW local notifications + polling | Partial (no push service/subscription) | No |
| Offline PWA | `sw.js` cache | Yes (shell) | n/a |
| Worker activity | per-device localStorage registry | Cosmetic only (device count ≥1) | No |
| Admin dashboard + analytics | `admin.html` | Yes (client-side auth & aggregation) | No |
| Incident/JSA filtering + CSV export | `admin.html` | Yes | No |
| Soft delete / restore / purge | `firebase.js` deleted-flag ops + `audit_log` | Yes | No |
| Audit logging | `audit_log` collection | Client fire-and-forget, spoofable | No |
| Multilingual UI | `lang.js` | Yes | n/a |
| Connectivity indicators | `firebase.js` MG.online + banner | Yes | n/a |
