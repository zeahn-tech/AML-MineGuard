# MineGuard Liberia — Changelog

Format: date · change · docs · status.

---

## 2026-09-10 (session 18) — Organization lifecycle + authentication remediation COMPLETE

- **Root cause (user-reported error):** `bootstrap_first_owner()` is a claim mechanism (oldest
  memberless mining_company org); once every org has an owner it raises `no claimable organization
  found…`. No self-service organization creation existed (org INSERT default-deny).
- Migration `20260903000099_org_lifecycle.sql` applied live: `create_organization()`
  SECURITY DEFINER (atomic org + owner membership + starter subscription; collision-safe slug;
  mining_company/contractor/service_provider only; regulator/platform rejected; audit via existing
  triggers; no new RLS policies — INSERT stays default-deny) + `org_transfer_ownership()`
  (owner-only atomic swap, single-owner invariant, admins cannot seize) + org_type `service_provider`.
- Client: onboarding UI (Create / Claim / Join) replacing "Set Up Organization (Owner)"; selected-org
  model revalidated against current memberships (UI state only); org switcher; first-site onboarding
  via existing `site_create`; logout clears the org preference.
- Evidence: `verify-org-lifecycle.mjs` 30/30 PASS self-cleaning (incl. forged owner/role/status
  denials, anon 401, regulator/platform 400, isolation, single-owner invariant); full regression
  all-PASS (04, olc, 06, 06c, 07, 08, 09, 10, 11, 12, 13); scan 0 CRITICAL; XSS clean.
- New doc: ORGANIZATION_LIFECYCLE.md. Updated: IMPLEMENTATION_STATUS, SESSION_HANDOFF, DECISIONS
  (ADR-015), PROJECT_MASTER, ARCHITECTURE, DATABASE_ARCHITECTURE, SECURITY_MODEL, RBAC_MODEL,
  RLS_MATRIX, supabase/README.
- Status: COMPLETE — not VERIFIED-tier (CI wiring still open).

## 2026-09-10 (session 17) — Phase 05 cutover COMPLETE: fresh-start (ADR-014), safety notices live, client cut over

- **ADR-014 recorded** (owner directive): the Firestore data migration is WAIVED — fresh start in
  Supabase; the legacy anonymous Firestore channel becomes fallback-only (signed-out users); import
  prep (ADR-012) stays on disk if the decision is reversed.
- Migration `20260903000097_phase05_cutover_notices.sql` **applied live**: `safety_notices` +
  `safety_notice_acks` (org+site scope, broadcast via `site_id` null, per-user idempotent acks,
  `notices.manage`/org-admin write gate, regulator SELECT, `client_id` offline idempotency) + 2 additive
  audit triggers → 23 total.
- Migration `20260903000098_phase05_cutover_notices_fix.sql` **applied live** (probe-driven):
  `notice_soft_delete(notice_id)` SECURITY DEFINER RPC — direct `PATCH {deleted:true}` 42501s because
  PostgREST re-checks the SELECT policy on UPDATE…RETURNING (same class as the Phase 07 `Prefer`
  finding); RPC gated on the catalog `notices.delete` permission.
- Client: `notices.js` signed-in reads/writes via PostgREST with legacy-shape reverse-mappers (zero UI
  changes); soft-delete via the RPC; signed-out fallback unchanged.
- **Evidence:** `scripts/verify-phase05.mjs` (new) **42/42 PASS, self-cleaning** — catalog, two-org RLS
  matrix, worker denials, site-targeting visibility, ack idempotency/cross-user isolation, broadcast vs
  site scope, RPC soft-delete + audit capture, regulator scope, `client_id` idempotency. Full regression
  all-PASS (04/05/06/06c/07/08/09/10/11/12/13, run in subsets); security scan 0 CRITICAL.
- Probe maintenance: `verify-phase07/08/09.mjs` audit-trigger expectations 21 → 23; transient scratch-org
  cleanup helpers added after a timed-out suite run collided on `organizations_name_lower_uidx`.
- Status: Phase 05 COMPLETE (cutover executed; full Firestore retirement = later deletion step requiring
  explicit owner approval per ADR-014 consequence 3). Standing user action: rotate service-role key +
  DB password (session 16 incident, SECURITY_CERTIFICATION §2).

## 2026-09-10 (session 16) — Phase 13 COMPLETE: production hardening + security certification, live-verified

- **SECURITY INCIDENT (found by executing TESTING_STRATEGY §5):** `scripts/run-probes.sh` had the live
  service-role JWT + Supabase DB password committed to git. Remediated in-file (env-injected runner);
  **rotations REQUIRED (user action, dashboard-only, STILL OPEN)** — checklist in SECURITY_CERTIFICATION §2.
- New `scripts/security-scan.mjs`: automated secret-leak scan (CRITICAL rules exit 1 → CI fails closed);
  baseline 0 CRITICAL / 16 HIGH, every HIGH classified-accepted with inline rationale.
- Durable test suite: `npm test` = security scan + `scripts/run-all-probes.mjs` (all 10 live probes with
  summary + non-zero exit on failure). TESTING_STRATEGY rollout now has a one-command harness; E2E browser
  layer remains open.
- Migration `…096_phase13_hardening.sql` **applied live**: `site_create` enforces active-plan `max_sites`
  (back-compat unlimited for null cap / no subscription); `regulator_expire_due_grants()` audited idempotent
  expiry sweep (closes both Phase 12 recorded gaps).
- **Evidence:** `verify-phase13.mjs` **27/27 PASS self-cleaning** (max_sites cap + upgrade + back-compat;
  sweep lifecycle incl. idempotency + worker denial + audit capture + expired-grant 0-row reads; Phase 12
  RPC surface intact); full regression all-PASS (04, 06, 06-cascade, 07, 08, 09, 10, 11 48/48, 12 31/31).
- **XSS render-path audit added** (`scripts/xss-audit.mjs`, wired into `npm test`): 63 HTML sinks audited,
  ~30 genuine escapes added in admin.html/app.js/notices.js; allowlist of reviewed-safe interpolations
  documented in the scanner. SECURITY_CERTIFICATION row 14 closed at the static layer.
- New `docs/engineering/SECURITY_CERTIFICATION.md` (per-control DEMONSTRATED/ACCEPTED/OPEN with artifacts,
  incident record, residual risks, production-candidate gates); `PRODUCTION_READINESS.md` re-ticked with
  evidence; IMPLEMENTATION_STATUS Phase 13 COMPLETE; PROJECT_MASTER phase row 13 COMPLETE.
- Status: Phase 13 COMPLETE (not VERIFIED-tier — wire `npm test` into CI for that). Remaining open rows:
  rotations (user), XSS suite, rate limiting, MFA enablement, media re-encode, backups/DR drill; Phase 05
  cutover remainder (legacy Firestore channel) is the next fixed-order work item.

## 2026-09-09 (session 15) — Phase 12 COMPLETE: SaaS + enterprise administration, live-verified

- Migration `20260903000094_phase12_saas_enterprise.sql` applied to `vuniwebbrvpgxscdsfei`:
  - `plans` (seeded ≥3 tiers) + `subscriptions` (one active row per org) — **SaaS modeling only, billing deliberately deferred**.
  - Site management RPCs `site_create`/`site_update`/`site_remove` — closes the Phase 06 recorded gap (sites writes were service-role-only); permission codes sites.create/update/delete enforced server-side.
  - `org_update_settings` (settings.manage) merging into `organizations.settings`/`branding` jsonb; `org_update_subscription` (billing.manage).
  - Platform layer: `bootstrap_first_platform_admin` (one-shot), `platform_list_organizations` (tenant inventory), `platform_update_organization_status` (suspend/reactivate).
  - Grant expiry administration (Phase 11 gap): 5-arg `regulator_issue_grant` with validated `p_expires_at` + `regulator_extend_grant` (issuing org's national_regulatory_admin only).
  - `gov_national_overview()` — server-side national roll-up over the caller's ACTIVE grants only (documented plain counts; non-negotiable #7).
  - Dedicated `trg_audit_subscriptions` audit trigger (additive convention; shared `trg_audit_capture` NOT rewritten) — 21 audit triggers total.
- Probe-driven fix migration `20260903000095_phase12_fix_rpc_results.sql` (convention of Phase 11 `…091`–`…093`):
  - `regulator_issue_grant`: fixed plpgsql result capture (42601 `returning` without INTO).
  - `trg_audit_subscriptions_capture`: fixed audit_log column names (`resource_type` → `resource`; was 42703 on every subscription change).
  - `platform_list_organizations`: explicit P0001 for non-platform callers (was HTTP 200 `[]`).
  - **Dropped the legacy 4-arg `regulator_issue_grant` overload** — PostgREST PGRST203 could not resolve partial named-argument calls with both overloads present, breaking all Phase 11 grant issuance; one canonical 5-arg signature with defaults remains.
- `scripts/verify-phase12.mjs`: **31/31 PASS, self-cleaning** — catalog, plan visibility (anon sees plans, not subscriptions), site lifecycle + worker denial, settings persistence + denial, subscription switch + denial, grant expiry issue/extend/deny, platform gating, national overview correctness (grant reflected; revoked excluded; non-granted user = zeros), audit coverage.
- Client: `supabase-auth.js` Phase 12 wrappers (site CRUD, settings, plans/subscription, extend grant, platform trio, national overview); `org-admin.js` site management + settings/branding + plan card; `gov-admin.js` grant expiry field + Extend action + National Overview block.
- Regression: Phase 06, 06-cascade, 07, 08, 09, 10, 11 suites ALL PASS (07/08/09 trigger counts 20→21; Phase 11 recovered to 48/48 via the overload drop).
- Docs: IMPLEMENTATION_STATUS, SESSION_HANDOFF (session 15), PROJECT_MASTER, RLS_MATRIX, SECURITY_MODEL, DATABASE_ARCHITECTURE, RBAC_MODEL, GOVERNMENT_PLATFORM, ARCHITECTURE, supabase/README.
- Status: Phase 12 COMPLETE (recorded live probes; no CI suite — not VERIFIED-tier). Known limits: no billing provider/invoicing; no platform-admin UI (API-level only); `max_sites` not yet enforced; no expiry sweep job (reads already exclude expired grants).

---

## 2026-09-09 (session 14) — Phase 11 COMPLETE: Government regulatory command center, live-verified

- Migrations `20260903000090_phase11_government_authorization.sql` + fix migrations `…091`–`…093` applied to `vuniwebbrvpgxscdsfei` (verified via `migration list` — all four recorded in `schema_migrations`):
  - `government_grants` — the explicit authorization record behind every government cross-org access: (regulator org, regulator user) → (target org, optional site), scope label, regulator_role snapshot, issued_by/issued_at/expires_at, active/revoked/expired lifecycle, partial unique index = one active grant per (regulator org, user, target org, site). No grant ⇒ zero rows on every tenant table.
  - SECURITY DEFINER helpers: `auth_user_is_regulator_org_member`, `auth_user_is_regulator_user_in`, `current_user_active_government_grants` (the policy primitive; expiry checked at read time), `auth_user_has_regulator_grant_for`.
  - RPCs: `bootstrap_first_regulator_admin` (one-shot claim of the first active regulator org with no members; mining/contractor/platform excluded; callers holding ANY active membership denied per …091), `regulator_issue_grant` (national_regulatory_admin only; targets limited to mining_company/contractor; site must belong to target; grantee must be a government member of the regulator org; duplicate active grant upserts), `regulator_revoke_grant` (immediate), `regulator_update_user_role` (seeded government role codes only).
  - 16 grant-gated regulator SELECT policies (incidents, incident_evidence, incident_witnesses, jsas, inspections, corrective_actions, emergency_events/acks/escalations/responders/log, sites, organizational_units, workers, organization_members, audit_log). Permission checks (workers.view / users.view / audit_logs.view) evaluated against the REGULATOR org per fix …091 (…090 versions were dead policies against the target org).
  - `trg_audit_capture()` extended with the `government_grants` branch → 20 audit triggers total. RLS on government_grants: regulator org reads own; target-org members with `audit_logs.view` may read grants touching their org (GOVERNMENT_PLATFORM §5 transparency); writes RPC-only.
  - Fix …092: `organization_members_role_check` extended with the 4 seeded government role codes (regulator memberships failed 23514 before). Fix …093: grant INSERT RETURNING captured into a variable (plpgsql 42601 — every issuance failed at runtime despite passing authorization).
- `scripts/verify-phase11.mjs` on `vuniwebbrvpgxscdsfei`: **48/48 checks PASS, cleanup verified** — catalog; onboarding (claim/one-shot/membership-holders-denied/anon 401); grant lifecycle (issue site-scoped + org-wide, duplicate upsert same id, cross-checks denied, inspector cannot issue/revoke, revoke 204, role assignment, re-issue after revoke); regulator read scopes (0 AML rows without grant; org-wide grant sees target incidents/inspections/CAPAs/emergency/sites; workers stay 0 without workers.view; org members readable only with users.view at the regulator org — inspector sees 0; site-scoped grant sees site-1 only, 0 site-2 leaks; regulator INSERT 403); revocation immediacy (0 rows immediately after revoke); grants RLS (own org reads; target org audit_logs.view reads touching grants; direct INSERT 403); audit (actor email, trigger source); regression (org owner incident flow unchanged; government user sees 0 AML rows).
- **Probe incident fixed**: a prior interrupted run's cleanup had DELETED the seeded `liberia-regulator` org (cleanup deletes `scratchRegOrgId`, which `onboarding()` re-points at the bootstrap-claimed seeded org). Org restored (upsert); probe cleanup now guards against deleting the seeded regulator/AML ids. Leftover scratch orgs/users from interrupted runs cleaned; Phase 10 probe artifacts likewise cleaned.
- Regression: verify-phase06 (PASS), verify-phase06-cascade (PASS), verify-phase07 (PASS — count assertions updated to Phase 11 totals: policies 5/5/4, 20 triggers), verify-phase08 (ALL PASS — policies 5/5, 20 triggers), verify-phase09 (PASS — policies events=4 acks=3 esc=3 resp=4 log=2, 20 triggers), verify-phase10 (all PASS, cleanup verified).
- Client: `gov-admin.js` (new) — 🏛️ Government panel: one-shot regulator bootstrap, grant issue (org-wide or site-scoped)/revoke, grants table, National Command Center (org/site drill-down over granted orgs only; empty state explains the no-grant-isolation guarantee); `supabase-auth.js` Phase 11 wrappers (bootstrap/regulatorIssueGrant/regulatorRevokeGrant/regulatorUpdateUserRole/fetchMyGovernmentGrants/fetchIssuedGrants/fetchIncidentsGrantScoped/fetchEmergencyGrantScoped); `admin.html` nav + panel + gov CSS (anchored Node splices per convention); `sw.js` precache v11; `auth-ui.js` government role labels. All assets served 200 by the preview; inline scripts parse clean.
- Status: Phase 11 COMPLETE — not VERIFIED-tier (recorded live probes, no CI suite yet). Phase 10 and earlier stay COMPLETE; Phase 05 stays PARTIALLY_COMPLETE.
- Docs updated: IMPLEMENTATION_STATUS (Phase 11 COMPLETE + evidence), SESSION_HANDOFF (session 14), CHANGELOG (this entry), PROJECT_MASTER (phase table row 11), GOVERNMENT_PLATFORM (target → live), RLS_MATRIX (§1.2/§1.5 government live), SECURITY_MODEL (government grant model), DATABASE_ARCHITECTURE (government_grants + 20 triggers), RBAC_MODEL (government membership flows live), ARCHITECTURE (government architecture), supabase/README.

## 2026-09-08 (session 13) — Phase 10 COMPLETE: Offline-first synchronization, live-verified

- New `offline-store.js` — IndexedDB local database (outbox / records / attachments / kv) replacing localStorage-as-database; idempotent non-destructive legacy migration (`mineguard_incidents`/`jsas`/`notices`/`sos_state` → records with clientId backfill); UMD (`window.MG_STORE`).
- New `sync-engine.js` — offline queue engine: FIFO + EMERGENCY-priority drain, exponential backoff (2s→60s) with 8-attempt cap, `client_id` idempotency (dup POST → 409 = already-synced; local dedupe), conflict detection (stale local vs newer server `updated_at` → `conflict`, no overwrite), per-record sync states, attachment upload (blob → `incident-evidence` storage → `incident_evidence` row), connectivity heartbeat, legacy→Phase 07–09 payload adapters (incident/jsa/SOS) with RLS reporter integrity; UMD (`window.MG_SYNC`).
- Wiring: `index.html` + `admin.html` (script tags + shared bootstrap in head: store/migration/engine/heartbeat/auth-change re-resolution/SW drain messaging); `sw.js` (precache, `mineguard-sync-drain` background sync, `sync-drain` fan-out); `firebase.js` (`_mgSyncEnqueue()` hook in `saveIncidentToCloud`/`saveJSAToCloud`/`saveEmergencySOSCloud` — signed-in Supabase sessions enqueue through the engine; Firestore legacy mirror untouched).
- Bug fixes from probe iteration: `sync-engine.js` `root` scope binding (ReferenceError would have killed auto-drain in browsers); `drain()` hardening so transport throws apply backoff + mark network-down instead of stranding mutations in `syncing`.
- `scripts/verify-phase10.mjs` on `vuniwebbrvpgxscdsfei`: **all 14 checks PASS, cleanup verified** (real engine + in-memory store + real PostgREST transport: ordering/emergency-priority, idempotency, backoff/retry, conflict, reporter integrity, attachments+storage, tenant isolation).
- Regression: `verify-phase06.mjs` (51), `verify-phase07.mjs` (62), `verify-phase08.mjs` (41), `verify-phase09.mjs` (56) all still PASS (no table/trigger changes).
- Status: Phase 10 COMPLETE. Phase 09 stays COMPLETE; Phase 08/07/06 stay COMPLETE; Phase 05 stays PARTIALLY_COMPLETE.
- Docs updated: IMPLEMENTATION_STATUS, SESSION_HANDOFF (session 13), CHANGELOG (this entry), PROJECT_MASTER (phase table), OFFLINE_SYNC_ARCHITECTURE (target → live), ARCHITECTURE (offline sync), MIGRATION_PLAN, supabase/README.

## 2026-09-04 (session 12) — Phase 09 COMPLETE: Emergency response + SOS, live-verified

- Migration `20260903000080_phase09_emergency_sos.sql` + fix migrations `…081`–`…084` applied to `vuniwebbrvpgxscdsfei` via `supabase db push --linked`:
  - `emergency_events` / `emergency_acknowledgements` / `emergency_escalations` / `emergency_responders` / `emergency_log` tables (org+site scoped).
  - Lifecycle ACTIVATED→ACKNOWLEDGED→RESPONDING→CONTAINED→RESOLVED→CLOSED enforced forward-only server-side (`trg_emergency_events_guard`); activated_by forced to auth.uid() + pinned immutable; resolved_by immutable; legacy deactivation records resolver; site_notice_scope broadcast default true.
  - Per-user acks with unique(event,user) idempotency (device retries never duplicate); acks immutable (no UPDATE/DELETE policies); acked_by server-pinned.
  - Append-only `emergency_log` lifecycle stream written by triggers; SELECT-only grant (no client DML).
  - RLS per RLS_MATRIX §1.2: org-wide roles view/insert; supervisor site-scope view; worker/contractor site_notice_scope view + own ack; resolve/close gated on `emergency.resolve`; escalation/responder = response-chain gate (supervisor+). 14 policies; 5 new audit triggers → 19 total.
  - Fix migrations: `…081` site-scope acknowledge for child authz; `…082` dedicated escalation gate (workers ack-only); `…083` child-guard 42703 (responders have no created_by); `…084` responder gate = response-chain, unused helper dropped.
- `scripts/verify-phase09.mjs` on `vuniwebbrvpgxscdsfei`: **all checks PASS, cleanup verified** (~60 checks: catalog, INSERT/SELECT/UPDATE matrix, lifecycle guards, ack integrity + duplicate 409, escalation/responder gating, log append-only, two-org isolation, audit actor integrity + message non-leak).
- Regression: `verify-phase06.mjs` + `verify-phase06-cascade.mjs` + `verify-phase07.mjs` + `verify-phase08.mjs` all still PASS; Phase 07/08 trigger-count assertions updated 14→19.
- Status: Phase 09 COMPLETE. Phase 08 stays COMPLETE; Phase 07 stays COMPLETE; Phase 06 stays COMPLETE; Phase 05 stays PARTIALLY_COMPLETE.
- Docs updated: IMPLEMENTATION_STATUS, SESSION_HANDOFF (session 12), CHANGELOG (this entry), PROJECT_MASTER (phase table), RLS_MATRIX, SECURITY_MODEL, DATABASE_ARCHITECTURE, EMERGENCY_RESPONSE_ARCHITECTURE, MINING_DOMAIN_MODEL, MIGRATION_PLAN, supabase/README.

## 2026-09-04 (session 11) — Phase 08 COMPLETE: JSA + inspection + corrective actions, live-verified

- Migrations `20260903000070_phase08_jsas.sql` + `20260903000071_phase08_inspections_capa.sql` + fix migrations `…072`/`…073` applied to `vuniwebbrvpgxscdsfei` via `supabase db push --linked`:
  - `jsas` / `jsa_steps` tables (org+site scoped; approval flow; `site_notice_scope`; soft-delete; client_id idempotency).
  - `inspections` / `corrective_actions` tables (org+site scoped; inspection_type/status/priority enums; polymorphic source linkage; soft-delete; client_id idempotency).
  - RLS policies with SECURITY DEFINER helpers: inspections (4 policies: select restricted to admin/safety/site-roles; insert/update gated by permission; delete admin-only). CAPA (4 policies: select org-admin + site-roles; insert/update by permission; delete admin-only).
  - `trg_audit_capture()` extended with `inspections` + `corrective_actions` branches (curated metadata) → 14 audit triggers total.
  - Fix migrations: inspection SELECT restricted (no worker access); CAPA SELECT uses `auth_user_has_site_access`; added `inspections.delete` + `corrective_actions.delete` permissions to catalog; fixed `auth_user_can_update_capa` for site-only assignees.
- `scripts/verify-phase08.mjs` on `vuniwebbrvpgxscdsfei`: **all checks PASS, cleanup verified**.
- Regression: `verify-phase06.mjs` + `verify-phase06-cascade.mjs` + `verify-phase07.mjs` all still PASS.
- Phase 07 probe trigger count updated from 10→14.
- Status: Phase 08 COMPLETE. Phase 07 stays COMPLETE; Phase 06 stays COMPLETE; Phase 05 stays PARTIALLY_COMPLETE.
- Docs updated: IMPLEMENTATION_STATUS, SESSION_HANDOFF (session 11), CHANGELOG (this entry), PROJECT_MASTER (phase table).

## 2026-09-04 (session 10) — Phase 07 COMPLETE: incident + evidence management, live-verified

- Migrations `20260903000060_phase07_incidents.sql` + `20260903000061_phase07_storage_evidence.sql`
  applied to `vuniwebbrvpgxscdsfei` via `supabase db push --linked`:
  - `incidents` / `incident_evidence` / `incident_witnesses` tables (org-scoped; Phase 05 mapper
    payload shape is a direct column subset; status lifecycle DRAFT…CLOSED; soft-delete;
    `site_notice_scope` broadcast flag).
  - Scope triggers: reporter FORCED to `auth.uid()` server-side on INSERT + pinned immutable
    on UPDATE; evidence/witness org/site mirrored from the incident; site/department org-consistency.
  - RLS_MATRIX §1.2 helpers + 11 policies: org-wide roles (owner/admin/safety_manager/
    safety_officer); site roles (site_manager/supervisor at row's site); worker own-only;
    site_notice_scope broadcast; hard-delete owner/admin/safety_manager only.
  - `trg_audit_capture()` extended with 3 safety-domain branches (curated metadata; body text /
    storage paths / statements never mirrored; org-scope nulling on cascade preserved)
    + 3 audit triggers → 10 total.
  - Private `incident-evidence` bucket (10 MB/object, image/pdf/video allowlist) + 4
    `storage.objects` policies resolving the incident token from path segment 6 through the
    incident's own RLS.
- `scripts/verify-phase07.mjs` on `vuniwebbrvpgxscdsfei`: **all checks PASS, cleanup verified**.
  Covered: catalog, full INSERT/SELECT/UPDATE/DELETE matrix across 6 roles, reporter spoof
  rejection, cross-site + cross-org insert denial, site_notice_scope broadcast scoping,
  evidence/witness scope, storage upload/download allowed+blocked, two-org tenant isolation
  (both directions), audit actor integrity + body-text non-leak + append-only.
- `scripts/verify-phase06.mjs` re-run: **all PASS** (no regressions).
- `scripts/verify-phase06-cascade.mjs` re-run: **all PASS** (no regressions).
- PostgREST note recorded: `Prefer: return=representation` on INSERT with RLS re-checks the
  SELECT policy on the RETURNING row and returns 42501 even when the INSERT is allowed
  (empirically verified; not an authz bug).
- Status: Phase 07 COMPLETE — not VERIFIED-tier (recorded live probes, no CI suite yet). Phase
  06 stays COMPLETE; Phase 05 stays PARTIALLY_COMPLETE.
- Docs updated: IMPLEMENTATION_STATUS, SESSION_HANDOFF (session 10), CHANGELOG (this entry),
  PROJECT_MASTER (phase table), RLS_MATRIX (§1.2 incidents live), SECURITY_MODEL (§2.4 storage
  live, §2.6 safety-domain triggers), DATABASE_ARCHITECTURE (§2.3/§2.5), MINING_DOMAIN_MODEL,
  MIGRATION_PLAN (§7 gate), supabase/README.

## 2026-09-03 (session 9) — Phase 06 COMPLETE: RLS_MATRIX enforcement + append-only server-side audit, live-verified

- Migrations `20260903000050_phase06_rls_audit.sql` / `…051_fix_org_delete_audit.sql` /
  `…052_fix_cascade_org_delete.sql` (from the prior interrupted session) confirmed applied +
  live-verified this session; migration history repaired (50–52 recorded in
  `supabase_migrations.schema_migrations` so `db push` applies only pending files).
- **NEW** `20260903000053_phase06_add_sites_audit.sql` (pushed via CLI): closes a real gap the
  new cascade regression probe exposed — `sites` had NO audit trigger (Phase 06 covered 6
  tables but omitted it). Adds the `sites` branch to `trg_audit_capture()` (name/location/
  county/status, org-scope nulling on org/cascade delete) + `trg_audit_sites`.
- **NEW** `scripts/verify-phase06-cascade.mjs`: org cascade-delete regression — single DELETE of
  an org with site + org member + site member + unit + worker + invite succeeds; ALL 7
  dependent rows cascade-removed; append-only audit rows retained for every resource with
  `organization_id` null (platform-scope, FK-safe), source='trigger', actor null under
  service-role (expected). All PASS, cleanup verified.
- `scripts/verify-phase06.mjs` re-run: all PASS, cleanup verified — site-scope SELECT matrix
  (site-only supervisor sees own site/units only; no site B; no org rows/invites/roster),
  least-privilege workers registry (0 rows for worker + site supervisor), organizations UPDATE
  gate by effect (owner changes stick; worker/outsider/other-org no-ops), cross-tenant 0 rows
  of AML, audit capture actor = auth.uid() (11 rows, 0 missing actions), invite tokens never
  mirrored, audit_log append-only (SELECT only; INSERT/UPDATE/DELETE → 403 and row count
  unchanged), escalation attempts 403.
- Status: Phase 06 COMPLETE — not VERIFIED-tier (recorded live probes, no CI suite yet). Phase
  05 remains PARTIALLY_COMPLETE (import still gated on ADR-003 export + safety-domain tables
  Phases 07–09 + review sign-off).
- Docs updated: IMPLEMENTATION_STATUS (Phase 06 COMPLETE + evidence), SESSION_HANDOFF (session
  9), PROJECT_MASTER (phase table), RLS_MATRIX, SECURITY_MODEL, DATABASE_ARCHITECTURE,
  RBAC_MODEL, supabase/README.

## 2026-09-03 (session 8) — Phase 05 PARTIALLY_COMPLETE: legacy volume measured + mapping/validation baseline (prep; zero DB writes)

- `scripts/phase05-inventory.mjs` fixed + extended: vocab-bucket bug; photo payloads now retained in
  the gitignored snapshot (strip threshold 4096 → 8 MB) so mapping can hash/type/export them. Ran
  read-only against live `aml-mineguard` Firestore (same anonymous REST channel as the shipped app).
  Measured volumes (previously "?"): incidents 4 (2 soft-deleted; 5 embedded data-URL JPEGs ≈ 881 KB
  decoded), jsas 4 (3), notices 12 (10), audit_log 64, emergency_sos 7 — 100% createdAt coverage;
  field census 19/13/16/6/20. Snapshot: `supabase/legacy-inventory/` (gitignored, sha256 manifest).
- `scripts/phase05-map.mjs` (new): pure/offline/deterministic/restartable mapper (tenant #1
  `arcelormittal-liberia`, seeded-site resolution, human-decision gates). Outputs under
  `supabase/migration-prep/` (gitignored): payloads for incidents/jsas/notices/emergency_events/
  audit_log (91 rows = 91 source docs; legacy `client_id` idempotency keys; soft-delete + legacy
  timestamps preserved), photos.manifest.ndjson (Phase 07 storage work queue), mapping-report.json
  (validation baseline), review-lists.json (29 items / 4 groups + 7 proposed workers + 2 proposed
  departments). Decisions via overrides.json; payloads byte-identical across re-runs (verified).
- Validation all PASS: source counts = inventory on all 5 collections; 0 required-field violations;
  audit orphans 50 (delete 25/purge 16/restore 9 — reference purged docs, expected); unique client ids.
- Data-quality findings surfaced (not silently fixed): site/zone vocab vs seeded sites (Tokadeh Mine /
  Uritton / Tokadeh / Lower Gangra / Bench 6 / Pit 3 / Rampard / Concentrator / WBHO Sites / Bench 12);
  badge hygiene (Nohama Dola AML-34 + AML-56 across docs; John Sebah shares AML-34; 4 jsas-only
  workers unbaged); free-text supervisors/witnesses.
- NOTHING imported. Cutover still gated: durable Firestore export (ADR-003), target tables + RLS
  (Phases 06–09), org-owner review sign-off, Phase 06 suite green.
- Docs updated: IMPLEMENTATION_STATUS, SESSION_HANDOFF (session 8), DECISIONS (ADR-012),
  MIGRATION_PLAN, PROJECT_MASTER, supabase/README. `.gitignore` covers both gitignored output dirs.
- Status: PARTIALLY_COMPLETE (evidence = recorded live probes + deterministic local validation; no
  automated CI suite yet). Next per phase order: Phase 06 (RLS + security enforcement).

## 2026-09-03 (session 7) — Phase 04 COMPLETE: site hierarchy + site-scoped permissions + org-admin flows, live-verified

- Migration `20260903000040_phase04_site_hierarchy.sql` (+ appended fix
  `20260903000041_phase04_fixes.sql`) applied to `vuniwebbrvpgxscdsfei`: `organizational_units`
  (departments/teams/work zones), `site_members` (site-scoped roles, same 9 org role codes),
  `workers` (worker registry), `org_invites` (email invites, sha256 one-time tokens); scope
  constraint triggers; RLS on all four (org-membership SELECT, default-deny writes).
- Site-scoped authz: `auth_user_site_effective_role` / `auth_user_has_site_access` /
  `auth_user_has_site_permission`; `auth_user_has_permission` + `auth_user_permissions` upgraded
  to max(org role, site role) for org members — site-only users keep site scope only (no org
  escalation, verified negative test). Permission catalog 60 → 62
  (`organizational_units.create/.update`).
- SECURITY DEFINER RPCs: org member add/re-role/remove (owner-protected), invite
  send/accept/revoke (email-match accept), site member assign/remove (site_manager of own site),
  unit create/update/remove, worker add/update/remove, `org_list_members` (emails, org-members
  only). PUBLIC EXECUTE revoked from all new functions.
- Client: `supabase-auth.js` Phase 04 wrappers (generic `rpc()` + GET helpers); `org-admin.js`
  Organization panel; `admin.html` nav item + panel; `sw.js` precache; preview serves all (200).
- Evidence: `scripts/verify-phase04.mjs` **58/58 PASS** with cleanup verified (isolation,
  authorization gates, invite lifecycle, site-scope matrix, trigger rejections); Phase 03
  regression (`verify-rbac.mjs`) still all-PASS after the helper upgrade; `verify-supabase.mjs`
  no FAIL; `node --check` clean.
- Fix migration note: `gen_random_bytes` (pgcrypto) replaced with core sha256 for invite tokens;
  `org_list_members` return column cast to text (auth.users.email is varchar).
- Docs updated: IMPLEMENTATION_STATUS, SESSION_HANDOFF (session 7), DECISIONS (ADR-011),
  DATABASE_ARCHITECTURE, RLS_MATRIX, RBAC_MODEL, MINING_DOMAIN_MODEL, PROJECT_MASTER,
  supabase/README.
- Status: COMPLETE — not VERIFIED-tier (recorded probes, no CI suite yet). Next per phase order:
  Phase 05 (data migration; still gated on the Firestore export/backup, ADR-003).

## 2026-09-03 (session 6) — Phase 03 COMPLETE: RBAC + permissions catalog + authz helpers, live-verified

- Migration `20260903000030_phase03_rbac.sql` applied to `vuniwebbrvpgxscdsfei`: `permissions`
  (60 codes / 19 domains), `roles` (16 system roles: 3 platform + 4 government + 9 organization),
  `role_permissions` (seeded bundles per RBAC_MODEL §3; owner = full 60, worker = self-service set),
  `organization_members.role` expanded to the 9 org roles, authz helpers
  (`auth_user_effective_role` / `auth_user_has_permission` / `auth_user_permissions`), RLS on catalogs
  (authenticated SELECT, writes default-deny).
- Client: `supabase-auth.js` RPC wrappers (`fetchEffectiveRole` / `hasOrgPermission` /
  `fetchMyPermissions`); `auth-ui.js` + `lang.js` EN/FR labels for all 9 org roles.
- `scripts/verify-supabase.mjs` extended; `scripts/verify-rbac.mjs` added (self-cleaning live probe:
  owner/worker/outsider permission matrix, tenant isolation, escalation attempts → 403, cleanup
  verified). 30/30 checks PASS on the live project; anon RPC checks PASS; AML tenant #1 untouched.
- Docs updated: IMPLEMENTATION_STATUS (Phase 03 COMPLETE + evidence), SESSION_HANDOFF (session 6),
  DECISIONS (ADR-010), RBAC_MODEL, RLS_MATRIX, PROJECT_MASTER, supabase/README.
- Status: COMPLETE — not VERIFIED-tier (recorded probes, no CI suite yet).

## 2026-09-03 (session 5) — Phase 02 COMPLETE: Supabase Auth + identity replaces the static-credential gate

- `config.js` (publishable keys) + `supabase-auth.js` (zero-dep GoTrue REST client: sign-in/up/out,
  refresh, memberships, org fetch, `bootstrapFirstOwner` RPC) + `auth-ui.js` (worker-app account chip +
  modal, EN/FR). `index.html` + `sw.js` wired.
- `admin.html`: removed hard-coded `admin`/`mineguard2024` gate + plaintext `mg_admin_pass` storage;
  email/password sign-in via Supabase Auth, dashboard gated on ACTIVE owner/admin membership,
  silent session restore, logout → GoTrue; Settings password row removed; actor name on records now the
  signed-in email.
- Migration `20260903000020_phase02_auth_onboarding.sql` applied: `bootstrap_first_owner()`
  (SECURITY DEFINER; first user claims first ACTIVE mining_company org with no members as owner;
  regulator orgs excluded) + self-service membership policies (own `invited` INSERT, withdraw-only
  UPDATE; self-promotion impossible).
- Live-verified on `vuniwebbrvpgxscdsfei` with a temporary probe user (created via signup + SQL email
  confirm, deleted after): tenant isolation 0 rows; self-promotion attempts 403; invite/withdraw work;
  DELETE is an RLS no-op; bootstrap claim + second-claim rejection exercised against a scratch org;
  anon RPC → 401. AML restored active with 0 members (claimable). Preview serves all new assets (200).
- Docs updated: IMPLEMENTATION_STATUS (Phase 02 COMPLETE + evidence), SESSION_HANDOFF (session 5),
  DECISIONS (ADR-009). Status: COMPLETE — not VERIFIED-tier (no automated suite yet).

## 2026-09-03 (session 4) — Phase 01 COMPLETE: schema applied + smoke-verified on live Supabase project

- Project `vuniwebbrvpgxscdsfei` linked (user supplied access token; env saved to sandbox `.env.local`,
  gitignored). `supabase` CLI added as devDependency.
- Pushed `20260903000000_tenant_foundation.sql` + follow-up `20260903000010_grant_standard_privileges.sql`
  (initial push surfaced 42501 privilege denials — grants added per Supabase convention).
- Seed applied via Management API: ArcelorMittal Liberia tenant #1 (active, mining_company) + Nimba Mine /
  Port Operations sites; Liberia regulator placeholder org.
- Added `scripts/verify-supabase.mjs` (zero-dep smoke checker) + `.gitignore` (env, `supabase/.temp/`).
- Verified: RLS on all tenancy tables; anon SELECT → 200 with 0 rows; helper RPC (anon) → false;
  elevated queries confirm seed rows. Supabase integration reported to catalog.
- Status: Phase 01 COMPLETE (smoke-verified; not VERIFIED-tier — no formal automated suite yet).
  Docs updated: DECISIONS (ADR-008 verification), IMPLEMENTATION_STATUS, PROJECT_MASTER, SESSION_HANDOFF.

## 2026-09-03 (session 3) — Phase 01: Supabase backend decided; tenant foundation authored (UNVERIFIED)

**Backend decision (ADR-008):** Supabase (PostgreSQL + RLS + Auth + Storage). User directive
2026-09-03; ADR-005 recommendation superseded. Firestore data migrates to Supabase in Phase 05.

Added (authored, NOT yet applied to any live database)
- `supabase/migrations/20260903000000_tenant_foundation.sql` — organizations / sites /
  organization_members + authz helper functions (`current_user_org_ids`, `auth_user_has_org_access`,
  `auth_user_is_org_admin`) + RLS enabled with membership SELECT policies; writes default-deny.
- `supabase/seed.sql` — idempotent tenant #1 (ArcelorMittal Liberia) + Nimba Mine / Port Operations sites
  + Liberia regulator placeholder org.
- `supabase/README.md` — env vars, apply/verify instructions, conventions.

Docs updated: DECISIONS (ADR-008), PROJECT_MASTER, ARCHITECTURE, DATABASE_ARCHITECTURE, RLS_MATRIX
(target = Supabase Postgres), IMPLEMENTATION_STATUS (Phase 01 IN_PROGRESS), SESSION_HANDOFF, CHANGELOG.

Status: schema authored but **UNVERIFIED** — apply + RLS smoke tests blocked on Supabase project
credentials (`NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`,
`SUPABASE_DB_URL`). No app code changed this session; no data changes.

## 2026-09-03 (session 2, interim) — Preview dev-server harness added

**No application code changed; no data changes.** The Freebuff preview failed because the repo is a
static, no-build app with no `package.json` (`npm run dev` → ENOENT). Fixed by adding:

- `package.json` — `dev`/`start` scripts (`node server.mjs`), zero dependencies.
- `server.mjs` — dependency-free static dev server (node:http) that binds `0.0.0.0`, honors
  `-p/-H` args and the injected `PORT` env var, serves correct MIME types, and blocks traversal/hidden
  paths (raw-socket probes: `/.git/config`, `..%2f` sequences → 403; `/`, `/admin.html`, assets → 200).
  Dev/preview only — not for production.

Verified: `freebuff-preview start` reported ready; HTTPS probes of the preview URL returned
`200 text/html` for `/` and `/admin.html`.

Status: preview harness working. Phase 01 overall remains gated on ADR-005 backend-path sign-off and
Firebase console verification (ADR-003) — see IMPLEMENTATION_STATUS.md / SESSION_HANDOFF.md.

## 2026-09-03 — Phase 00: architecture audit + engineering documentation (session 1)

**No application code changed.** First session of the production transformation program.

Added
- `/docs/engineering/` documentation suite (17 files): PROJECT_MASTER, IMPLEMENTATION_STATUS,
  ARCHITECTURE, DATABASE_ARCHITECTURE, SECURITY_MODEL, RLS_MATRIX, RBAC_MODEL, MINING_DOMAIN_MODEL,
  OFFLINE_SYNC_ARCHITECTURE, EMERGENCY_RESPONSE_ARCHITECTURE, GOVERNMENT_PLATFORM, MIGRATION_PLAN,
  TESTING_STRATEGY, PRODUCTION_READINESS, DECISIONS, CHANGELOG, SESSION_HANDOFF.

Audit highlights recorded (details in SECURITY_MODEL.md)
- CRITICAL: hard-coded admin credentials + client-only admin gate (admin.html:1629 `admin`/`mineguard2024`);
  API-key-only Firestore REST data plane (firebase.js/sw.js/firebase_rest_test.html); zero tenant isolation;
  localStorage-as-database with no retry queue (silent offline data loss); spoofable audit log; plaintext
  localStorage credentials.
- HIGH: single-tenant hard-coding; poll-everything realtime; whole-collection downloads (limit 500, no
  cursors); unbounded destructive API surface.
- MEDIUM: 3,055-line admin.html monolith; duplicate serialization code; racy read/ack counters;
  render-path XSS audit pending; no backups/export automation.
- LOW: stale comments/versions; dev diagnostic pages shipped; hard-coded update URLs.

Baseline preserved feature inventory recorded in IMPLEMENTATION_STATUS.md (glossary, PPE, JSA, incidents +
photos, emergency/SOS, notices, i18n EN/FR, PWA offline, admin analytics/filtering/CSV, soft-delete/restore,
audit log, connectivity indicators).

Next
- Phase 01 definition and gates recorded in SESSION_HANDOFF.md; see Phase 01 "Next task".

## Session 19 (2026-09-12)

- NEW `auth-gate.js`: authentication gate + centralized destination resolver
  (AUTH_REQUIRED / NO_ORGANIZATION / SELECT_ORGANIZATION / WORKER_WORKSPACE /
  COMPANY_ADMIN) reading only RLS-filtered server rows.
- index.html: splash dismissal now entry-gated; worker workspace no longer
  reachable unauthenticated; no protected-UI flicker before auth resolves.
- auth-ui.js: sign-in/sign-up route via `routeAfterAuth`; sign-out returns
  to the gate and clears selected-org preference + private tenant state.
- sw.js: gate precached; cache version bumped.
- Tests: `scripts/verify-auth-gate.mjs` (21 checks) wired into the durable
  suite; 21/21 PASS live. Security scan 0 CRITICAL; XSS audit clean.
- Docs: AUTHENTICATION_GATE_AND_ENTRY_ROUTING.md (new).

