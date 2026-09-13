# MineGuard Liberia — Session Handoff

| Field | Value |
|---|---|
| Session | 21 — Worker join requests + admin approval + notifications/push COMPLETE (join-requests.js; migrations …110–…114 applied live; verify-worker-join 49/49 + verify-push-foundation 9/9 PASS self-cleaning; full regression all-PASS). Prior: 20 — Regulator organization claim + provisioning COMPLETE (…100–…102; verify-regulator-lifecycle 33/33). Prior: 18 — Organization lifecycle + authentication remediation COMPLETE (create_organization + org_transfer_ownership RPCs applied live; onboarding UI create/claim/join; selected-org model + switcher; verify-org-lifecycle 30/30 PASS; full regression all-PASS). Prior: 17 — Phase 05 cutover COMPLETE (fresh-start, ADR-014): owner waived the Firestore import; migrations `…097` (safety_notices + acks) + `…098` (soft-delete RPC) applied live; `notices.js` cut over to PostgREST for signed-in users (Firestore = fallback-only); `verify-phase05.mjs` 42/42 PASS self-cleaning; full probe suite (04/05/06/06c/07/08/09/10/11/12/13) all-PASS after audit-trigger-count expectations updated 21→23; **rotations from the session-16 incident still REQUIRED** |
| Date | 2026-09-13 |
| Agent | Buffy (Freebuff/Vly) |

## Session 21 — what was completed (Worker membership + invitations + notifications/push, COMPLETE)

Context: production directive — workers create an account, request to join an existing
organization, and get worker-only access until an admin approves; admins review/approve/reject,
get notified (in-app + push-ready), and can switch workspaces. Reuse-first forensic audit done first.

- **Reused (no parallel systems):** Phase 04 invitations (org_invites tokens), organization_members +
  require_org_admin, Phase 03 RBAC, Phase 06 audit triggers, auth-gate workspace resolution +
  showWorkerRefusal, org settings jsonb.
- **Migrations …110–…114 applied live (HTTP 201):** join-request table + server-set roles + RPCs
  (request/review race-safe), notifications store, opt-in-only discovery TVF, audit-capture cases,
  **security fix …112** (list TVF require_org_admin gate — was client-gated only), push foundation
  …113 (push_subscriptions: hashed endpoints, RPC-only, own-row RLS), …114 restores Phase 04
  organizational_units.* permission rows lost in the catalog wipe (probe-caught regression).
- **Client:** join-requests.js (onboarding join UX + admin review card + notification bell + opt-in
  toggle), admin.html onboarding options incl. Join, app.js push (de)registration via push-client.js
  (graceful no-op until VAPID), supabase-auth.js wrappers, sw.js v16.
- **Probes:** verify-worker-join 49/49 + verify-push-foundation 9/9 PASS self-cleaning; wired into
  run-all-probes (join, push). Full regression all-PASS (04 fixed by …114; 07/08/09 catalog counts
  23→24 triggers). security-scan 0 CRITICAL / 16 HIGH baseline; xss-audit clean (9 files).
- New doc: WORKER_MEMBERSHIP_AND_INVITATION_LIFECYCLE.md (as-built).

## Session 21 (follow-up) — account-creation UX verification + gate onboarding actions

User report: the "Set organization" button was unreachable when creating an account.

**Live verification (REST-level, exact client call chain):** signup (autoconfirm ON → immediate
session, no email round-trip) → fetchMyMemberships → 0 rows (NO_ORGANIZATION) →
organization_search_joinable reachable (join flow usable). Account creation itself works
correctly server-side.

**Root cause of the report:** (1) auth-gate.js "Create Account" button opened the modal in sign-IN
mode (openAuthModal ignored its mode argument — openModal always reset to signin), so users had to
discover the hidden toggle link; (2) the NO_ORGANIZATION gate showed guidance TEXT with no action —
the Create/Join onboarding existed only on the admin sign-in screen (the literal "Set Up
Organization (Owner)" button no longer exists; it was replaced in session 18 by Create/Claim/Join
options).

**Fixes (client-only, no schema change):** auth-ui.js openModal(mode) honors the requested mode +
exposes window.MG_AUTH_UI.open/close; auth-gate.js uses the hook and adds an actionable SET YOUR
ORGANIZATION section (Create/Join buttons → admin.html?onboard=create|join) shown for
NO_ORGANIZATION; admin.html showClaimStep deep-links to the requested form. Probes re-run: auth-gate
21/21, worker-join 49/49, push 9/9, org-lifecycle 30/30, regulator 33/33, phase04 green.
security-scan 0 CRITICAL (scanner probe-password classification extended to the Mg*Pass! family —
3 false CRITICALs from new probe scripts eliminated; 19 classified HIGH = documented baseline).

## Session 21 — standing user actions + next session

- Provision the push **sender** (VAPID keys + delivery worker) when push delivery is wanted — the
  store/RPCs/client/SW display are ready; in-app notifications remain authoritative.
- STILL OPEN from session 16: rotate service-role key + DB password (SECURITY_CERTIFICATION §2).
- Phase 13 open control rows unchanged (rate limiting, MFA, media re-encode, DR drill).
- Full Firestore retirement still requires explicit owner approval (ADR-014); platform-admin UI
  console still RPC-level (Phase 12 limitation); CI wiring for probes still open.

## Session 18 — what was completed (Organization lifecycle + authentication remediation, COMPLETE)

Context: user-reported error `no claimable organization found…` for new sign-ups. Forensic audit
first (findings in IMPLEMENTATION_STATUS §Session 18), then implementation:

- **Migration `…099_org_lifecycle.sql` applied live (HTTP 201):** `create_organization()`
  (atomic org + owner + starter subscription; collision-safe slug; type whitelist —
  regulator/platform rejected; ownership derived from auth.uid(); audit via existing triggers) and
  `org_transfer_ownership()` (owner-only, atomic swap, single-owner invariant, admins cannot
  seize); org_type extended with `service_provider`.
- **Client onboarding UI (admin.html):** Create New Organization / Claim Existing Organization
  (labeled bootstrap-only) / Join by invitation. `attemptAdminEntry` → `resolveActiveOrg`.
- **Selected-org model (supabase-auth.js):** preference is UI state, revalidated against CURRENT
  active memberships; cleared on logout. Org switcher + first-site onboarding card in org-admin.js.
- **New probe `verify-org-lifecycle.mjs`: 30/30 PASS self-cleaning**; wired into the suite as
  `olc`. Full regression all-PASS (04, olc, 06, 06c, 07, 08, 09, 10, 11, 12, 13); security scan
  0 CRITICAL; XSS audit clean.
- New doc: `ORGANIZATION_LIFECYCLE.md` (full lifecycle + diagrams + security boundaries).

## Session 18 — standing user actions + next session

- STILL OPEN from session 16: rotate service-role key + DB password (SECURITY_CERTIFICATION §2).
- Phase 13 open control rows unchanged (rate limiting, MFA, media re-encode, DR drill).
- Full Firestore retirement still requires explicit owner approval (ADR-014).
- Wire `npm test` into CI to move artifacts to VERIFIED-tier.

## Session 17 — what was completed (Phase 05 cutover — fresh-start, ADR-014)

Context: owner directive "Let go every data migration from Firestore, we are going to start afresh with
new data in Supabase" → ADR-014. The prior session had authored migration `…097` + client cutover but
was interrupted before apply/verify. This session completed the cutover:

- **ADR-014 recorded** in DECISIONS.md (fresh-start; Firestore = fallback-only channel for signed-out
  users; import prep stays on disk if the decision is ever reversed).
- **Migrations `…097` + `…098` applied live** (…097 was already applied by the interrupted session;
  …098 added the `notice_soft_delete` SECURITY DEFINER RPC — PostgREST re-checks the SELECT policy on
  PATCH…RETURNING, same 42501 class as the Phase 07 `Prefer` finding).
- **`scripts/verify-phase05.mjs` (new)**: 42/42 PASS, self-cleaning — catalog, two-org RLS matrix,
  worker write denials, site-targeting visibility, ack idempotency + cross-user isolation, broadcast vs
  site scope, admin soft-delete via RPC + audit, regulator read scope, `client_id` idempotency.
- **Probe catalog-drift updates**: `verify-phase07/08/09.mjs` audit-trigger count 21 → 23 (two new
  notices triggers). Suite-hygiene: a timed-out suite run leaves scratch orgs that collide on
  `organizations_name_lower_uidx` on re-run; clean leftovers first (transient helpers
  `scripts/inspect-leftovers.mjs`, `scripts/clean-p8-residue.mjs`).
- **Full regression all-PASS** (run in subsets to stay under the terminal timeout): 04, 05, 06, 06c,
  07, 08, 09, 10, 11, 12, 13; security scan 0 CRITICAL.

## Session 17 — verification evidence (recorded)

- Migration history: `…096`, `…097`, `…098` all recorded in `supabase_migrations.schema_migrations`.
- `verify-phase05.mjs` 42/42 PASS + residue {notices:0, orgs:0}; Phase 07/08/09 re-run ALL-PASS after
  the trigger-count fix; Phase 08 was also blocked by a leftover-org name collision from an earlier
  timed-out run (cleaned, then ALL-PASS).
- Scratch-data check: 0 leftover probe orgs / notices / users across all prefixes.

## Session 17 — standing user actions + next session

- **USER ACTION (still open from session 16):** rotate the service-role key + DB password
  (SECURITY_CERTIFICATION §2 — committed copies remain valid until rotated).
- Phase 13 remainder (open control rows): XSS adversarial suite, rate limiting, MFA enablement,
  media re-encode, backups/restore drill (SECURITY_CERTIFICATION §1/§4).
- Wire `npm test` into CI to reach VERIFIED-tier evidence.
- Phase 05 remainder per ADR-014 consequence (3): full Firestore retirement (removing the signed-out
  mirror) is a later deletion step requiring explicit owner approval.

## Session 16 — what was completed (Phase 13 — hardening + security certification, COMPLETE)

- **Secret-leak incident (TESTING_STRATEGY §5 found it for real):** `scripts/run-probes.sh` carried the
  live service-role JWT + DB password, committed. Remediated in-file (env-injected now); **the user MUST
  rotate the service-role key and DB password in the Supabase dashboard — the old values remain valid
  and live in git history.** Full incident record + checklist: `SECURITY_CERTIFICATION.md` §2.
- **`scripts/security-scan.mjs` (new)** — automated secret-leak scan over tracked files; CRITICAL rules
  (service-role JWT, `sbp_` tokens, private keys, postgres URLs w/ passwords, `mineguard2024`, misplaced
  API keys) exit 1; baseline **0 CRITICAL / 16 HIGH** all classified-accepted (Firebase web key =
  public-by-design; probe passwords = throwaway users) — rationale inline + in SECURITY_CERTIFICATION §3/§5.
- **Durable suite:** `npm test` = scan + `scripts/run-all-probes.mjs` (all 10 probes, summary, CI-gateable
  exit). `package.json` scripts: `test`, `test:scan`, `test:probes`, `test:one`, `security:scan`.
- **Migration `…096_phase13_hardening.sql` (authored, NOT applied):** `site_create` enforces active-plan
  `max_sites` (null/no-subscription = unlimited back-compat; same 4-arg signature — no PGRST203 overload);
  `regulator_expire_due_grants()` audited idempotent sweep (national_regulatory_admin or scheduler;
  lapses captured by the existing grants audit trigger). Schema conventions verified pre-authoring.
- **`SECURITY_CERTIFICATION.md` (new)** — per-control DEMONSTRATED/ACCEPTED/OPEN table with artifacts,
  incident + rotation checklist, residual risks (legacy Firestore dual-read channel = highest-priority
  residual), gates to "production candidate". **`PRODUCTION_READINESS.md`** re-ticked with evidence.
- Note: an interrupted earlier attempt had pre-authored `run-all-probes.mjs` / `verify-phase13.mjs` /
  the `run-probes.sh` fix; reviewed + validated this session, scanner extended, `npm test` wired.

- **XSS render-path audit (SECURITY_CERTIFICATION §1 row 14 closed at the static layer):**
  new `scripts/xss-audit.mjs` — audits every dynamic interpolation reaching an HTML sink
  (63 sink statements across 8 client files); ~30 genuine escapes added in `admin.html` /
  `app.js` / `notices.js` (JSA task/worker/location/date, incident name/badge/location/status/
  severity/witnesses/description/deletedBy/deletedAt, contact name+number from localStorage,
  glossary filter text, photo src + onclick, notice filter fragment). Remaining interpolations
  allowlisted as reviewed-safe (static `data.js` fields, numeric chart bars, fixed-literal
  ternaries, enum label/color lookups) with the rationale recorded in the scanner. Wired into
  `npm test` (exit 1 on any unescaped interpolation). Dynamic adversarial-payload E2E remains open.
- **`npm test` composition**: security scan + XSS audit + all 10 live probes.

## Session 16 — verification evidence (recorded)

- Migration `…096` applied live (HTTP 201, fresh access token) via `scripts/apply-migration.mjs`.
- `scripts/verify-phase13.mjs`: **27/27 PASS, self-cleaning** — catalog (hardened site_create with
  unchanged signature; sweep RPC granted to authenticated), max_sites (cap denial names the plan, no
  partial row, upgrade re-allows, no-subscription back-compat), sweep (past-due lapsed, future/null
  untouched, idempotent, worker denied, lapses audited, expired-grant reads 0), scan self-check,
  Phase 12 RPC surface intact. Cleanup: 3 orgs / 4 users / 3 grants / 8 sites removed.
- Full regression all-PASS: 04, 06, 06-cascade, 07, 08 (after cleaning leftover probe orgs from a
  timed-out earlier run), 09, 10, 11 (48/48), 12 (31/31); security-scan exit 0 (0 CRITICAL / 16
  classified HIGH).

## Session 16 — standing user actions + next session

- **USER ACTION (dashboard-only, still open):** rotate the service-role key + DB password — the
  committed copies remain valid until rotated (SECURITY_CERTIFICATION §2). Consider rotating `sbp_`
  access tokens pasted in chat.
- Phase 13 remainder (open control rows): XSS adversarial suite, rate limiting, MFA enablement,
  media re-encode, backups/restore drill (SECURITY_CERTIFICATION §1/§4).
- Wire `npm test` into CI to move verification artifacts to VERIFIED-tier evidence.
- Per fixed phase order, next: Phase 05 cutover remainder (legacy Firestore channel) and/or the
  hardening remainder above — owner's call; both are recorded in IMPLEMENTATION_STATUS.

## Session 15 — what was completed (Phase 12 — SaaS + enterprise administration, COMPLETE)

Context: next phase per fixed phase order (Session 14 handoff). Phase 12 implements PROJECT_MASTER §10 SaaS modeling (plans/subscriptions in schema, billing deferred), closes the Phase 06 sites-write gap and Phase 11 grant-expiry gap, adds the platform administration layer, and moves national roll-ups server-side (non-negotiable #7).

- **Migration `…094`** (applied live): `plans` + `subscriptions` tables (modeling only); RPCs `site_create/update/remove`, `org_update_settings`, `org_update_subscription`, `bootstrap_first_platform_admin`, `platform_list_organizations`, `platform_update_organization_status`, 5-arg `regulator_issue_grant` (p_expires_at), `regulator_extend_grant`, `gov_national_overview()`; dedicated `trg_audit_subscriptions` trigger (21st audit trigger — shared `trg_audit_capture` deliberately NOT rewritten).
- **Fix migration `…095`** (probe-driven): grant-issue `returning id` → `into` variable (42601); audit capture corrected to real `audit_log.resource`/`resource_id` columns (was 42703 on every subscription change); `platform_list_organizations` → plpgsql with explicit P0001 gate (was HTTP 200 [] for non-platform callers); **dropped legacy 4-arg `regulator_issue_grant` overload** — PostgREST PGRST203 could not resolve partial named-argument calls with both overloads live, breaking ALL Phase 11 grant issuance.
- **Probe**: `scripts/verify-phase12.mjs` 31/31 PASS, self-cleaning (orgs/users/sites/grants/audit removed in finally).
- **Client**: `supabase-auth.js` Phase 12 wrappers (site CRUD, settings, plans/subscription, extend grant, platform trio, national overview; duplicate 4-arg issue wrapper removed); `org-admin.js` site create/rename/remove + settings/branding + plan card; `gov-admin.js` expiry field + Extend action + National Overview block.
- **Regression**: 06 PASS, 06-cascade PASS, 07 PASS (triggers 20→21), 08 ALL PASS, 09 PASS, 10 PASS, 11 **48/48** (recovered via overload drop).
- **Files changed**: `supabase/migrations/20260903000094_phase12_saas_enterprise.sql` (new), `supabase/migrations/20260903000095_phase12_fix_rpc_results.sql` (new), `scripts/verify-phase12.mjs` (new), `supabase-auth.js`, `org-admin.js`, `gov-admin.js`, `scripts/verify-phase07.mjs` + `verify-phase08.mjs` + `verify-phase09.mjs` (trigger counts 20→21).
- **Docs updated**: IMPLEMENTATION_STATUS (Phase 12 COMPLETE + evidence), SESSION_HANDOFF (this), CHANGELOG (session 15), PROJECT_MASTER, RLS_MATRIX, SECURITY_MODEL, DATABASE_ARCHITECTURE, RBAC_MODEL, GOVERNMENT_PLATFORM, ARCHITECTURE, supabase/README.

**Known limitations**: no billing provider (plan switches are administrative records, not revenue); no platform-admin UI (API-level only); `max_sites` not yet enforced by `site_create`; feature flags/usage not enforced; no expiry sweep job (reads already exclude expired grants).

**Next session**: **Phase 13** per fixed phase order — TESTING_STRATEGY rollout remains the standing open item; billing integration deferred until commercially required.

---

## Session 14 — what was completed (Phase 11 — Government regulatory command center, COMPLETE)

Context: next phase per PROJECT_MASTER §11 and Session 13's handoff. Phase 11 implements GOVERNMENT_PLATFORM.md: explicit, audited, grant-scoped regulator authorization (never blanket access) + regulator command-center surfaces.

- **State recovery**: migrations `…090`–`…093` were authored + applied in an interrupted prior session (verified live via `supabase migration list` + catalog checks); the probe existed but had never run to completion. No code was rewritten; the session completed verification, fixed defects, and shipped the client layer.
- **Database (already applied, verified live)**: `government_grants` table (explicit authorization records; partial unique index = one active grant per regulator org/user/target org/site); helpers (`auth_user_is_regulator_org_member`, `auth_user_is_regulator_user_in`, `current_user_active_government_grants`, `auth_user_has_regulator_grant_for`); RPCs (`bootstrap_first_regulator_admin`, `regulator_issue_grant`, `regulator_revoke_grant`, `regulator_update_user_role`); 16 grant-gated regulator SELECT policies across all safety-domain + hierarchy + audit tables; `government_grants` audit branch in `trg_audit_capture()` → 20 audit triggers; RLS on grants (regulator org reads own; target org w/ `audit_logs.view` reads touching grants; writes RPC-only).
- **Fix migrations already applied (documented by probes)**: …091 regulator-org permission evaluation (dead policies fixed) + one-shot bootstrap guard; …092 government role codes in `organization_members_role_check`; …093 grant RPC result capture (plpgsql 42601).
- **verify-phase11 probe fixed + run to completion (48/48 PASS, cleanup verified)**: probe parsing bugs fixed (scalar-uuid RPC returns a bare JSON string; void RPCs → 204; `organization_members` has no `id` column); two stale expectations corrected to match the implemented design (…091: users.view-holding regulators read target org members; …090: target org with `audit_logs.view` reads grants touching their org — transparency per GOVERNMENT_PLATFORM §5).
- **OPERATIONAL INCIDENT — seeded regulator org restored**: a prior interrupted run's cleanup had DELETED the seeded `liberia-regulator` organization (cleanup deletes `state.scratchRegOrgId`, which `onboarding()` re-points at the bootstrap-claimed org). Restored via upsert (new id `0eba2d84-f5af-4137-bd83-91d407376fa9`); the probe cleanup now refuses to delete the seeded regulator/AML orgs. Leftover scratch orgs/users from interrupted Phase 10/11 runs were cleaned; all probe artifacts verified removed afterwards (AML intact, seeded regulator intact with 0 active members — claimable).
- **Client layer (new this session)**: `gov-admin.js` — Government panel for regulator users: one-shot bootstrap CTA for brand-new government users; grant issue (target org UUID + optional site UUID + scope label; org-wide when site blank) / revoke (immediate); grants table (target, site, scope, regulator role, status, expiry); National Command Center — org/site drill-down over the union of the caller's active grants only (stat cards + recent incidents + recent emergency events; empty state states the isolation guarantee). `supabase-auth.js` wrappers (`bootstrapFirstRegulatorAdmin`, `regulatorIssueGrant`, `regulatorRevokeGrant`, `regulatorUpdateUserRole`, `fetchMyGovernmentGrants`, `fetchIssuedGrants`, `fetchIncidentsGrantScoped`, `fetchEmergencyGrantScoped`). `admin.html`: 🏛️ Government nav item + `panel-government` + gov CSS (anchored Node splices, the large-file convention; inline scripts re-parsed clean). `sw.js`: `gov-admin.js` precached. `auth-ui.js`: government role labels on the account chip. Preview serves all new assets (HTTP 200).
- **Regression**: verify-phase06 (PASS), verify-phase06-cascade (PASS), verify-phase07 (PASS — catalog counts updated to Phase 11 totals: incidents/evidence/witnesses policies 5/5/4; 20 audit triggers), verify-phase08 (ALL PASS — policies 5/5; 20 triggers), verify-phase09 (PASS — emergency policies events=4 acks=3 esc=3 resp=4 log=2; 20 triggers), verify-phase10 (all PASS, cleanup verified).

## Session 14 — verification evidence (recorded)

- `scripts/verify-phase11.mjs` on `vuniwebbrvpgxscdsfei`: 48/48 PASS, cleanup verified (details in IMPLEMENTATION_STATUS §Phase 11).
- Regression suites all-PASS: verify-phase06, verify-phase06-cascade, verify-phase07 (counts updated), verify-phase08 (counts updated), verify-phase09 (counts updated), verify-phase10.
- `node --check` clean on gov-admin.js, supabase-auth.js, auth-ui.js, sw.js, verify-phase11.mjs; admin.html inline scripts parse clean (3 scripts, 0 errors); preview serves /, /admin.html, /gov-admin.js, /supabase-auth.js, /org-admin.js, /sw.js → 200.

## Session 14 — files changed

- New: `gov-admin.js`
- Edited: `supabase-auth.js` (Phase 11 wrappers), `admin.html` (nav + panel + CSS + script include + showPanel/refreshPanel wiring), `sw.js` (precache gov-admin.js), `auth-ui.js` (government role labels), `scripts/verify-phase11.mjs` (probe fixes: error detail, scalar-RPC parsing, 204 acceptance, org-members expectations, seeded-org cleanup guard), `scripts/verify-phase07.mjs` + `scripts/verify-phase08.mjs` + `scripts/verify-phase09.mjs` (Phase 11 catalog-count updates)
- Database: no NEW migrations this session (…090–…093 were applied previously); seeded `liberia-regulator` org restored; probe artifacts cleaned.
- Docs: IMPLEMENTATION_STATUS (Phase 11 COMPLETE + evidence), SESSION_HANDOFF (session 14, this), CHANGELOG (session 14), PROJECT_MASTER (phase table row 11), GOVERNMENT_PLATFORM, RLS_MATRIX, SECURITY_MODEL, DATABASE_ARCHITECTURE, RBAC_MODEL, ARCHITECTURE, supabase/README.

## Session 14 — known limitations / warnings for next session

- Status is COMPLETE, not VERIFIED-tier (recorded live probes, no CI suite — TESTING_STRATEGY rollout remains open).
- Grant expiry exists in schema/helpers but the government panel does not yet set expiry dates (Phase 12 administration surface). Scope labels are free text (not authority — permissions resolve from the grantee's regulator-org role).
- Command-center aggregates are client-side over grant-scoped rows (50 most recent); national roll-ups should move to authorized server-side aggregate views in Phase 12 (non-negotiable #7: documented formulas only).
- The one-shot regulator bootstrap on `liberia-regulator` is still available (0 active members) — the platform owner should claim it deliberately, as with the AML owner claim.
- Auth config reminder unchanged: `site_url` is still `http://localhost:3000`; set it to the real app origin before inviting real users.
- Worker data flows remain on the legacy anonymous Firebase channel + Phase 10 engine for signed-in users (dual-read window; Phase 05 remainder).
- Next session: **Phase 12 — SaaS + enterprise administration** (per fixed phase order).

## Session 13 — what was completed (Phase 10 — Offline-first synchronization, COMPLETE)

Context: next phase per PROJECT_MASTER §11 and Session 12's handoff. Phase 10 is the client-side offline-first layer (no new migrations — the Phase 07–09 tables already carry `client_id` unique idempotency keys), implementing OFFLINE_SYNC_ARCHITECTURE §2.1–§2.8.

- **New `offline-store.js`** — IndexedDB database replacing localStorage-as-database: `outbox` (mutations with priority/state/attempts/next_attempt_at), `records` (per-record cache keyed by client_id with sync_state), `attachments` (pending blobs + metadata), `kv` (settings only). Idempotent non-destructive legacy migration (`mineguard_incidents`/`jsas`/`notices`/`sos_state` → records with stable clientId backfill; legacy keys left for the Firebase readers). UMD: `window.MG_STORE`, Node probes `require()` it.
- **New `sync-engine.js`** — queue engine: FIFO drain with EMERGENCY priority first; exponential backoff (2s→60s) + 8-attempt cap; `client_id` idempotency (dup POST → 409 = already-synced; local dedupe on (entity, client_id, op)); conflict detection (stale local updated_at vs newer server → `conflict` state, no overwrite); per-record sync states; attachment sync (blob → `incident-evidence` storage X-Upsert → `incident_evidence` row); connectivity heartbeat + reconnect drain; legacy→Phase 07–09 payload adapters (incident/jsa/SOS). UMD: `window.MG_SYNC`.
- **Wiring** — `index.html` + `admin.html`: two script tags + shared bootstrap in `<head>` (store, migration, engine init, connectivity wiring, heartbeat, mg-auth-change context re-resolution, SW drain messaging). `sw.js`: precache both files, `mineguard-sync-drain` background sync, `sync-drain` message fan-out. `firebase.js`: `_mgSyncEnqueue()` hook in `saveIncidentToCloud`/`saveJSAToCloud`/`saveEmergencySOSCloud` — signed-in Supabase sessions also enqueue through the engine (non-blocking; Firestore legacy mirror + signed-out devices unchanged).
- **Applied `scripts/verify-phase10.mjs`** — self-cleaning live probe running the REAL engine (in-memory store + real PostgREST transport) against the live project: **all 14 checks PASS, cleanup verified** — queueing/drain, emergency-first ordering (E > A > B > C FIFO by server created_at), RLS reporter integrity (reported_by_user_id = actor), idempotency (dedupe + exactly 1 server row), backoff/retry (failure → attempts=1/pending/future next_attempt_at; retry lands JSA, no duplicate), conflict (stale update → conflict state, newer server row preserved), attachments (blob → storage object + evidence row), tenant isolation both directions, cleanup verified.
- **Bug found + fixed during probe iteration**: `sync-engine.js` factory used `root` (UMD wrapper parameter) without a local binding → `ReferenceError` in browsers (auto-drain would never fire); rebound `root` inside the factory. Also hardened `drain()` so transport throws increment attempts/backoff + mark the batch network-down (previously a throw stranded the mutation in `syncing`).
- **Regression**: `verify-phase06.mjs` (51), `verify-phase07.mjs` (62), `verify-phase08.mjs` (41), `verify-phase09.mjs` (56) all still PASS (Phase 10 adds no tables/triggers — counts unchanged).

## Session 13 — verification evidence (recorded)

- `scripts/verify-phase10.mjs` on `vuniwebbrvpgxscdsfei`: all 14 checks PASS, cleanup verified (details in IMPLEMENTATION_STATUS §Phase 10).
- Regression suites all-PASS: verify-phase06 (51 checks), verify-phase07 (62), verify-phase08 (41), verify-phase09 (56).

## Session 13 — files changed

- New: `offline-store.js`, `sync-engine.js`, `scripts/verify-phase10.mjs`
- Edited: `index.html` + `admin.html` (sync script tags + bootstrap block in head), `sw.js` (precache + background sync + drain messaging), `firebase.js` (`_mgSyncEnqueue` hook in incident/JSA/SOS save flows), `sync-engine.js` (root binding + drain catch hardening)
- Database: none (client-side phase; Phase 07–09 client_id idempotency keys are the server side)
- Docs: IMPLEMENTATION_STATUS (Phase 10 COMPLETE + evidence), SESSION_HANDOFF (session 13), CHANGELOG (session 13), PROJECT_MASTER (phase table row 10), OFFLINE_SYNC_ARCHITECTURE (target → live), ARCHITECTURE (offline sync section), MIGRATION_PLAN (§7 gate), supabase/README (status + verify scripts).

## Session 13 — known limitations / warnings for next session

- Status is COMPLETE, not VERIFIED-tier (recorded live probes, no CI suite — TESTING_STRATEGY rollout remains open).
- The engine only enqueues when a Supabase session exists AND the user has active org memberships (RLS-filtered context resolution). Users without memberships keep the legacy Firestore-only path — a warning is logged, nothing is lost.
- Attachments sync from the engine assumes the app stores photo blobs via the attachments store (`MG_STORE.attachmentPut`); the current app embeds compressed base64 photos in the incident payload, so evidence uploads are engine-verified (probe) but not yet wired to the app's photo picker — that is app-cutover work (Phase 05 remainder / Phase 13).
- Background sync (`mineguard-sync-drain`) is best-effort: real push/periodicsync delivery needs a push provider (Phase 13). The 30s heartbeat + connectivity events cover retries in the foreground.
- Next session: **Phase 11 — Government regulatory command center** (per fixed phase order).

## Session 12 — known limitations / warnings for next session

- Status is COMPLETE, not VERIFIED-tier (recorded live probes, no CI suite — TESTING_STRATEGY rollout remains open).
- Activation is intentionally restricted to `emergency.activate` holders (owner/admin/safety_manager/safety_officer/site_manager bundles) — supervisors/workers can acknowledge but not raise (matches the legacy admin-console-only SOS activation; revisit in Phase 13 hardening if worker-initiated SOS is required).
- Client UI for emergency/SOS remains on the legacy anonymous Firebase channel (dual-read window); wiring the backend lifecycle to the app is Phase 05 cutover / Phase 10 offline-sync work.
- `emergency_log` rows are trigger-written only (append-only stream); `source='rpc'/'service'` audit writers + government/platform readers land with Phases 11–12.
- Next session: **Phase 10 — Offline-first synchronization** (per fixed phase order).

## Session 12 — what was completed (Phase 09 — Emergency response + SOS, COMPLETE)

Context: next phase per PROJECT_MASTER §11 and Session 11's handoff. Phase 09 creates the emergency/SOS safety-domain tables using the Phase 06 RLS primitives + Phase 07/08 audit trigger pattern, and satisfies EMERGENCY_RESPONSE_ARCHITECTURE §2 (lifecycle, per-user acks, escalation, responder disposition, append-only log) + PROJECT_MASTER §12.4 (safety-critical honesty, duplicate prevention).

- **Applied migration `…080`** — `emergency_events` / `emergency_acknowledgements` / `emergency_escalations` / `emergency_responders` / `emergency_log` tables: org+site scoped; Phase 05 mapper emergency payload shape is a direct column subset (client_id/category/message/contact_number/assembly_point/activated_by_text/ended_by_text/started_at/deactivated_at/duration_seconds/status/notified_workers_legacy/created_at/deleted — import-ready); lifecycle ACTIVATED→ACKNOWLEDGED→RESPONDING→CONTAINED→RESOLVED→CLOSED enforced forward-only in `trg_emergency_events_guard`; activated_by forced to auth.uid() on INSERT and pinned immutable on UPDATE; resolved_by immutable; legacy deactivation (ACTIVATED→RESOLVED with deactivated_at) records the resolver server-side; `trg_emergency_log_capture` writes the append-only emergency_log stream on activation + every transition; `trg_emergency_child_guard` mirrors org/site from the event + pins acked_by. RLS per RLS_MATRIX §1.2: org-wide roles (owner/admin/safety_manager/safety_officer/site_manager) view/insert; supervisor site-scope view; worker/contractor site-notice-scope view + own ack (unique(event,user)); resolve/close gated on emergency.resolve; escalation/responder = response-chain gate. 14 policies; 5 new audit triggers (19 total); emergency_log SELECT-only grant.
- **Applied fix migrations** (probe-driven): `…081` (child authz accepts site-scope acknowledge for site-only supervisors), `…082` (dedicated escalation gate — workers ack-only per matrix), `…083` (child guard 42703 — responders have no created_by column), `…084` (responder gate = response-chain; unused child helper dropped).
- **Applied `scripts/verify-phase09.mjs`** — self-cleaning live probe: **all checks PASS, cleanup verified** (~60 checks): catalog (5 tables RLS, 14 policies, 19 audit triggers); INSERT matrix (owner + site-only site_manager activate; supervisor/worker denied per Phase 03 bundles; spoofed activated_by rejected; cross-site/cross-org denied; activated_by forced); SELECT matrix (org pool, site-only supervisor site A only, site-A worker site_notice_scope, site-B worker 0, outsider/anon 0); lifecycle (forward-only, backward rejected, resolved_by immutable, resolver recorded, CLOSED path); acks (201 + pinned, duplicate 409, spoof denied, closed-event denied, UPDATE no-op); escalation/responder gating (supervisor escalates 201, worker denied, safety_manager dispatches + disposition update, worker denied); emergency_log append-only (trigger stream present, client INSERT denied); two-org isolation; audit integrity (insert/transition/ack/log captured with actor, forged INSERT rejected, message never mirrored); cleanup verified.
- **Regression**: `verify-phase06.mjs` + `verify-phase06-cascade.mjs` + `verify-phase07.mjs` + `verify-phase08.mjs` all still PASS (no regressions; Phase 07/08 trigger-count assertions updated 14→19).

## Session 12 — verification evidence (recorded)

- `scripts/verify-phase09.mjs` on `vuniwebbrvpgxscdsfei`: all checks PASS, cleanup verified (details in IMPLEMENTATION_STATUS §Phase 09).
- Regression suites all-PASS: verify-phase06 (cleanup verified), verify-phase06-cascade, verify-phase07 (cleanup verified), verify-phase08.

## Session 12 — files changed

- New: `supabase/migrations/20260903000080_phase09_emergency_sos.sql`, `…081_phase09_fix_child_authz.sql`, `…082_phase09_fix_escalation_gate.sql`, `…083_phase09_fix_child_guard.sql`, `…084_phase09_fix_responder_gate.sql`, `scripts/verify-phase09.mjs`
- Edited: `scripts/verify-phase07.mjs` + `scripts/verify-phase08.mjs` (audit-trigger count 14→19)
- Database: all 5 migrations applied to `vuniwebbrvpgxscdsfei`; 5 emergency tables live with RLS + lifecycle guards + audit triggers; migration history consistent.
- Docs: IMPLEMENTATION_STATUS (Phase 09 COMPLETE + evidence), SESSION_HANDOFF (session 12), CHANGELOG (session 12), PROJECT_MASTER (phase table row 09), RLS_MATRIX (§1.2 emergency live), SECURITY_MODEL (§2.4/§2.6 emergency triggers + lifecycle), DATABASE_ARCHITECTURE (§2.4 emergency concrete, §2.5 19 triggers), EMERGENCY_RESPONSE_ARCHITECTURE (target → live), MINING_DOMAIN_MODEL (emergency concrete), MIGRATION_PLAN (§7 gate update), supabase/README (status + layout).

## Session 11 — what was completed (Phase 08 — JSA + inspection + corrective actions, COMPLETE)

Context: next phase per PROJECT_MASTER §11 and Session 10's handoff. Phase 08 creates the JSA + inspection + CAPA safety-domain tables using the Phase 06 RLS primitives + Phase 07 audit trigger pattern.

- **Applied migration `…070`** — `jsas` / `jsa_steps` tables (org+site scoped; approval flow; `site_notice_scope`; soft-delete; client_id idempotency) + RLS policies + 2 audit triggers.
- **Applied migration `…071`** — `inspections` / `corrective_actions` tables (org+site scoped; inspection_type/status/priority enums; polymorphic source linkage; soft-delete; client_id idempotency) + RLS policies with SECURITY DEFINER helpers + 2 audit triggers → 14 total.
- **Applied fix migration `…072`** — inspection SELECT restricted (workers can't see inspections); CAPA SELECT allows site-only members via `auth_user_has_site_access`.
- **Applied fix migration `…073`** — added `inspections.delete` + `corrective_actions.delete` permissions to catalog; fixed `auth_user_can_update_capa` for site-only assignees.
- **Applied `scripts/verify-phase08.mjs`** — self-cleaning live probe: **all checks PASS, cleanup verified**. Covered: catalog (4 tables, 8 policies, 14 audit triggers), full INSERT/SELECT/UPDATE/DELETE matrix across admin, safety_manager, site-only supervisor, worker, outsider; data-change verification; cross-tenant isolation; audit actor integrity.
- **Regression**: `verify-phase06.mjs` + `verify-phase06-cascade.mjs` + `verify-phase07.mjs` all still PASS (no regressions; Phase 07 trigger count updated from 10→14).

## Session 10 — what was completed (Phase 07 — Incident + evidence management, COMPLETE)

Context: next phase per PROJECT_MASTER §11 and Session 9's handoff. Phase 07 creates the
safety-domain incident tables + storage-backed evidence + their RLS using the Phase 06
primitives, which also unblocks Phase 05's own gate (target safety-domain tables now exist
for incidents).

- **Applied migration `…060`** (`supabase db push --linked`) — `incidents` / `incident_evidence` /
  `incident_witnesses` (org-scoped; Phase 05 mapper payload shape is a direct column subset;
  status lifecycle DRAFT…CLOSED; soft-delete; `site_notice_scope` broadcast flag), scope triggers
  (reporter forced to auth.uid() on INSERT and pinned immutable on UPDATE; evidence/witness
  org/site mirrored from the incident server-side; site/department org-consistency), RLS_MATRIX
  §1.2 helpers + 11 policies (org-wide roles owner/admin/safety_manager/safety_officer;
  site roles site_manager/supervisor; worker own-only; site_notice_scope; hard-delete
  owner/admin/safety_manager only), and `trg_audit_capture()` extended with the three
  safety-domain branches (incidents/incident_evidence/incident_witnesses — curated metadata;
  body text / storage paths / statements never mirrored into audit; org-scope nulling on
  cascade preserved) + 3 audit triggers (10 total).
- **Applied migration `…061`** — private `incident-evidence` bucket (10 MB/object, image/pdf/video
  allowlist) + 4 `storage.objects` policies that resolve the incident from path segment 6
  (incident UUID OR legacy client_id) through the incident's own RLS — knowing a path grants
  nothing.
- **Applied `scripts/verify-phase07.mjs`** — self-cleaning live probe: **all checks PASS,
  cleanup verified**. Covered: catalog (3 tables, 11 policies, 10 audit triggers, bucket + 4
  storage policies), full incidents INSERT/SELECT/UPDATE/DELETE matrix across owner,
  safety_officer, site-only supervisor, site-only worker, org worker, outsider, anon;
  reporter spoof rejection; cross-site + cross-org insert denial; site_notice_scope broadcast
  scoping (site-A worker reads, site-B worker does not); evidence/witness scope (own vs
  another's denied); storage upload/download allowed + blocked paths; two-org tenant isolation
  (both directions); audit actor integrity + body-text non-leak + append-only. `node --check` clean.
- **Regression**: `verify-phase06.mjs` + `verify-phase06-cascade.mjs` both still all-PASS
  (no regressions).
- **PostgREST note**: `Prefer: return=representation` on INSERT causes PostgREST to re-check
  the SELECT policy on the RETURNING row and returns 42501 even when the INSERT is allowed
  (empirically verified; recorded as a known limitation, not an authz bug). Client code should
  POST without Prefer and re-select.

## Session 10 — verification evidence (recorded)

- `scripts/verify-phase07.mjs` on `vuniwebbrvpgxscdsfei`: all checks PASS, cleanup verified
  (details in IMPLEMENTATION_STATUS §Phase 07).
- Phase 06 regression: `scripts/verify-phase06.mjs` all PASS, cleanup verified.
- Phase 06 cascade regression: `scripts/verify-phase06-cascade.mjs` all PASS.

## Session 10 — files changed

- New: `supabase/migrations/20260903000060_phase07_incidents.sql`,
  `supabase/migrations/20260903000061_phase07_storage_evidence.sql`,
  `scripts/verify-phase07.mjs`
- Database: both migrations applied to `vuniwebbrvpgxscdsfei`; incident/evidence/witnesses
  tables live; incident-evidence storage bucket + policies live.
- Docs: IMPLEMENTATION_STATUS (Phase 07 COMPLETE + evidence), SESSION_HANDOFF (session 10),
  CHANGELOG (session 10), PROJECT_MASTER (phase table row 07), RLS_MATRIX (§1.2 incidents
  live), SECURITY_MODEL (§2.4 storage live, §2.6 safety-domain triggers added),
  DATABASE_ARCHITECTURE (§2.3 incident tables concrete, §2.5 incident triggers),
  MINING_DOMAIN_MODEL (incidents concrete), MIGRATION_PLAN (§7 gate update),
  supabase/README (status + layout).

## Session 10 — known limitations / warnings for next session

- Status is COMPLETE, not VERIFIED-tier (recorded live probes, no CI suite).
- Client UI for incidents is not wired to Supabase — the legacy anonymous Firebase channel
  remains live (dual-read window). Client cutover is Phase 05 import / Phase 10 offline-sync.
- Incident INSERT via direct RLS (not RPC) is used in this phase for direct matrix testing;
  production write path is SECURITY DEFINER RPCs (Phase 08/09/12).
- Next session: **Phase 08 — JSA + inspection + corrective actions** (per fixed phase order,
  creates the remaining safety-domain tables + RLS using the same Phase 06/07 primitives).

## Session 9 — what was completed (Phase 06 — RLS + security enforcement)

Context: Phase 06 is the next phase per PROJECT_MASTER §11 and was recommended by Session 8's
handoff. Phase 06 code (migrations `…050`–`…052`, `scripts/verify-phase06.mjs`, orphan-cleanup and
membership-repro diagnostics) existed from a prior interrupted turn but was NOT recorded in the
docs. This session established the true state, closed a real gap the docs never knew about, and
recorded everything with evidence.

- **State recovery**: `verify-phase06.mjs` re-run against the live project — every check PASS,
  cleanup verified (50+ checks: site-scope SELECT matrix, least-privilege worker roster,
  org UPDATE gate by effect incl. cross-tenant no-op on tenant #1, audit actor integrity /
  append-only / token non-leak, escalation 403s). Migrations 50–52 were confirmed live but NOT
  recorded in `supabase_migrations.schema_migrations` (applied out-of-band earlier) — recorded
  them so `supabase db push` only applies genuinely pending migrations.
- **New regression probe** `scripts/verify-phase06-cascade.mjs`: single cascade DELETE of an org
  with site + org member + site member + unit + worker + invite. Found a REAL Phase 06 gap:
  `sites` had no audit trigger (the Phase 06 set covered 6 tables but omitted `sites`), so
  site create/update/delete was never audited. Also validated the 51/52 org-delete fix end to
  end (cascade succeeds; ALL 7 resources retained as platform-scope audit rows, org_id null).
  Initial probe FAILs were probe bugs (SQL operator precedence; org_invites column is `token`,
  not `token_hash`), not database bugs — fixed and re-run to all-PASS.
- **Fix migration** `20260903000053_phase06_add_sites_audit.sql` (NEW): `sites` branch in
  `trg_audit_capture()` (name/location/county/status, org-scope nulling on cascade) +
  `trg_audit_sites` trigger. Pushed via CLI; `db push` now applies only migration 53.
- **Re-verified after the fix**: `verify-phase06-cascade.mjs` all PASS (7/7 resources audited
  with correct semantics); `verify-phase06.mjs` remains all-PASS (migration 53 only ADDS an
  audit trigger; no authorization surface changed).

## Session 9 — verification evidence (recorded)

- `scripts/verify-phase06.mjs` on `vuniwebbrvpgxscdsfei`: all checks PASS, cleanup verified
  (details in IMPLEMENTATION_STATUS §Phase 06 — catalog, org-update gate by effect, site-scope
  matrix incl. no-transitive-site-B + worker roster 0 rows, cross-tenant 0 rows of AML, audit
  actor=uid + append-only 403s + token non-leak, escalation 403s).
- `scripts/verify-phase06-cascade.mjs` on `vuniwebbrvpgxscdsfei`: all checks PASS, cleanup
  verified — single org DELETE with 7 dependent-row families succeeds; dependent rows
  cascade-removed; audit rows written for organizations + sites + organization_members +
  site_members + organizational_units + workers + org_invites, every row
  `organization_id` null (platform-scope retention), source='trigger', action '*.delete',
  actor null under service-role (correct by design).
- Catalog check: audit triggers now on ALL 7 tenant-management tables incl. `sites`
  (trg_audit_sites enabled).
- `supabase db push --linked` applies only `20260903000053` (history consistent).
- `node --check` clean on `verify-phase06-cascade.mjs` and `verify-phase06.mjs`.
- Phase 03/04 suites (verify-rbac.mjs / verify-phase04.mjs) were green before this session and
  migration 53 touches no authorization surface — no re-run performed this session (not
  claimed).

## Session 9 — files changed

- New: `supabase/migrations/20260903000053_phase06_add_sites_audit.sql`,
  `scripts/verify-phase06-cascade.mjs`
- Database: migration …053 applied to `vuniwebbrvpgxscdsfei`; `schema_migrations` history
  repaired (…050–…052 recorded as applied).
- Docs: IMPLEMENTATION_STATUS (Phase 06 COMPLETE + evidence), SESSION_HANDOFF (session 9),
  CHANGELOG (session 9), PROJECT_MASTER (phase table row 06), RLS_MATRIX / SECURITY_MODEL /
  DATABASE_ARCHITECTURE / RBAC_MODEL (Phase 06 live state), supabase/README (status + layout).

## Session 9 — known limitations / warnings for next session

- Status is COMPLETE, not VERIFIED-tier (recorded live probes, no CI suite — TESTING_STRATEGY
  rollout still open).
- Phase 06 covered Phases 01–04 tables + audit foundation ONLY. Safety-domain tables and their
  RLS (RLS_MATRIX §1.2) land with Phases 07–09; the legacy anonymous Firebase worker-data
  channel remains live (dual-read window) until those gates close.
- `sites` INSERT/UPDATE/DELETE for end users remain service-role-only (no RPC/self-service yet;
  organizations INSERT is platform-level, Phase 12).
- Next session options: (a) **Phase 07 — Incident + evidence management** (per fixed phase
  order — creates the safety-domain tables + storage-backed evidence + their RLS using the
  Phase 06 primitives, which also unblocks Phase 05's own gate (b)); or (b) continue Phase 05
  only after the user supplies the Firestore console export/backup (ADR-003) AND the org owner
  answers `supabase/migration-prep/review-lists.json` via `overrides.json`. Recommended per
  phase docs: Phase 07 next.
- `site_url` auth-config reminder unchanged (still `http://localhost:3000`; set to the real app
  origin before inviting real users).

## Session 8 — what was completed (Phase 05 — Database migration prep)

Context: Phase 05 is the next phase per PROJECT_MASTER §11. Full import/cutover is gated on (a) the
durable user-owned Firestore export (ADR-003, still owed), (b) target safety-domain tables + RLS that
Phases 06–09 create, (c) org-owner review sign-off, (d) MIGRATION_PLAN §7 gate order. This session
completed every unblocked §4.1/§4.3 item: measured volume + field census + validation baseline.

- **Inventory** — `scripts/phase05-inventory.mjs` authored last session, fixed + extended this session
  (vocab-bucket init bug; photo payloads now RETAINED — strip threshold 4096 → 8 MB — so mapping can
  hash/type/export them). Ran read-only against the live `aml-mineguard` Firestore over the same
  anonymous REST channel the shipped app uses. Snapshot under `supabase/legacy-inventory/` (gitignored).
  Volumes: incidents 4 (2 del; 19 fields), jsas 4 (3 del; 13 fields), notices 12 (10 del; 16 fields),
  audit_log 64 (6 fields), emergency_sos 7 (20 fields); 100% createdAt coverage; photos: 4 docs carry
  `photos` (2 empty arrays), 5 embedded data-URL JPEGs ≈ 881 KB decoded / ~1.17 MB base64.
- **Mapping** — `scripts/phase05-map.mjs` (new): pure/offline/deterministic/restartable mapper under
  tenant #1 (`arcelormittal-liberia`) + seeded-site resolution (Nimba Mine → nimba-mine, Port
  Operations → port-operations; everything else flagged, never silently guessed). Outputs under
  `supabase/migration-prep/` (gitignored): `payloads/{incidents,jsas,notices,emergency_events,
  audit_log}.ndjson` (91 rows = 91 source docs; `client_id` idempotency keys; soft-delete preserved;
  legacy timestamps kept; legacy text kept in `*_text` fields where the target has no equivalent),
  `photos.manifest.ndjson` (Phase 07 storage upload queue), `mapping-report.json` (validation
  baseline), `review-lists.json` (29 items / 4 groups + 7 proposed workers + 2 proposed departments).
  Human decisions are recorded in `overrides.json` (gitignored dir) and re-runs are deterministic
  (payloads byte-identical across two runs, verified by sha256 diff).

## Session 8 — verification evidence (recorded)

- Inventory run: all 5 collections PASS (counts above; no FAIL).
- Mapping run: all PASS — source counts equal inventory counts on every collection; required-field
  violations 0; unique client ids per family; photos 5 rows / 881 KB; audit orphans 50
  (delete 25 / purge 16 / restore 9 — rows referencing hard-purged legacy docs, expected).
- Determinism: `sha256sum` of all payload files + photos manifest identical across consecutive runs.
- `node --check` clean on phase05-inventory.mjs and phase05-map.mjs.
- Spot checks: incident rows keep reporter name/badge/dept, status map open→SUBMITTED /
  resolved→RESOLVED, epoch createdAt converted to ISO, `deleted` preserved; emergency events 7 with
  status ACTIVATED/CLOSED from active/endedBy, site nimba-mine resolved; photos manifest rows have
  mime image/jpeg + sha256 + org-scoped storage keys (sites "unassigned" pending review-lists
  answers — locations don't match seeded sites).

## Session 8 — files changed

- New: `scripts/phase05-map.mjs`
- Edited: `scripts/phase05-inventory.mjs` (vocab bug + photo retention), `.gitignore`
  (legacy-inventory + migration-prep output = personal data, gitignored)
- Docs: IMPLEMENTATION_STATUS (Phase 05 PARTIALLY_COMPLETE + evidence), SESSION_HANDOFF (session 8),
  CHANGELOG (session 8), DECISIONS (ADR-012), MIGRATION_PLAN (measured volumes §1 + execution log §8),
  PROJECT_MASTER (phase table row 05), supabase/README (toolkit + status)

## Session 8 — known limitations / warnings for next session

- **Phase 05 is PARTIALLY_COMPLETE, not COMPLETE/VERIFIED**: NOTHING was written to the target
  database; the apply step cannot run yet (no target tables until Phases 06–09; no durable export).
- Next session options: (a) Phase 06 — RLS + security enforcement (full RLS_MATRIX per-table policies
  over Phases 01–04 tables using the live authz helpers) — unblocks Phase 05's own gate (MIGRATION_PLAN
  §7); or (b) continue Phase 05 only after the user supplies the Firestore console export/backup
  (ADR-003) AND the org owner answers `supabase/migration-prep/review-lists.json` via `overrides.json`.
  Recommended order per phase docs: Phase 06 next.
- Deliverables are gitignored but NOT encrypted — do not push them; they contain worker names, badges,
  incident descriptions and photos.
- `site_url` auth-config reminder unchanged (still `http://localhost:3000`; set to the real app origin
  before inviting real users).

## Session 7 — what was completed (Phase 04 — Mining company + site hierarchy)

- Migration `supabase/migrations/20260903000040_phase04_site_hierarchy.sql` authored + pushed via CLI
  to `vuniwebbrvpgxscdsfei`, then an appended fix migration
  `20260903000041_phase04_fixes.sql` (see findings below):
  - `organizational_units` (departments/teams/work zones, parent_id + unit_type, org/site scope
    triggers), `site_members` (site-scoped roles reusing the 9 org role codes), `workers`
    (worker registry with optional auth.users link), `org_invites` (email invites; one-time
    sha256 token; 7-day expiry; lifecycle pending/accepted/revoked/expired).
  - Site-scoped authz helpers: `auth_user_site_effective_role`, `auth_user_has_site_access`,
    `auth_user_has_site_permission` (max(org role, site role)); `auth_user_has_permission` /
    `auth_user_permissions` upgraded so an ACTIVE ORG MEMBER's site roles widen scope — but a
    site-only user (no org membership) never gains org scope from a site row.
  - Permission catalog +2 codes (`organizational_units.create/.update`) with bundles
    (owner/admin/safety_manager create+update; safety_officer/site_manager update).
  - SECURITY DEFINER RPCs (each re-checks authorization): org member add/re-role/remove
    (owner-protected; removal withdraws site memberships), invite send/accept/revoke
    (email-match on accept), site member assign/remove (owner/admin or that site's
    site_manager), unit create/update/remove, worker add/update/remove,
    `org_list_members` (members + emails for org members).
  - RLS on all four tables (org-membership SELECT; own-row for site_members); writes
    default-deny (RPC-only); PUBLIC EXECUTE revoked from all new functions.
- Client: `supabase-auth.js` — generic `rpc()` + PostgREST GET helpers + Phase 04 wrappers;
  `org-admin.js` (new) renders the Organization panel; `admin.html` — 🏢 Organization nav item +
  panel (members, invites with shareable token, sites/units tree, worker registry); `sw.js`
  precache updated. All served by the preview (HTTP 200 checks).

## Session 7 — verification evidence (recorded)

- `scripts/verify-phase04.mjs` live probe on `vuniwebbrvpgxscdsfei`: **58/58 PASS**, cleanup
  verified (scratch org + 6 probe users removed; AML tenant #1 untouched):
  - site-scoped resolution (siteMgr org-member widening; site-only user site-scope only,
    no transitive site B; plain worker none);
  - org-admin gates (outsider/site-only/worker denied; owner protected from remove/re-role;
    no second owner; remove withdraws site memberships; re-add reactivates);
  - invite lifecycle (token; pending re-invite upsert; email-match accept; duplicate member /
    duplicate accept / revoked accept denied);
  - hierarchy + workers (units incl. cross-site parent trigger rejection; worker add/update/
    remove; permission denials);
  - RLS/isolation (outsider + anon 0 rows on all four tables; org members read org rows;
    site-only reads own site_members row only).
- `scripts/verify-rbac.mjs` re-run after the `auth_user_has_permission` upgrade: all PASS
  (Phase 03 semantics preserved; owner bundle now 62 codes incl. the 2 new units codes).
- `scripts/verify-supabase.mjs`: no FAIL (anon RLS checks).
- `node --check` clean on supabase-auth.js, org-admin.js, verify-rbac/verify-supabase/
  verify-phase04; admin.html inline scripts parse clean; preview serves admin.html (with
  Organization markers), org-admin.js, supabase-auth.js (200).

## Session 7 — files changed

- New: `supabase/migrations/20260903000040_phase04_site_hierarchy.sql`,
  `20260903000041_phase04_fixes.sql`, `org-admin.js`, `scripts/verify-phase04.mjs`
- Edited: `supabase-auth.js` (Phase 04 wrappers), `admin.html` (nav + panel + script include +
  showPanel/refreshPanel wiring — via anchored Node splices; str_replace cannot reach deep
  content in large HTML files), `sw.js` (precache), `scripts/verify-supabase.mjs` +
  `scripts/verify-rbac.mjs` (config.js public fallback for URL/anon key)
- Docs: IMPLEMENTATION_STATUS (Phase 04 COMPLETE + evidence), SESSION_HANDOFF (session 7),
  CHANGELOG (session 7), DECISIONS (ADR-011), DATABASE_ARCHITECTURE, RLS_MATRIX, RBAC_MODEL,
  MINING_DOMAIN_MODEL, PROJECT_MASTER (phase table), supabase/README (status + layout)

## Session 7 — known limitations / warnings for next session

- Status is COMPLETE, not VERIFIED-tier (recorded live probes, not a CI suite).
- Phase 05 next: Firestore → Supabase data migration. User still owes the `aml-mineguard`
  export/backup (ADR-003) before Phase 05 can start; MIGRATION_PLAN §4 ordering gates it.
  Tenant #1 (AML) departments/teams will be seeded from legacy text during Phase 05 mapping.
- Site-ONLY members cannot SELECT org-scope rows yet (units/workers RLS = org membership);
  Phase 06 wires the per-table matrix using the site-scoped helpers. Site assignment UI in the
  Organization panel is read-only for org members in this phase (assignment RPCs exist and are
  verified; the panel shows site roles on the member rows).
- Invite delivery is in-app token sharing until a mail provider lands (Phase 09/13);
  `org_accept_invite` requires the invitee to use the invited email.
- Auth config reminder (unchanged): `site_url` is still `http://localhost:3000`; set it to the
  real app origin before inviting real users.

## Session 6 — what was completed (Phase 03 — RBAC + permissions)

- Migration `supabase/migrations/20260903000030_phase03_rbac.sql` authored + pushed via CLI
  (`supabase db push --linked`, Management API path) to `vuniwebbrvpgxscdsfei`:
  - `permissions` (60 codes / 19 domains), `roles` (16 system roles across platform/government/
    organization scopes; org role codes = `organization_members.role` values), `role_permissions`
    (seeded bundles per RBAC_MODEL §3).
  - `organization_members.role` check expanded to owner/admin/safety_manager/safety_officer/
    site_manager/supervisor/worker/contractor/member (backwards-compatible).
  - Helpers `auth_user_effective_role(uuid)`, `auth_user_has_permission(uuid, text)`,
    `auth_user_permissions(uuid)` — SECURITY DEFINER, fixed search_path; granted to anon + authenticated.
  - RLS enabled on the three catalog tables (SELECT `to authenticated`; writes default-deny) +
    standard privileges.
- Client: `supabase-auth.js` RPC wrappers (`fetchEffectiveRole` / `hasOrgPermission` /
  `fetchMyPermissions`); `auth-ui.js` role-name map + `lang.js` EN/FR keys for all 9 org roles.
  SW precache already covered the touched files; preview serves updated files (HTTP 200 + markers).
- `scripts/verify-supabase.mjs` extended with Phase 03 anon + service-role checks;
  `scripts/verify-rbac.mjs` added — self-cleaning end-to-end RBAC probe.

## Session 6 — verification evidence (recorded)

- `node --check` clean on all touched JS; migration push finished successfully.
- `scripts/verify-supabase.mjs`: PASS — `auth_user_has_permission(anon)` = false,
  `auth_user_effective_role(anon)` = null (plus prior RLS checks).
- `scripts/verify-rbac.mjs` full probe (30 checks, ALL PASS, cleanup verified):
  - owner: role='owner', 60 permissions, has_permission true for organizations.manage / billing.manage /
    audit_logs.view / jsas.approve / users.suspend;
  - worker: role='worker', true for incidents.create / jsas.create / emergency.acknowledge, false for
    organizations.manage / users.suspend / analytics.view / billing.manage / audit_logs.view;
  - outsider (no membership): role=null, has_permission=false;
  - isolation: owner sees only scratch org; outsider + anon see zero org rows;
  - escalation attempts via PostgREST all → 403 (INSERT owner/active; UPDATE role→admin; UPDATE status);
  - catalogs: authenticated reads 16 roles; anon reads 0;
  - cleanup: scratch org + probe users removed; AML tenant #1 intact (0 active members, claimable).
- Probe technique note: probe users are created directly in `auth.users` via Management API SQL with a
  pgcrypto bcrypt hash (no email sent) — avoids the project's signup email rate limit (429 observed on
  the GoTrue signup path this session) and never touches the email quota.

## Session 6 — files changed

- New: `supabase/migrations/20260903000030_phase03_rbac.sql`, `scripts/verify-rbac.mjs`
- Edited: `scripts/verify-supabase.mjs`, `supabase-auth.js`, `auth-ui.js`, `lang.js`
- Docs: IMPLEMENTATION_STATUS (Phase 03 COMPLETE + evidence), SESSION_HANDOFF (session 6),
  CHANGELOG (session 6), DECISIONS (ADR-010), RBAC_MODEL (status), RLS_MATRIX (status note),
  PROJECT_MASTER (phase table), supabase/README (live status + layout)

## Session 6 — known limitations / warnings for next session

- Status is COMPLETE, not VERIFIED-tier (recorded probes, not a CI suite).
- Phase 04 next: mining company + site hierarchy — `site_members` (site-scoped roles reuse the org role
  codes), departments/teams, worker registry, org-admin member/invite flows. Site-scope permission
  resolution (`max(org role, site role)`) belongs there; `auth_user_has_permission` stays the policy
  primitive for Phase 06.
- Platform/government membership flows are Phases 11–12; the roles exist in the catalog now.
- Full RLS_MATRIX per-table policies land in Phase 06; tenant writes remain default-deny until then.
- First-owner claim on AML is still one-shot and unused (0 active members) — see Session 5 warning.
- Auth config reminder: `site_url` still `http://localhost:3000`; set to the real origin before inviting
  users.

## Session 5 — what was completed

- New client modules: `config.js` (publishable Supabase config), `supabase-auth.js` (zero-dep GoTrue
  REST client — signUp / signInWithPassword / signOut / ensureSession+refresh / getUser /
  fetchMyMemberships / fetchOrganization / onAuthChange / bootstrapFirstOwner RPC), `auth-ui.js`
  (worker-app account chip + sign-in/up modal, EN/FR keys added to `lang.js`).
- `index.html`: scripts wired after `app.js`; `sw.js` precache updated. Worker app behavior unchanged
  when signed out (identity is additive in Phase 02).
- `admin.html` (edits applied via anchored Node splices — the write-layer `str_replace` cannot reach
  deep content in large files):
  - Removed the hard-coded `admin`/`mineguard2024` login + localStorage password override (and the
    Settings "Admin Password" row; `mg_admin_pass` purge runs in `supabase-auth.js`).
  - Login = email/password vs Supabase Auth; dashboard unlocks only with an ACTIVE owner/admin
    membership; otherwise "no admin role" error or the first-owner "Set Up Organization" claim step.
  - Silent session restore on load (keeps offline dashboard usable); logout calls GoTrue; topbar badge
    + Settings/Safety Officer Name and soft-delete actor names now derive from the signed-in email
    (`getAdminActorName()`).
- Migration `supabase/migrations/20260903000020_phase02_auth_onboarding.sql` applied to
  `vuniwebbrvpgxscdsfei` via CLI:
  - `bootstrap_first_owner()` (SECURITY DEFINER, authenticated-only): first user claims the first
    ACTIVE `mining_company` org with no active members as OWNER (regulator/platform excluded);
    refuses once ownership exists.
  - Membership RLS: INSERT own `member`/`invited` inert row; UPDATE own row only invited→removed;
    no self-promotion to owner/admin/active; DELETE stays default-deny.

## Session 5 — verification evidence (recorded)

- JS syntax: `node --check` on extracted admin inline script + all new modules — clean.
- Proc ACL: `bootstrap_first_owner` → `{postgres, authenticated}` (anon NOT granted). pg_policies:
  3 membership policies with intended quals/WITH CHECK.
- End-to-end over PostgREST with a temporary confirmed probe user (`mg.probe.gmailtest@gmail.com`,
  created via signup + SQL email-confirm, deleted after):
  - Non-member org SELECT → 200 `[]` (isolation).
  - INSERT self owner/active → 403 42501; member/active → 403; own invited → 201; own rows readable.
  - UPDATE invited→active → 403; invited→removed → 204; DELETE own row → 204 no-op (row still
    present — no DELETE policy exists).
  - Bootstrap full path vs a scratch org (AML temporarily suspended so the probe could not consume
    tenant #1): claim → scratch org id; membership owner/active; org SELECT = scratch only; second
    bootstrap → 400 P0001 "owner already exists".
  - Cleanup verified: scratch org deleted, AML restored `active`, probe membership/user/identities
    removed — AML has **0 active members and remains claimable**.
- Anon `rpc/bootstrap_first_owner` → HTTP 401.
- Auth config read: signups enabled, email confirmation ON, `site_url = http://localhost:3000`.
- Preview proxy: `/`, `/admin.html`, `/config.js`, `/supabase-auth.js`, `/auth-ui.js` all 200 with
  new markers present.

## Session 5 — files changed

- New: `config.js`, `supabase-auth.js`, `auth-ui.js`; `supabase/migrations/20260903000020_phase02_auth_onboarding.sql`
- Edited: `index.html`, `admin.html`, `lang.js`, `sw.js`
- Docs: IMPLEMENTATION_STATUS (Phase 02 COMPLETE + evidence), CHANGELOG (session 5),
  DECISIONS (ADR-009). `admin.html`/`index.html` edits landed via Node splice because the write-layer
  str_replace only reaches shallow content in those large files; each edit asserted a unique anchor and
  persistence was confirmed via read_files + the live preview proxy.

## Session 5 — known limitations / warnings for next session

- Status is COMPLETE, not VERIFIED-tier — no formal automated suite yet (TESTING_STRATEGY rollout is
  still an open cross-cutting item).
- **Auth config action for the user:** `site_url` is still `http://localhost:3000` — set it to the real
  app origin (Settings → Auth → URL Configuration in the Supabase dashboard) before inviting real
  users, so confirmation/recovery emails link to the app. Email confirmation is ON
  (`mailer_autoconfirm=false`) — new sign-ups must confirm before they can sign in; alternatively the
  owner account can be created directly in Auth → Users (email + password, "Auto confirm user").
- **First-owner claim is one-shot:** tenant #1 (ArcelorMittal Liberia) currently has 0 active members.
  The FIRST user who signs in on `admin.html` and clicks "Set Up Organization (Owner)" becomes its
  owner. The platform owner should do this deliberately; after that, adding people is org-admin work
  (Phase 04 invites). If the claim is ever consumed accidentally, recovery needs an elevated SQL fix
  (delete the accidental membership) — see supabase/README.
- Worker data flows still write via the legacy anonymous Firebase channel (dual-read window) —
  per-table Supabase write policies + data-plane gating land in Phase 06; admin soft-delete actor is
  still an email string until then.
- Editing large HTML files: use anchored Node splices (see Session 5 files-changed note), then verify
  through read_files — str_replace cannot see deep content in `index.html`/`admin.html`.

## Session 4 — what was completed

- User supplied Supabase project URL + publishable (anon) key, then chose access-token apply method and
  supplied token. Values merged into sandbox `.env.local` (gitignored).
- Installed `supabase` CLI (devDependency), linked project `vuniwebbrvpgxscdsfei`, pushed migrations:
  - `20260903000000_tenant_foundation.sql` (tenancy tables + authz helpers + RLS)
  - `20260903000010_grant_standard_privileges.sql` (anon/authenticated grants + default privileges;
    added after first push showed 42501 privilege denials pre-RLS)
- Applied `supabase/seed.sql` via Management API (HTTP 201): AML tenant #1 + Nimba Mine / Port Operations
  sites + Liberia regulator placeholder org.
- Added `scripts/verify-supabase.mjs` smoke checker + `.gitignore` (+ `supabase/.temp/`).

## Session 4 — verification evidence (recorded)

- `supabase db push` finished both migrations; seed HTTP 201.
- Elevated queries: organizations = arcelormittal-liberia + liberia-regulator; AML sites = 2;
  relrowsecurity = true on all 3 tables; 3 helper functions present.
- Anon PostgREST: organizations → 200, 0 rows; `rpc/auth_user_has_org_access` → false.
- Supabase integration reported to the service catalog (search `0dbd2bbf-ffc8-4cac-b777-a71d510e2060`).

## Session 4 — files changed

- `supabase/migrations/20260903000010_grant_standard_privileges.sql` (new)
- `scripts/verify-supabase.mjs` (new), `.gitignore` (new), `package.json`/`package-lock.json` (supabase devDep)
- Docs: IMPLEMENTATION_STATUS (Phase 01 COMPLETE), PROJECT_MASTER (phase table), DECISIONS (ADR-008
  verification), CHANGELOG, SESSION_HANDOFF, supabase/README (live status)
- Database: migrations + seed applied to project `vuniwebbrvpgxscdsfei` (evidence above)

## Session 4 — known limitations / remaining Phase 01 items

- Not VERIFIED-tier: no formal automated unit suite yet (recorded smoke checks only).
- Writes remain service-role/default-deny until Phase 02 auth + onboarding policies.
- Firebase `aml-mineguard` export/backup still owed by user before Phase 05 (ADR-003).

## Session 4 — exact next task (Phase 02 — Authentication + identity on Supabase)

1. Read PROJECT_MASTER → IMPLEMENTATION_STATUS → SESSION_HANDOFF; then DECISIONS ADR-008 + RBAC_MODEL.
2. Wire Supabase Auth (GoTrue REST) into the vanilla PWA: sign-up/sign-in flows in `index.html`/`admin.html`,
   session persistence (memory+storage policy decided then — no plaintext creds), logout.
3. Replace the `admin.html` client-side gate (`admin`/`mineguard2024`, localStorage) with real auth;
   worker flow gains lightweight identity; first-owner onboarding creates the membership row linking
   `auth.users` to organization #1.
4. Add onboarding RLS policy so a new authenticated user can read/write their own membership row.
5. Keep the anonymous Firebase channel read-only during the dual-read window (documented gating).
6. DoD: implementation + verification + docs updated; Phase 02 status recorded with evidence.

## Session 3 — Phase 01 authored, apply blocked on credentials (superseded above)

## Session 3 — what was completed

1. **ADR-008 resolved (user directive): backend = Supabase.** Supabase Postgres/RLS/Auth/Storage chosen;
   Firestore data migrates to it in Phase 05. ADR-005 recommendation superseded; decision propagated to
   PROJECT_MASTER, ARCHITECTURE, DATABASE_ARCHITECTURE, RLS_MATRIX, IMPLEMENTATION_STATUS, DECISIONS.
2. Authored (NOT yet applied — no live project yet):
   - `supabase/migrations/20260903000000_tenant_foundation.sql` — organizations / sites /
     organization_members + updated_at triggers + authz helpers (`current_user_org_ids`,
     `auth_user_has_org_access`, `auth_user_is_org_admin`) + RLS enabled w/ membership SELECT policies,
     writes default-deny (service-role only).
   - `supabase/seed.sql` — idempotent tenant #1 (ArcelorMittal Liberia) + Nimba Mine / Port Operations
     sites + Liberia regulator placeholder.
   - `supabase/README.md` — env vars, apply paths (SQL editor or `npx supabase db push --db-url`),
     smoke checks, conventions.
3. Service chosen via catalog search (search `0dbd2bbf-ffc8-4cac-b777-a71d510e2060`, slug `supabase`).

## Session 3 — what changed (files)

- `supabase/migrations/20260903000000_tenant_foundation.sql` (new)
- `supabase/seed.sql` (new)
- `supabase/README.md` (new)
- `docs/engineering/DECISIONS.md` (ADR-008 + ADR-005 superseded)
- `docs/engineering/IMPLEMENTATION_STATUS.md`, `CHANGELOG.md`, `SESSION_HANDOFF.md`
- `docs/engineering/PROJECT_MASTER.md`, `ARCHITECTURE.md`, `DATABASE_ARCHITECTURE.md`, `RLS_MATRIX.md`
  (target = Supabase PostgreSQL)

Database changes: none applied. Migrations: 1 authored, 0 applied. Tests: none run on a live DB.
Security findings: unchanged from Phase 00 (C1–C7 …) — the authored schema is designed to close C2/C3
once applied behind real auth; NOT yet verified at runtime.

## Session 3 — BLOCKERS (exact next actions for the user)

1. **Provide Supabase project credentials** (Settings → Environment / Keys):
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY` (SQL apply/admin; never shipped to client)
   - `SUPABASE_DB_URL` (direct migration apply + verification)
   Create the project via the Supabase setup link if not already done.
2. Then the next session applies `20260903000000_tenant_foundation.sql` + `seed.sql`, runs the smoke
   checks in `supabase/README.md`, records results here, and moves Phase 01 to COMPLETE/VERIFIED-eligible.
3. Firestore export/backup of `aml-mineguard` (all 5 collections) still needed from console before Phase 05.

## Critical findings (must-read before Phase 01) — unchanged from Phase 00

| # | Severity | Finding | Evidence |
|---|---|---|---|
| C1 | CRITICAL | No real authentication; hard-coded admin creds `admin`/`mineguard2024`; client-only gate; settings rewrite creds into localStorage | admin.html:1629-1641, 2320-2329 |
| C2 | CRITICAL | Firestore accessed via REST with only embedded API key; no identity; add/update/delete/purge open to any caller | firebase.js `_FB` + restAdd/restQuery/restUpdate/restDelete/restDeleteAll; sw.js:8-12; firebase_rest_test.html |
| C3 | CRITICAL | No tenant isolation: flat shared collections (incidents/jsas/audit_log/notices/emergency_sos), no organization_id, no user scope | firebase.js COL_* + restQuery |
| C4 | CRITICAL | Authorization is a UI illusion; audit log client-written, actor defaults to 'admin', deletable; missing most sensitive ops | admin.html doLogin/showPanel; firebase.js logAuditEvent |
| C5 | CRITICAL | localStorage as authoritative store incl. plaintext creds, incidents+photos, SOS state/log | app.js/firebase.js/notices.js localStorage keys |
| C6 | CRITICAL | "Offline save → will sync when online" has no retry mechanism → silent cloud data loss; photo-dropping silent; duplicate risk from timestamp+name matching | firebase.js saveIncidentToCloud/saveJSAToCloud (no queue), photo-truncation loop |
| C7 | HIGH | API key + AML branding + admin page public; secrets duplicated in client files; no env separation | index.html/version.json (GitHub Pages update URL), README |
| H1 | HIGH | Single-tenant hard-coding everywhere (AML, Nimba Mine, Liberia) | index.html banner, manifest.json, admin.html defaults |
| H2 | HIGH | Poll-everything realtime (5–30 s per collection per device + SW) — cost/scale; global SOS fan-out to every device | firebase.js subscribe*, notices.js polling, sw.js polling |
| H3 | HIGH | No pagination — full top-500 collection pulls and full re-renders | firebase.js restQuery limit/max, admin render loops |
| H4 | HIGH | Unbounded destructive API surface (hard delete/purge/deleteAll) on same anonymous channel | firebase.js restDelete/purge* |

Also MEDIUM: monolith pages + duplicated serialization code; racy readCount/ackCount; pending XSS render-path
audit; no backups/DR; LOW: stale comments, dev test pages in production site, hard-coded URLs, duplicate
constants.

## Tests performed

None on a live database this session. No VERIFIED statuses claimed. SQL was authored carefully but has NOT
been executed anywhere yet — treat as UNVERIFIED until applied + smoke-tested.

## Unresolved issues / verification blockers

1. Supabase project credentials missing (BLOCKER — above).
2. Firestore console contents (rules, auth users, indexes, real volumes) unverifiable from repo (ADR-003);
   export/backup still owed before Phase 05.
3. Legacy app continues to run on the anonymous Firestore channel during the dual-read window (by design;
   gating lands with Phase 02 auth + Phase 06 policies).
4. Environment mismatch note: repo is static no-build vanilla PWA; preview harness now works
   (package.json + server.mjs). Hosting/deploy pipeline redesign deferred (Phase 12/13).

## Exact next task (resume point after credentials arrive)

1. Verify credentials presence: `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`,
   `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_DB_URL`.
2. Apply migration + seed (SQL editor paste or `npx supabase db push --db-url "$SUPABASE_DB_URL"` +
   seed apply), per `supabase/README.md`.
3. Run smoke checks (org/site rows; helper functions false with no session; RLS denial as unauthenticated
   via PostgREST anon).
4. Record results in IMPLEMENTATION_STATUS.md; close out Phase 01 sub-items; then proceed to
   Phase 02 (Supabase Auth + identity + replacing the admin.html localStorage gate).

## Warnings for next session

- This repo is **not** the Vite/React/Convex template: no build step; vanilla JS multi-page PWA + now a
  Supabase SQL backend in `supabase/`. Do not assume tooling exists; verify first.
- Never ship `SUPABASE_SERVICE_ROLE_KEY` / `SUPABASE_DB_URL` to the client or commit them. The anon key is
  public by design — RLS is the security boundary.
- Preserve worker app UX + offline shell + EN/FR + notices/incident/JSA/SOS semantics.
- No VERIFIED without recorded evidence; Phase 01 schema is authored-but-UNVERIFIED until applied.
- Phase order: complete Phase 01 verification before Phase 02 work; do not skip phases.

## Session 19 (2026-09-12) — Authentication gate + entry routing

**Completed:** centralized auth gate (auth-gate.js) with destination
resolver; entry-gated splash dismissal in index.html; routeAfterAuth in
auth-ui.js; sign-out → gate; worker screen blocked for unauthenticated users;
org context always from membership. verify-auth-gate.mjs 21/21 PASS
(self-cleaning), wired into run-all-probes. Security scan 0 CRITICAL,
xss-audit clean. New doc: AUTHENTICATION_GATE_AND_ENTRY_ROUTING.md.

**Next-session actions:** none required for the gate itself; standing items —
credential rotation (session-16 incident), Phase 13 open control rows
(rate limiting, MFA, media re-encode, DR drill), CI wiring, Firestore
retirement approval.


## Session 20 (2026-09-12) — Regulator organization claim + provisioning

**Completed:** regulator lifecycle remediation — provision RPC (platform-admin
only) + claim-status TVF + one-shot claim UX with visible outcomes; RBAC catalog
reseeded live (…102) after discovering it was empty; organization_members_role_check
extended to platform roles (…101). verify-regulator-lifecycle.mjs 33/33 PASS
(self-cleaning), wired into run-all-probes. verify-phase11 fixtures de-seeded
(48/48). Full regression green; security-scan 0 CRITICAL; xss-audit clean.
New doc: REGULATOR_ORGANIZATION_LIFECYCLE.md.

**Next-session actions:** none required for the regulator lifecycle itself; standing
items — platform-admin UI console (RPC-level provisioning today), credential
rotation (session-16 incident), Phase 13 open control rows (rate limiting, MFA,
media re-encode, DR drill), CI wiring, Firestore retirement approval.
