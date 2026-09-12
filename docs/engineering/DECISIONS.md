# MineGuard Liberia — Decisions (ADR log)

Format: date · decision · reason · alternatives · consequences.

---

## ADR-001 — 2026-09-03 · Current app is a prototype data plane; transformation is phased, not a silent rewrite

**Decision.** The existing MineGuard PWA is preserved as the product surface and source of feature truth,
but its data/security layer (unauthenticated Firestore REST + localStorage) is classified as
prototype-only and will be replaced behind the phased plan (Phases 00–13). Phase 00 changes nothing but
documentation.

**Reason.** Audit evidence: no authentication (admin gate = client JS vs hard-coded `admin`/`mineguard2024`
in `admin.html:1629`), API-key-only Firestore REST in `firebase.js`/`sw.js`, flat shared collections with no
`organization_id`, localStorage mirror with no retry queue, base64 photos in documents. These violate every
tenant-isolation/security requirement and cannot be patched cosmetically.

**Alternatives.** (a) Rewrite everything now from scratch; (b) patch in place feature-by-feature without a
data-plane change; (c) full re-platform in one release. Rejected: (a)/(c) risk losing working offline PWA
value; (b) keeps unsafe foundation while pretending otherwise.

**Consequences.** Long Phase 00+ run before UI-level SaaS features; existing capabilities keep working
during transition; safety-critical replacement must land before "production" claims (per
PRODUCTION_READINESS definition).

## ADR-002 — 2026-09-03 · Repository documentation system adopted

**Decision.** Engineering memory lives in `/docs/engineering/` per PROJECT_MASTER.md; every session reads
PROJECT_MASTER → IMPLEMENTATION_STATUS → SESSION_HANDOFF first and updates the three at session end.

**Reason.** Conserve context; prevent chat-history drift; make state auditable and handoff-safe.

**Alternatives.** Wiki/external docs (unverifiable here) · README-only (insufficient granularity).
**Consequences.** Docs must be maintained as part of Definition of Done for every phase.

## ADR-003 — 2026-09-03 · Firestore console state is out-of-band; verification is a Phase 01 gate

**Decision.** Security rules, Auth users, real dataset volume, indexes, and billing state of project
`aml-mineguard` are not present in this repository and were NOT assumed. First Phase 01 action = verify +
export + backup, then record findings.

**Reason.** Rules in console cannot be audited from code; all C/H findings above hold regardless of current
rules content (no identity exists to authorize against).

**Consequences.** A console-misconfiguration (e.g., rules = public read/write) could make today's exposure
worse than code inspection alone shows; do not assume it is safe until checked.

## ADR-004 — 2026-09-03 · Admin/worker role separation must become real identity (Phase 02), not UI flags

**Decision.** Target model: identity provider + server sessions; roles/permissions resolved server-side;
never accept client-declared role/org. `mg_admin_user`/`mg_worker_name` patterns are removed.

**Reason.** C1/C3/C4 — client-declared identity is meaningless for isolation and audit.

**Consequences.** Some current convenience (open worker app, instant JSA) gains a lightweight sign-in that
must stay one-tap in practice (offline-first worker UX retained).

## ADR-005 — 2026-09-03 · Backend path decision deferred to Phase 01 with a recommended direction

**STATUS: SUPERSEDED — resolved by the user on 2026-09-03 in favor of Supabase (see ADR-008).**

**Decision.** Re-platform the data plane onto the environment's managed backend with built-in auth +
server-side authorization helpers + object storage + realtime (Convex-type stack), rebuilding the PWA shell
around the existing UX, rather than deepening the Firebase API-key REST integration. **This is a
recommendation recorded now; final sign-off happens at the start of Phase 01 after console verification
(ADR-003) and any user constraint review.**

**Reason.** Requirements demand: server-enforced row-level org checks (database-enforced authorization
helpers), real auth incl. roles across orgs, object storage with per-request authorization, scoped realtime,
and an offline sync engine — none expressible reliably on today's anonymous REST surface, where even
Firestore rules cannot scope by user because no user exists. A managed backend in this environment gives
auth/identity, reactive queries, server-authoritative mutations with authorization helpers, and storage in
one coherent system with tooling that runs here.

**Alternatives.** (a) Stay on Firebase: add Firebase Auth + rules + cloud storage — viable but rules-based
tenant scoping is brittle at multi-role scale, the console cannot be operated from this environment, and the
REST-only transport (deliberately chosen for restricted networks) still needs a rewrite for Auth tokens;
(b) custom API server (ops burden); (c) static-only evolution (impossible: no server enforcement).

**Consequences.** A frontend re-platform (framework + build + PWA rebuild) rides on this decision — it is
the single biggest architectural consequence of Phase 01 and must not be made implicitly.

## ADR-006 — 2026-09-03 · Media moves to object storage; base64-in-document is legacy

**Decision.** Target stores evidence/files as storage objects under org-scoped paths with server-side
authorization; client-compressed uploads; database holds references. The "shrink photos until the doc fits,
silently drop the rest" mechanism in `firebase.js` is eliminated in Phase 07.

**Reason.** Doc-size tax, no granular authorization, data-loss behavior, scaling limits (C6/H3/H4).

**Consequences.** Storage cost + upload pipeline appear; evidence integrity (hash) and retention must be
added with it.

## ADR-007 — 2026-09-03 · AML data becomes tenant #1 via migration; zero AML hard-coding in code

**Decision.** ArcelorMittal Liberia / Nimba Mine becomes seeded organization #1 with sites/departments;
all UI/asset hard-coding of AML (banner, logo, "Nimba Mine" defaults, manifest text) is parameterized by
org branding.

**Reason.** Requirement §32/§33 — current app embeds one tenant's brand and defaults throughout.

**Consequences.** Migration (Phase 05) must seed org + resolve legacy text references; visual identity must
stay strong under org theming.

## ADR-008 — 2026-09-03 · Backend path RESOLVED: Supabase (PostgreSQL) is the production backend

**Decision.** MineGuard's data plane re-platforms onto **Supabase**: PostgreSQL database with Row Level
Security as the tenant-isolation enforcement layer, Supabase Auth (GoTrue) for identity (Phase 02), Supabase
Storage for org-scoped media (Phase 07), consumed by the vanilla PWA through plain-HTTPS PostgREST `fetch`
calls. Firestore data migrates into this Postgres schema (Phase 05). User directive 2026-09-03
("Backend path: Supabase; Firebase data: use Supabase as the Backend").

**Reason.** Postgres RLS gives true database-enforced row-level authorization that maps 1:1 to the required
`auth_user_has_org_access(org_id)` / permission model (RLS_MATRIX.md) — the property the anonymous
Firestore REST surface fundamentally cannot provide (no identity to authorize against, ADR-001/005
findings C1–C4). PostgREST keeps the app's no-build, plain-fetch, restricted-network architecture; no
client SDK dependency required. Supabase was confirmed as the fit for this exact stack via the service
catalog search (2026-09-03, search `0dbd2bbf-ffc8-4cac-b777-a71d510e2060`).

**Alternatives considered.** (a) Convex (ADR-005 recommendation) — excellent in-env tooling but pushes the
vanilla PWA toward a bundler/framework and a second opinion was not required once the user chose Supabase;
(b) Firebase Auth + rules on the existing project — still viable, but rules-based multi-role tenancy is
brittle and the console cannot be operated from this repo; (c) stay on anonymous Firestore REST — rejected
(C1–C3).

**Consequences.** (1) `supabase/` becomes the backend source of truth — migrations + seed committed in-repo
(20260903000000_tenant_foundation.sql, seed.sql); (2) RLS is enabled on tenancy tables from Phase 01 with
membership SELECT policies; full RLS_MATRIX policy set lands Phase 06; (3) Phase 02 wires Supabase Auth and
replaces the hard-coded `admin`/`mineguard2024` localStorage gate; (4) Firebase project `aml-mineguard`
keeps serving the legacy app during the dual-read window and is exported/backed up before Phase 05
(ADR-003 still applies to that export); (5) real Supabase project credentials are required to apply and
verify migrations — Phase 01 verification is BLOCKED until the user supplies `NEXT_PUBLIC_SUPABASE_URL` /
`NEXT_PUBLIC_SUPABASE_ANON_KEY` (+ `SUPABASE_SERVICE_ROLE_KEY` / `SUPABASE_DB_URL` for SQL apply);
(6) ADR-005's frontend re-platform consequence is dropped — the vanilla PWA is retained, evolved with
plain-fetch PostgREST clients.

**Verification (2026-09-03, same day):** migrations `20260903000000_tenant_foundation.sql` +
`20260903000010_grant_standard_privileges.sql` pushed via Supabase CLI to project `vuniwebbrvpgxscdsfei`;
seed applied (AML tenant #1 + 2 sites + regulator placeholder). RLS enabled on tenancy tables; anon
PostgREST SELECT returns 0 rows; `auth_user_has_org_access(anon)` = false. Details + evidence in
`IMPLEMENTATION_STATUS.md` Phase 01. Integration reported to the service catalog.

---

## ADR-009 — Phase 02 auth & identity design (2026-09-03)

**Status: accepted; implemented + live-verified 2026-09-03 (evidence in IMPLEMENTATION_STATUS Phase 02).**

**Decision.** (1) Auth client = zero-dependency GoTrue REST over plain fetch (`supabase-auth.js`), matching
the PWA's no-build/restricted-network constraint; no SDK. (2) Session tokens persist in localStorage under
`mg_auth_session` (access + refresh + expiry); passwords are never stored; the legacy `mg_admin_pass`
plaintext key is deleted on load; silent restore + refresh keeps the offline PWA usable. (3) The
`admin.html` dashboard gate authorizes on ACTIVE membership with role owner/admin — client-side only as
UX, never as security (RLS is the boundary); the static `admin`/`mineguard2024` login is deleted.
(4) First-owner onboarding = `bootstrap_first_owner()` SECURITY DEFINER RPC granting OWNER of the first
ACTIVE `mining_company` org with zero active members; regulator/platform orgs excluded; the function
refuses once any org is owned. (5) Self-service membership policies permit only own `member`/`invited`
INSERT and withdraw-only UPDATE; self-promotion to owner/admin/active is impossible through RLS.

**Reason.** One-shot owner bootstrap gives the (previously owner-less) seeded tenant a legitimate first
administrator without exposing a backdoor to anyone afterwards: an org that already has an active
owner/admin can never be claimed. Narrow WITH CHECK policies keep "read/write own membership row" without
granting the ability to escalate. REST-only client preserves the worker app's offline shell and keeps
auditable plain-HTTP requests.

**Alternatives considered.** (a) Supabase JS SDK — adds a bundler requirement the static app lacks;
(b) auto-create membership for every sign-up — rejected: silently attaches strangers to tenant #1;
(c) invite-code/email-allowlist onboarding — correct long-term (Phase 04 org-admin flows will add it), too
eager for Phase 02; (d) keep the localStorage password gate until Phase 06 — rejected (C1).

**Consequences.** (1) Auth config on the project requires `site_url` (currently `http://localhost:3000`)
pointed at the real app origin before inviting real users — email confirm/recovery links derive from it;
email confirmation is ON. (2) The bootstrap claim is consumed by the FIRST user who signs in and clicks
"Set Up Organization" — the platform owner should do this deliberately in the preview; afterwards
membership provisioning is org-admin work (Phase 04). (3) Worker data flows still use the legacy
anonymous Firestore surface during the dual-read window; per-table Supabase write policies + data-plane
gating land in Phase 06. (4) Admin-dashboard records carry an actor string (email) until Phase 06 maps
audit/ownership to `auth.users` ids. (5) RLS self-service policies + bootstrap RPC are versioned in
`supabase/migrations/20260903000020_phase02_auth_onboarding.sql`.

---

## ADR-010 — Phase 03 RBAC: permission catalog + role bundles as database tables; role = named set of permissions (2026-09-03)

**Status: accepted; implemented + live-verified 2026-09-03 (evidence in IMPLEMENTATION_STATUS Phase 03).**

**Decision.** RBAC core lands as three database tables — `permissions` (60 codes / 19 domains, from
RBAC_MODEL §2), `roles` (16 seeded system roles: 3 platform + 4 government + 9 organization; org role
codes exactly equal `organization_members.role` values so helpers join by code), and `role_permissions`
(seeded default bundles from RBAC_MODEL §3; owner = full catalog, admin = catalog minus billing.manage,
worker/contractor = self-service set, etc.). `organization_members.role` check constraint expands to the
9 org roles. Three SECURITY DEFINER helpers (`auth_user_effective_role`, `auth_user_has_permission`,
`auth_user_permissions`) become the single authorization primitive that Phase 06 RLS policies and future
RPCs call. Catalogs are readable by any authenticated user (no tenant data in them); writes stay
default-deny until Phase 12 custom org roles.

**Reason.** Granular permission checks in server logic beat role-name checks (RBAC_MODEL §1); seeding the
catalog + bundles in the migration gives Phase 06 policies a tested primitive and the client a
server-resolved permission mirror (`fetchEffectiveRole` / `hasOrgPermission` / `fetchMyPermissions` in
`supabase-auth.js`) without shipping any authorization logic to the client. Keeping org role codes equal
to the existing membership role text preserves Phase 01/02 behavior (helpers, `bootstrap_first_owner`,
admin gate) with zero data migration.

**Alternatives considered.** (a) FK from `organization_members.role` to `roles(id)` — normalized but
requires a data migration of the text column and breaks the plain-text role contract the existing client
and Phase 02 policies rely on; rejected for now, revisit if custom org roles need it in Phase 12.
(b) Client-side permission maps — rejected (C4: UI illusion; enforcement must be server-side).
(c) JSONB permission grants per membership — less queryable and harder to audit than the join table.

**Consequences.** (1) Phase 06 policies will call `auth_user_has_permission(org_id, perm)` — the helper
is already live-verified. (2) Site-scoped resolution (Phase 04 `site_members`) reuses the same org role
codes; effective permission = max(org role, site role). (3) Platform/government membership flows are
Phases 11–12 but their role definitions and bundles are seeded now. (4) New migration
`20260903000030_phase03_rbac.sql`; probe harness `scripts/verify-rbac.mjs` (self-cleaning) provides
repeatable positive/negative evidence and is the seed of the TESTING_STRATEGY tenant-isolation suite.

---

## ADR-011 — Phase 04 site hierarchy: RPC-gated writes + site-scoped permission resolution; site roles never grant org scope to non-members (2026-09-03)

**Status: accepted; implemented + live-verified 2026-09-03 (evidence in IMPLEMENTATION_STATUS Phase 04).**

**Decision.** The mining-company/site layer lands as four org-scoped tables — `organizational_units`
(self-referencing departments/teams/work zones), `site_members` (roles reuse the same 9 org role codes),
`workers` (registry with optional auth.users link), `org_invites` (email onboarding) — with RLS
SELECT-only policies (org-membership scope; own-row for site_members) and **all tenant writes through
SECURITY DEFINER RPCs that re-check authorization** (`org_add_member`, `org_send_invite`,
`org_accept_invite`, `site_assign_member`, `org_create_unit`, `worker_add`, …). Site-scoped permission
resolution = max(org role, site role) via new helpers `auth_user_site_effective_role` /
`auth_user_has_site_access` / `auth_user_has_site_permission`; the org-scope primitives
`auth_user_has_permission` / `auth_user_permissions` are upgraded so an ACTIVE ORG MEMBER's site roles
widen scope, while a **site-only user (no org membership) never obtains org scope from a site row**.

**Reason.** Phase 04 is the first phase that lets tenant data change through end-user actions; keeping
writes on audited, permission-checking RPCs (instead of guessing at RLS policy predicates for every
join-table mutation) gives one reviewable chokepoint and matches the phase order — the full per-table
RLS_MATRIX policy set lands in Phase 06 and can later absorb paths the RPCs proved. Documented
inheritance (RBAC_MODEL §1.5) says org membership implies role capability across sites and site roles
narrow/augment it — implementing that as "site widens org member; site-only user stays site-scoped"
prevents the obvious escalation (invite someone as site admin and read the whole org) while keeping
site-scope enforcement available for Phase 06 policies.

**Alternatives considered.** (a) Full RLS write policies now — deferred by phase order (Phase 06); RPCs
remain valid afterward either way. (b) Site-only users inherit org scope from their site role — rejected
(privilege escalation; contradicts org-as-hard-boundary). (c) New membership table per org role set —
rejected; site_members reuses the seeded role codes so the RBAC join layer is unchanged.
(d) Firestore-style client writes + validation — rejected (backend-enforced security principle).

**Consequences.** (1) All Phase 04 management RPCs raise server-side on insufficient privileges; probes
prove outsider/site-only/worker denial paths. (2) Invite acceptance is email-matched
(`org_accept_invite` compares the signed-in user's email with the invite) — the invite token is a
one-time secret delivered in-app until a mail provider is wired (Phase 09/13). (3) `org_list_members`
exposes member emails only to org members (SECURITY DEFINER + membership gate). (4) Permission catalog
grows 60 → 62 (`organizational_units.create/.update`); owner bundle auto-widens; worker bundle
unchanged. (5) Migrations `20260903000040_phase04_site_hierarchy.sql` +
`20260903000041_phase04_fixes.sql`; probe harness `scripts/verify-phase04.mjs` (58 checks, self-
cleaning) extends the tenant-isolation evidence base.

## ADR-012 — Phase 05 prep: snapshot-based offline mapping with human-decision gates; photo payloads retained for hashing (2026-09-03)

**Decision.** Phase 05 migration prep is executed in two repo-local, gitignored stages against the
legacy data BEFORE any import: (1) `scripts/phase05-inventory.mjs` snapshots all 5 Firestore
collections read-only over the same anonymous REST channel the shipped app uses — photo payloads are
RETAINED whole (total ≈ 1.2 MB; only fields ≥ 8 MB are stripped) so mapping can decode, hash (sha256),
type (JPEG/PNG sniff) and export them; (2) `scripts/phase05-map.mjs` maps the snapshot to the
documented target shape offline — deterministic, restartable, dry-run by construction — emitting
per-table payloads keyed by legacy `client_id` (idempotent apply), a photo object-storage manifest,
a validation report, and review lists. The mapper NEVER silently resolves what the org owner must
decide (site/zone vocabulary vs seeded sites, worker badge hygiene, free-text supervisors/witnesses):
unresolved values are flagged in `review-lists.json` and answered through `overrides.json` on re-run.

**Reason.** MIGRATION_PLAN §1 "Volume: unknown" made every downstream decision ungrounded; the durable
user-owned Firestore export (ADR-003) is still outstanding and target safety-domain tables land in
Phases 06–09 — so the only responsible Phase 05 progress is measurable prep with recorded evidence.
Retaining photos (vs the inventory's original 4096-char strip) is required for faithful hashing/mime
classification before the Phase 07 object-storage move; the payloads validate the mapping contract now
so cutover becomes "tables + credentials + review sign-off" later.

**Alternatives considered.** (a) Run the import straight from live Firestore at cutover — rejected:
no reproducibility, no diff-able snapshot, and the anonymous channel is a prototype surface being
retired. (b) Keep stripping photos ≥ 4096 chars — rejected: cannot hash/type/export media for the
Phase 07 work queue from the snapshot. (c) Auto-resolve site/zone/department/badge mismatches by
fuzzy rules — rejected: silent decisions on safety records violate the org-hard-boundary and
no-silent-guess principles; they are review items instead. (d) Skip to Phase 06 — noted: Phase 06 is
the recommended next phase after this prep lands, but it does not replace the volume/mapping baseline.

**Consequences.** (1) Two new gitignored dirs (`supabase/legacy-inventory/`, `supabase/migration-prep/`)
contain personal data — never pushed. (2) `phase05-map.mjs` status maps open→SUBMITTED,
resolved→RESOLVED and JSA→SUBMITTED as documented (MIGRATION_PLAN §3) in ONE place to sync with
Phase 07–09 DDL. (3) Photo storage keys follow
`organizations/{org}/sites/{slug|unassigned}/incidents/{client_id}/{i}.jpg` — "unassigned" until
review answers land. (4) Audit_log rows import with `legacy_import: true` (actor strings are not
tamper-proof evidence). (5) Deterministic re-runs are verified by byte-identical payload hashes.

## ADR-014 — Phase 05 cutover: fresh-start directive — the Firestore data migration is WAIVED; Supabase becomes the only production data path for signed-in users (2026-09-10)

**Decision (owner directive, quoted: "Let go every data migration from Firestore, we are going to start
afresh with new data in Supabase").** No legacy Firestore documents are imported. Tenant #1 and every
future tenant start with empty safety-domain tables. The legacy anonymous Firestore channel remains
ONLY as the signed-out/local-only fallback path (workers are identity-optional by design, Phase 02);
for any signed-in user, the Supabase offline-sync engine (Phase 10) is the authoritative read AND
write path for incidents, JSAs, emergency events, and (new) safety notices. ADR-003's Firestore
export/backup requirement is satisfied by ADR-012's gitignored snapshot (local, not durable) plus the
explicit owner waiver of the import — the platform owns the consequence: legacy history does not
appear in the new system.

**Reason.** The legacy corpus is small (~100 docs), contains review-gated hygiene problems (site
vocabulary mismatches, badge conflicts, free-text actors) that would each need owner decisions, and
blocks the production cutover indefinitely. Starting fresh lets every tenant begin inside the
tenant-isolation model with server-pinned identity from day one — the property the legacy data can
never have (all of it is anonymous-channel data). The import prep (ADR-012) remains available on disk
if the owner later reverses this decision.

**Consequences.** (1) The last legacy-only domain without a Supabase home — safety notices — moved into
the tenant model in migration `20260903000097_phase05_cutover_notices.sql` (`safety_notices` +
`safety_notice_acks`: org+site scoped, `notices.manage`/org-admin writes, broadcast semantics via
site_id null, per-user idempotent acks, dedicated additive audit triggers → 23 audit triggers).
(2) Signed-in reads/writes cut over in `firebase.js` (incidents/JSAs/SOS via the sync engine) and
`notices.js` (direct PostgREST with legacy-shape reverse-mappers so no UI code changes). (3) The
Firestore channel is now fallback-only; full retirement (removing the signed-out mirror) is a later
deletion step requiring explicit owner approval. (4) `review-lists.json` and the import payloads stay
gitignored and unimported. (5) Fresh-start means tenant #1's admin dashboards show zero historical
rows until new production data is created.

## ADR-015 — Self-service organization creation + controlled ownership transfer (2026-09-10)

**Decision.** Normal company onboarding is a first-class platform capability: a signed-in user may
create a `mining_company`, `contractor`, or `service_provider` organization through the
SECURITY DEFINER RPC `create_organization(p_name, p_org_type, p_county)` — which atomically
creates the org, the creator's owner membership (identity from `auth.uid()`, never client data),
and a starter-plan subscription (existing Phase 12 model; no billing). Regulator/platform orgs remain
provisioning-only. Slug generation is server-side and collision-safe (`-2`, `-3`…); the UUID
stays the primary identifier and slugs carry no security meaning. Ownership succession is the
owner-initiated RPC `org_transfer_ownership` (atomic swap, exactly one active owner invariant,
admins cannot seize). `bootstrap_first_owner()` is retained for controlled first-deployment
bootstrap only and is no longer presented as the normal creation path. Organizations INSERT remains
default-deny — creation is ONLY possible through the approved RPC (no RLS weakening).

**Reason.** `bootstrap_first_owner` is a claim of a pre-seeded memberless org, not a creation
mechanism: once any org had an owner, every new user hit "no claimable organization found…". A
multi-tenant SaaS needs self-service tenancy without weakening the tenant boundary.

**Consequences.** (1) Any sign-up can become a tenant owner — mitigated by plan caps (starter:
3 sites/25 users, Phase 13 enforcement) and audit capture; rate limiting remains an open Phase 13
control row. (2) The unique `lower(name)` index intentionally rejects duplicate org names even
when slugs could disambiguate (existing business rule preserved). (3) Ownership transfers and
creations are audited via the existing triggers. (4) The selected-organization client preference is
explicitly NOT a security boundary (RLS revalidates every access).
