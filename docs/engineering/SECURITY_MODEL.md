# MineGuard Liberia — Security Model

| Field | Value |
|---|---|
| Doc status | BASELINE from Phase 00 audit + TARGET model below. **Phase 12 landed 2026-09-09**: SaaS/enterprise administration — plans/subscriptions modeled (SELECT-only RLS; subscriptions org-private), all site/settings/subscription/platform mutations via SECURITY DEFINER RPCs with server-side permission gates (`sites.*`, `settings.manage`, `billing.manage`, platform-scope membership); `platform_list_organizations` explicitly raises P0001 for non-platform callers (probe-driven fix …095); dedicated subscriptions audit trigger (21 total); `gov_national_overview` computes aggregates server-side over active grants only (no client-side stitching of cross-tenant data). **Phase 11 landed 2026-09-09**: government authorization model live — `government_grants` (explicit record behind every cross-org regulator read; expiry supported; revocation immediate), grant-gated regulator SELECT policies on 16 tables (no grant ⇒ zero rows), grant-expiry administration via 5-arg `regulator_issue_grant` + `regulator_extend_grant` (future-only validation; issuing org's national_regulatory_admin only); legacy 4-arg overload dropped (fix …095) so PostgREST resolves one canonical signature. Live-verified on `vuniwebbrvpgxscdsfei` (`verify-phase12.mjs` 31/31 PASS self-cleaning; `verify-phase11.mjs` 48/48 PASS; Phase 06–10 regression green). Phases 06–10 landed as previously recorded. Remaining safety-domain tables (notices, documents) ungated until Phase 10+. |
| Last updated | 2026-09-09 |
| Severity scale | CRITICAL (exploitable today / data-loss / isolation) · HIGH · MEDIUM · LOW |

---

## 1. Findings (evidence-based, from repository inspection)

### CRITICAL

- **C1 — No real authentication; hard-coded admin credentials in source.** Worker app has no sign-in at all
  (identity is free text + device id in localStorage: `mg_worker_name`, `mg_worker_device_id`). Admin gate is
  client-side only: `admin.html:1629-1641` compares input to `localStorage.mg_admin_user`/`mg_admin_pass`
  with **hard-coded defaults `admin` / `mineguard2024`** in shipped source. Success = hiding a div. Anyone can
  open `admin.html` and use the default credentials, or read/edit the localStorage credential values directly.
  No server knows who anyone is.
- **C2 — Unauthenticated Firestore REST data plane.** All reads/writes/deletes use the REST API with only the
  public API key (`AIzaSyCPqKNe7zyTfBqLT6Gh7Cx2-f7jSf1gvTg`), embedded in `firebase.js`, `sw.js`, and
  `firebase_rest_test.html`. No Firebase Auth, no token, no per-actor identity anywhere. Firestore security
  rules cannot distinguish users; whether the console rules currently allow anonymous access is **not
  verifiable from this repo** and must be checked in Phase 01. Any client can add/update/delete documents in
  `incidents`, `jsas`, `audit_log`, `notices`, `emergency_sos` (helpers include hard `restDelete`,
  `restDeleteAll`, purge flows).
- **C3 — No tenant isolation (by design of the schema).** One flat shared collection per domain for all
  sites/companies. "Company A vs Company B" protection does not exist at any layer — no
  `organization_id`, no rules, no server filter. Worker/admin dashboards pull the same whole collection.
  Records contain PII and sensitive safety data (worker names, badge numbers, injuries, photo evidence,
  SOS acknowledgements).
- **C4 — Client-side authorization illusion / no audit integrity.** "Admin" powers (delete, restore, purge,
  SOS activate/deactivate, notice publish) are plain functions any visitor can call from the console;
  UI-hidden panels are not security. Audit log is fire-and-forget client writes with actor defaulting to the
  string `'admin'` (`firebase.js logAuditEvent`) — spoofable, deletable, and missing most sensitive actions
  (logins, role changes, data reads). Not acceptable as an audit trail.
- **C5 — localStorage as authoritative store + plaintext credentials.** Admin credentials, worker identity,
  incidents+photos, JSAs, notices, SOS state and SOS audit log all live in localStorage (XSS-readable,
  per-device, quota-limited, no expiry). Claims like "saved locally, will sync when online" have **no
  implementation behind them** — writes made while offline are never retried → silent data loss for cloud
  consumers (C6/H3 overlap).
- **C7 — Secrets/keys in client + public admin surface.** API key + project id duplicated across client
  files and test pages shipped to a public GitHub Pages site alongside `admin.html` and a downloadable APK.
  Admin "password change" only rewrites localStorage. No secret can be considered secret.

### HIGH

- **H1 — Single-tenant hard-coding.** AML branding, "Nimba Mine" site defaults, Liberia-only framing embedded
  in `index.html`, `manifest.json`, `admin.html` defaults, README/update URLs (`eman1992hub.github.io/AML-MineGuard`).
  Multi-tenant branding/settings cannot be expressed.
- **H2 — Realtime/scale model.** Every device polls collections every 5–30 s (incidents, notices twice,
  SOS) plus SW polling; costs and battery scale with device count; no server push, no scoping.
- **H3 — No sync reliability.** No write queue/retry/idempotency; local↔cloud matching by
  timestamp+name heuristics (e.g. `savedAt`+`name`) is collision-prone → duplicate incidents/JSAs on retry;
  photo-dropping is silent; localStorage eviction loses user data; no conflict handling.
- **H4 — Whole-collection downloads.** `restQuery` defaults to limit 500 with no cursors; dashboards
  re-render entire lists on 15 s polls; no pagination/virtualization; will not survive thousands of records.
- **H5 — Unbounded destructive surface.** Hard deletes (`restDelete`, `restDeleteAll`, purge-30-day) exist
  and are callable by the same unauthenticated channel used everywhere.

### MEDIUM

- **M1 — Maintainability/attack surface:** 3,055-line `admin.html` + 1,409-line `index.html` monoliths,
  inline handlers (`onclick=` strings), duplicated Firestore value-conversion code in 3+ files, no bundler/
  lint/typecheck/tests. 
- **M2 — XSS hygiene to verify:** much rendering uses `innerHTML`; escaping helpers exist (`escapeHtml`,
  `escHtml`) and are used in notice/admin card paths, but every template-literal render path must be audited
  for raw interpolation of user content (photo names, custom contacts, notice fields, worker inputs). Flagged
  as an explicit test/audit item, not yet proven vulnerable.
- **M3 — Notification/read-ack integrity:** notice `readCount`/`ackCount` are racy client increments; SOS
  "acknowledged workers" derive from per-device localStorage arrays; counts are not trustworthy.
- **M4 — No data backup/export automation or retention policy visible; single GitHub Pages host + APK.

### LOW

- **L1 — Cleanup:** stale comments/versions (SW header "v9" vs `mineguard-v10`; `window.MG.db` unused);
  dev/test pages (`firebase_rest_test.html`, `admin_sync_diagnostic.html`) ship to production site;
  hard-coded `https://eman1992hub.github.io/…` in `version.json`/`index.html`; duplicate constant definitions
  (API key, cache name) across files.

---

## 2. Target security model (Phase 01+)

### 2.1 Authentication
- Identity provider-backed auth (email/password + federated logins) with server-issued, short-lived,
  revocable sessions; MFA-ready for admin/government roles.
- No credentials in localStorage; no client-only gates; logout/session-expiry enforced server-side.

### 2.2 Authorization (RBAC)
- Granular permissions (see `RBAC_MODEL.md`), assigned through roles at platform, organization, and site
  scope; permission checks server-side on every operation (`authUserHasPermission(orgId, perm)`), with
  client UI only reflecting what the server allowed.

### 2.3 Tenant isolation
- `organization_id` on every tenant-owned record, set server-side from session identity — never from
  client-supplied input. Database-level authorization helpers + matching security rules. Cross-org access
  only via explicit grants (regulator/government roles, platform audit role) that are themselves audited.
- Files: object storage keyed `organizations/{orgId}/…` with server-side authz per request — knowing a path
  grants nothing.

### 2.4 Storage/media
- Object storage (no base64-in-document at scale); server-issued upload/download authorization; content-type
  allowlist; image re-encode on ingest; evidence retention rules.
- **LIVE (Phase 07, 2026-09-04):** Private `incident-evidence` bucket (`public = false`; 10 MB/object;
  allowed MIME types: image/jpeg, image/png, image/webp, application/pdf, video/mp4) created in
  `20260903000061_phase07_storage_evidence.sql`. `storage.objects` SELECT/INSERT/UPDATE/DELETE policies
  resolve the incident from the 6th path segment (incident UUID or legacy `client_id`) through the
  incident's own row-level policy on `public.incidents` — knowing an object key grants nothing; every
  access is authorized by the same RLS_MATRIX §1.2 helpers used on the database table. A worker may
  only upload to / read from / update their own incident's objects; an org-wide role may operate on any
  incident in scope; hard-delete is gated to `incidents.delete` holders only. Phase 05 photo uploads
  from the legacy inventory use a compatible path layout (`organizations/{org_slug}/sites/{site_slug}/
  incidents/{client_id}/i.jpg`); the policy accepts both UUID and `client_id` forms.

### 2.5 Sessions/secrets/API
- Session tokens httpOnly/secure where applicable; API key(s)/service credentials server-side only;
  per-tenant secrets; no secrets in client bundles; server-side rate limiting & input validation;
  no client-trusted role/org claims.

### 2.6 Audit logging
- Server-written, append-only, tamper-resistant audit for: login/logout, user create/suspend, role &
  permission change, incident create/modify/delete/restore, JSA approval, inspection completion, notice
  publication, emergency activation/resolution, org setting changes, document access where required.
  Fields: actor, org, action, resource, resourceId, timestamp, metadata, source/device info (see
  `DATABASE_ARCHITECTURE.md` §2.5).
- **LIVE (Phase 06–09, 2026-09-03/04):** `public.audit_log` (RLS: SELECT for org members with
  `audit_logs.view`; INSERT/UPDATE/DELETE privileges revoked from anon + authenticated — append-only)
  is written ONLY by the database: SECURITY DEFINER trigger `trg_audit_capture()` (extended in
  `20260903000060_phase07_incidents.sql` then `…070`/`…071` (Phase 08) and `…080` (Phase 09)) on
  **all 19 audited tables** — 7 tenant-management tables (organization_members, site_members,
  **sites**, organizational_units, workers, org_invites, organizations — Phase 06) + **incidents,
  incident_evidence, incident_witnesses** (Phase 07) + **jsas, jsa_steps, inspections,
  corrective_actions** (Phase 08) + **emergency_events, emergency_acknowledgements,
  emergency_escalations, emergency_responders, emergency_log** (Phase 09) — records actor from
  `auth.uid()` + actor email (never a client-supplied string — closes the C4 spoofable-audit path
  for these operations), a curated metadata subset (one-time invite tokens, incident descriptions,
  storage paths, witness statements, and emergency messages are never mirrored into audit), and
  source='trigger'. Emergency lifecycle guarantees (SECURITY_MODEL §2.6 + PROJECT_MASTER §12.4):
  every emergency activation/transition/ack/escalation/responder write is audit-captured with the
  acting user; `emergency_log` (itself audited) is an append-only stream with no client write
  path. Org hard-delete and cascade deletes succeed and RETAIN their audit rows as platform-scope
  history (`organization_id` null) via fixes `…051`/`…052`; the `sites` gap was closed by `…053`.
  Remaining safety-domain ops (notices, documents) are audited when their tables + triggers land;
  `source='rpc'/'service'` writers and platform/government audit readers land with Phases 11–12.

### 2.7 Administrator & platform security
- Break-glass/platform-admin actions require elevated auth, are never "same as every device", and every such
  action is audited with actor identity; no client-replaceable "admin" flags.

### 2.8 Threat model (target)
Threats addressed at minimum: cross-tenant read/write (C3), anonymous data-plane abuse (C1/C2), credential
theft/session hijack, XSS → data exfiltration, spoofed audit, media exfiltration by path guessing, offline
queue forgery/replay, emergency-channel abuse (spoofed SOS), regulator over-reach (over-broad cross-org
access), insider admin abuse. Tests for each class are listed in `TESTING_STRATEGY.md`; statuses tracked in
`PRODUCTION_READINESS.md`.
