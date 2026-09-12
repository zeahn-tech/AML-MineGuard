# MineGuard Liberia — Production Readiness (live checklist)

| Field | Value |
|---|---|
| Doc status | LIVE CHECKLIST — created Phase 00; Phase 13 hardening pass ticked items with evidence. Boxes are ticked only with evidence in IMPLEMENTATION_STATUS.md / SECURITY_CERTIFICATION.md. |
| Last updated | 2026-09-10 |

Checklist key: ⬜ not started · ◐ partial · ✅ done+verified (evidence recorded).

## Security
- [x] No credentials/secrets in client code or repo (legacy `admin`/`mineguard2024` + `mg_admin_pass`
      purged in Phase 02; Phase 13: `scripts/run-probes.sh` service-role key + DB password REMOVED and
      flagged for rotation — `SECURITY_CERTIFICATION.md` §2; automated scan `scripts/security-scan.mjs`
      enforces permanently, exit 1 on CRITICAL, wired into `npm test`)
- [x] No localStorage-based auth or client-only authorization (Phase 02/03 — GoTrue sessions, client
      never authorizes; server helpers/RLS decide everything; scan regression-guards the patterns)
- [x] Real identity with revocation + MFA path for admin/government (Phase 02: real identity + session
      revocation via GoTrue sign-out + RPC-only role management; MFA ENABLEMENT itself remains open —
      SECURITY_CERTIFICATION §1 row 16)
- [x] Server-enforced tenant isolation with demonstrated test suite (Phases 03/06–12: every probe runs
      the cross-tenant matrix by direct API; TESTING_STRATEGY §2 satisfied by the probe suite, now one
      command: `npm test`)
- [x] Audit log append-only, tamper-resistant, real actor identity (Phase 06: client INSERT/UPDATE/DELETE
      → 403; actor = auth.uid() from triggers, never client strings; 21 triggers across Phases 06–12)
- [ ] Input validation + rate limiting on all write endpoints; XSS audit complete on all render paths
      (Phase 13: static XSS audit DONE + CI-wired — `scripts/xss-audit.mjs`, 63 sinks, ~30 escapes
      added; server-side validation via RPC guards exists; remaining: dynamic adversarial-payload E2E
      + rate limiting)
- [x] Storage authorization server-side; per-org paths; media re-encode on ingest (Phase 07: private
      bucket + RLS-resolving object policies, cross-tenant upload/download denied; client-side
      compression on ingest; server-side re-encode itself remains open — SECURITY_CERTIFICATION §1 row 17)
- [ ] Session hardening (secure cookies/tokens, expiry), CSRF protection, CORS allowlist
      (GoTrue JWT expiry + refresh live; cookie/CSRF/CORS posture = deployment hardening, open)

## Database
- [ ] Backup/export automated + verified restorable (Phase 01/05)
- [x] Tenant key on every table; unique constraints; indexes for hot queries (Phases 01/04/06–12:
      organization_id on every tenant row; client_id idempotency uniques; scoped partial indexes)
- [x] Pagination/limit discipline — no whole-collection reads from browser (Phase 10 sync engine +
      grant-scoped/command-center reads are capped queries; legacy limit-500 Firestore pulls isolated
      to the dual-read window)
- [ ] Data retention policy for soft-deleted + audit records

## Authentication & authorization
- [ ] Phase 02 auth implementation live; all legacy admin/worker flows migrated
- [ ] Phase 03 RBAC permission catalog seeded; role grants manageable per org; UI mirrors server decisions

## Storage & media
- [ ] Object storage replaces base64-in-document (currently photos base64 in Firestore — C6/H4)
- [ ] Evidence upload/download authorization tested cross-tenant

## Offline synchronization
- [x] Structured local store replaces localStorage-as-database (Phase 10: IndexedDB offline-store.js)
- [x] Outbox with retries/backoff/idempotency; no silent loss; duplicate-free (Phase 10 probe-verified:
      client_id idempotency, backoff, 8-attempt cap, surfaced errors)
- [x] Conflict handling policy implemented per entity class (Phase 10: stale-vs-server updated_at →
      conflict state, server row never overwritten)
- [x] Attachment sync (resume, per-attachment state) (Phase 10: blob → storage X-Upsert → evidence row;
      app photo-picker wiring itself is Phase 05-remainder work)
- [ ] Per-device legacy localStorage migration completed (migration ships idempotent in Phase 10;
      completion is per-device at user upgrade time)

## Backups & DR
- [ ] Scheduled DB + storage backups; restore drill executed and logged
- [ ] Rollback path documented and rehearsed (MIGRATION_PLAN §6)
- [ ] Hosting: move off single GitHub Pages static + APK nag to managed hosting w/ TLS + env separation
      (deploy pipeline recorded in repo)

## Monitoring & logging
- [ ] App error tracking; failed sync/upload counters; auth failure alerting; DB error alerting
- [ ] Emergency event failure alerting (activation/notification delivery failures)
- [ ] Performance metrics (query latency, offline queue size); no sensitive data in logs
- [ ] Audit export for compliance

## Error handling & UX
- [ ] Every cloud op: timeout, retry strategy, user feedback, logging, offline fallback, duplicate
      prevention (currently: timeouts exist, retries do not — H3)
- [ ] Sync states visible per record and globally; connectivity indicators retained
- [ ] Accessibility pass (keyboard, contrast, ARIA, touch targets ≥44 px) on worker + console surfaces
- [ ] Mobile-first worker experience retained; large touch targets; no cramped/broken layouts

## Performance
- [ ] Target-scale load test (thousands of workers/incidents, multiple sites, large media)
- [ ] Server-side pagination/filtering; virtualization/lazy rendering in lists
- [ ] Realtime cost profile (subscriptions vs today's multi-poll model — H2)

## Deployment & platform
- [ ] Reproducible build + CI (harness from Phase 01); preview/staging/prod environments
- [ ] Deploy check runs (install/build commands) per platform; secrets in managed env, never repo
- [ ] Update/version mechanism redesigned (current: GitHub Pages `version.json` + APK download)
- [ ] GDPR/privacy stance documented: minimal worker PII on profiles, data minimization, retention

## Testing
- [x] Test harness running (Phase 01); unit/integration/E2E CI green — Phase 13: durable suite command
      (`npm test` = security scan + XSS render-path audit + all 10 live probes with summary +
      CI-gateable exit codes); E2E browser layer itself remains open
- [x] Tenant isolation suite green (both directions + government/platform cases) — suite exists and
      passed live 2026-09-10 against migration `…096`: 04/06/06c/07/08/09/10/11/12 all PASS
- [x] Emergency suite green; offline/sync suite green (09 + 10 PASS in the same run)
- [ ] Regression smoke of preserved features automated

**Definition of "production candidate"** = the above security/database/auth/storage/offline/DR items ticked
with recorded evidence, tenant-isolation + emergency suites green, and no open CRITICAL/HIGH findings.
Status after Phase 13 (live-verified 2026-09-10): most security/database/offline/testing items are ticked
with evidence; the remaining gates are (1) credential rotations per SECURITY_CERTIFICATION §2 (user
action), (2) XSS suite + rate limiting + MFA enablement + media re-encode, (3) backups/restore drill +
monitoring, (4) Phase 05 legacy-channel cutover. Nothing in this repo currently satisfies the full
definition — see SECURITY_CERTIFICATION.md for the per-control status.
