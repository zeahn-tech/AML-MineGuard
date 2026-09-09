# MineGuard Liberia — Production Readiness (live checklist)

| Field | Value |
|---|---|
| Doc status | LIVE CHECKLIST — created Phase 00. Current app is **not production ready**; boxes are unticked until evidence exists in IMPLEMENTATION_STATUS.md. |
| Last updated | 2026-09-03 |

Checklist key: ⬜ not started · ◐ partial · ✅ done+verified (evidence recorded).

## Security
- [ ] No credentials/secrets in client code or repo (currently: hard-coded `admin`/`mineguard2024` in
      `admin.html`; Firebase API key in 3 client files — CRITICAL C1/C2/C7)
- [ ] No localStorage-based auth or client-only authorization (currently present — C1/C4)
- [ ] Real identity with revocation + MFA path for admin/government (Phase 02)
- [ ] Server-enforced tenant isolation with demonstrated test suite (Phases 03/06 + TESTING §2)
- [ ] Audit log append-only, tamper-resistant, real actor identity (currently spoofable — C4)
- [ ] Input validation + rate limiting on all write endpoints; XSS audit complete on all render paths
- [ ] Storage authorization server-side; per-org paths; media re-encode on ingest (Phase 07)
- [ ] Session hardening (secure cookies/tokens, expiry), CSRF protection, CORS allowlist

## Database
- [ ] Backup/export automated + verified restorable (Phase 01/05)
- [ ] Tenant key on every table; unique constraints; indexes for hot queries (Phase 01/06)
- [ ] Pagination/limit discipline — no whole-collection reads from browser (currently limit-500 pulls — H4)
- [ ] Data retention policy for soft-deleted + audit records

## Authentication & authorization
- [ ] Phase 02 auth implementation live; all legacy admin/worker flows migrated
- [ ] Phase 03 RBAC permission catalog seeded; role grants manageable per org; UI mirrors server decisions

## Storage & media
- [ ] Object storage replaces base64-in-document (currently photos base64 in Firestore — C6/H4)
- [ ] Evidence upload/download authorization tested cross-tenant

## Offline synchronization
- [ ] Structured local store replaces localStorage-as-database (Phase 10)
- [ ] Outbox with retries/backoff/idempotency; no silent loss; duplicate-free
- [ ] Conflict handling policy implemented per entity class
- [ ] Attachment sync (resume, per-attachment state)
- [ ] Per-device legacy localStorage migration completed

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
- [ ] Test harness running (Phase 01); unit/integration/E2E CI green
- [ ] Tenant isolation suite green (both directions + government/platform cases)
- [ ] Emergency suite green; offline/sync suite green
- [ ] Regression smoke of preserved features automated

**Definition of "production candidate"** = the above security/database/auth/storage/offline/DR items ticked
with recorded evidence, tenant-isolation + emergency suites green, and no open CRITICAL/HIGH findings.
Nothing in this repo currently satisfies that definition.
