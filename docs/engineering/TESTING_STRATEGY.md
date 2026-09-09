# MineGuard Liberia — Testing Strategy

| Field | Value |
|---|---|
| Doc status | PLAN. Current repo has **no test infrastructure** (no package.json, no test runner). Establishing a test harness is a Phase 01 prerequisite for the phases below. |
| Last updated | 2026-09-03 |

## 1. Layers

| Layer | Scope | Notes |
|---|---|---|
| Unit | Domain logic: risk scoring, status transitions, permission resolution, dedupe keys, import mapping, i18n keys, CSV export | |
| Integration | Auth + authorization helpers against the database; storage authz; notification/emergency server logic; outbox sync engine | |
| E2E (browser) | Worker flows (report incident w/ photo, JSA, notice ack, SOS ack), console flows, government flows | Mobile viewport; offline simulation (devtools/Playwright offline) |
| Security | Auth bypass, IDOR, spoofed claims, XSS, injection, media abuse, secret leakage scan | |
| RLS / tenant isolation | Dedicated suite (below) | |
| Offline/sync | Dedicated suite (below) | |
| Emergency | Dedicated suite (below) | |
| Performance | Poll/query latency at target scale (thousands of workers/incidents), list rendering, storage ops | |

## 2. Tenant isolation suite (required — "demonstrated, not assumed")

Prove, in both directions (A↔B) and across surfaces:
- Company A cannot SELECT/INSERT/UPDATE/DELETE Company B rows (incidents, JSAs, notices, CAPAs,
  inspections, emergency events, audit, settings, analytics).
- A cannot read B's files (object storage refs + signed-URL attempts with B's paths).
- A cannot receive B's realtime events/push/notifications.
- A cannot reach B's settings or analytics.
- Same-organization, same-site, different-site matrices.
- Government: authorized access works and is scoped; **unauthorized government access denied**;
  grant revocation takes effect immediately.
- Platform administrator access works and is audited; support/admin roles cannot edit tenant data
  outside audited playbooks.
- Server-side enforcement proven by direct API calls (bypassing UI), not by UI hiding.

## 3. Offline/sync suite

- Write offline → reconnect → delivered exactly once (idempotency key check).
- Two devices create concurrently → no duplicates; conflict policy applied per entity class.
- Retry with transient failure → backoff → success; permanent failure surfaces to UI with log entry.
- Offline queue survives reload/kill; queue order preserved; attachment upload resumes.
- localStorage→IndexedDB migration runs once and reports counts; legacy keys archived.
- Photos captured offline are never silently dropped; sync state visible per record.

## 4. Emergency suite

- Lifecycle transitions valid/invalid (e.g., close-without-resolution rejected).
- Activation: authorized org/site user only; worker without permission denied; spoofed orgId rejected.
- Escalation timeouts fire; acknowledgements recorded per user (not per device); concurrent acks safe.
- Offline activation + ack + reconnect; duplicate activation prevented; audience targeting correct.
- SW notification actions ack authenticated identity; broadcast scoped to org/site.

## 5. Security testing

- Hard-coded credential scan (grep + CI): admin/mineguard defaults, API keys in client code.
- Auth bypass/IDOR tests; role/permission edge tests; client-supplied orgId/siteId rejected.
- XSS: every render path fed adversarial input (names, notice text, contact fields, photo captions, import).
- Audit integrity: attempt to edit/delete server audit entries → denied; entries contain real actor.
- Secret scan in repo artifacts and exported bundles; media path traversal; oversized upload rejection.

## 6. Regression scope (every release of preserved features)

Glossary & PPE offline; JSA save/list/delete incl. offline; incident report + photos offline/online;
emergency procedures + contacts; SOS banner/ack; notices read/ack/pin/expiry; EN/FR switching;
PWA install + SW cache invalidation; admin dashboard panels, filters, CSV export; soft-delete/restore/purge
flow; connectivity indicators. Manual smoke checklist retained in PRODUCTION_READINESS.md until automated.

## 7. Execution policy

- CI on every change (harness created Phase 01): unit + integration + lint + typecheck + security scan.
- E2E on staging before deploy; tenant suite and emergency suite must pass before any Phase 06/09 gate.
- Record results (pass/fail counts, commands, dates) into IMPLEMENTATION_STATUS.md; statuses only move to
  VERIFIED with recorded evidence.
