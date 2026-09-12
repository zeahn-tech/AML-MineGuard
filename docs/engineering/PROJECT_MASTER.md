# MineGuard Liberia — Project Master

| Field | Value |
|---|---|
| Doc status | BASELINE (created during Phase 00 architecture audit) |
| Last updated | 2026-09-10 |
| Source of truth | This repository (`/home/daytona/codebase`) |
| Related docs | See `IMPLEMENTATION_STATUS.md`, `ARCHITECTURE.md`, `SESSION_HANDOFF.md` |

> Reading order at the start of every session: `PROJECT_MASTER.md` → `IMPLEMENTATION_STATUS.md` → `SESSION_HANDOFF.md`, then only the supporting docs relevant to the task. Do not re-read the whole repository or whole chat history.

---

## 1. Project purpose

MineGuard Liberia is a digital mining safety and regulatory platform for Liberia. The current repository
is a static, offline-first PWA ("Mining Safety Companion") originally built for **ArcelorMittal Liberia /
Nimba Mine** workers. The product vision transforms it into a **secure, offline-first, multi-tenant SaaS**
platform used by mining companies, their sites, contractors, workers, safety staff, and the Liberian
regulatory community — one platform, many tenants, strong organizational isolation.

## 2. Product vision

A commercial and potentially government-adopted platform supporting:

- Government / regulatory authorities (national overview, inspections, compliance)
- Multiple mining companies, each with multiple sites
- Contractors, safety officers, supervisors, managers, inspectors, workers
- Emergency response teams and platform administrators

Non-goal for the MVP era: AI, billing, advanced analytics. Architecture must be *ready* for them, never
*dependent* on them.

## 3. Architecture principles

1. **Backend-enforced security.** Tenant isolation, authorization, and audit are enforced by the server/database,
   never by React/JS conditions, hidden UI, localStorage, or URL parameters.
2. **One application, one platform, many tenants.** No per-company forks or per-company frontends.
3. **Offline-first but never data-loss.** Every operation has a deterministic sync strategy with queues,
   retries, idempotency, and conflict handling. Offline records are never silently dropped.
4. **Safety-critical honesty.** SOS/emergency flows must have explicit lifecycle, acknowledgement, escalation,
   and audit. No silently-failed safety operations; duplicate prevention on retries.
5. **Evidence-based status.** Docs use exact statuses (NOT_STARTED / IN_PROGRESS / BLOCKED / PARTIALLY_COMPLETE /
   COMPLETE / VERIFIED). No claim of "production ready" without evidence.
6. **Preserve working value.** Glossary, PPE, JSA, incident reporting + photos, emergency procedures/SOS,
   notices, notifications, offline PWA install, analytics/filtering/CSV export, soft delete/restore, audit log,
   multilingual UI (EN/FR), connectivity indicators — all preserved and hardened, not removed.
7. **Phased, non-destructive change.** Backup → document → map → migrate → validate → test → rollback path
   before any destructive cleanup. Phases execute in the fixed order in §11.

## 4. Technology stack

### 4.1 Current (audited 2026-09-03)

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML/CSS/JS PWA — `index.html` (worker app), `admin.html` (admin dashboard) |
| Content/i18n | `data.js` (glossary, PPE, contacts, first aid, tips), `lang.js` (EN/FR) |
| Backend/database | Google Firebase project `aml-mineguard`, Firestore via **REST API key only** (`firebase.js`) |
| Media | Base64 JPEGs inside Firestore documents (client-compressed; ~80–150 KB each) |
| Offline | Service worker (`sw.js`, cache `mineguard-v10`) + localStorage as the local data store |
| Realtime | Client polling (5–30 s) + `BroadcastChannel` (same-device) + SW background sync/polling |
| Hosting/distribution | GitHub Pages (`eman1992hub.github.io/AML-MineGuard`) + `MineGuard.apk` update flow via `version.json` |
| Build tooling | **None** — no `package.json`, no bundler, no tests, no CI (all absent from repo) |

### 4.2 Target (see `ARCHITECTURE.md`, `DECISIONS.md` ADR-001/ADR-008)

Backend decided 2026-09-03 (ADR-008): **Supabase** — PostgreSQL with Row Level Security (database-enforced
tenant isolation + authorization helpers), Supabase Auth (Phase 02), Supabase Storage (Phase 07), consumed
by the retained vanilla PWA over plain-HTTPS PostgREST `fetch` (no build step required; matches the app's
restricted-network requirement). Real offline persistence layer (queued writes, not
localStorage-as-database) per `OFFLINE_SYNC_ARCHITECTURE.md`. Legacy Firebase/Firestore serves the app
during the dual-read window and is exported before Phase 05 migration.

## 5. Major modules (current → target)

| Module | Current implementation | Phase |
|---|---|---|
| Glossary / PPE / first aid / tips | `data.js`, static, offline | preserved (P0/P4) |
| Multilingual EN/FR | `lang.js` `t()` keys | preserved |
| JSA | Form + localStorage `mineguard_jsas` + Firestore `jsas` | Phase 08 |
| Hazard ID / risk levels | Low/Medium/High/Critical hard-coded lists | Phase 08 (configurable matrix) |
| Incident reporting + photos | Form + `mineguard_incidents` + Firestore `incidents` (base64) | Phase 07 |
| Emergency procedures | Static steps + contacts | preserved |
| SOS / emergency | Boolean `active` doc in `emergency_sos` + local `mineguard_sos_state`, BroadcastChannel, SW notifications | Phase 09 (backend complete: emergency_events lifecycle + per-user acks + escalation + responders + append-only log; client cutover is Phase 05/10) |
| Safety notices | `notices` collection, poll 15–30 s, read/ack counters | Phase 08/09 hardening |
| Notifications | Local Notification + SW polling (no push infrastructure) | Phase 09+ |
| Admin dashboard | `admin.html` (client-side auth), all panels local+Firestore | Phases 01–06 |
| Analytics/CSV/filters | Client-side aggregation over full downloads | Phase 11/13 |
| Soft delete / restore / purge | `deleted` flags + `audit_log` writes | preserved, hardened |
| Audit log | `audit_log` collection, client fire-and-forget | Phase 06 |
| Workers/activity | Per-device localStorage registry only | Phases 01–04 |

## 6. Tenant model

Target hierarchy (see `MINING_DOMAIN_MODEL.md`):

```
Organization  ←  the hard security boundary (organization_id)
└── Sites ─────── Departments ──── Teams ──── workers/supervisors/safety officers
```

- Every org-owned record carries `organization_id` (and site scope where relevant): incidents, JSAs,
  inspections, notices, emergency events, documents, audit logs, analytics, settings.
- Platform & government roles may cross organizations **only via explicit, recorded authorization**.
- Example seed tenant: **ArcelorMittal Liberia** (org) → Nimba Mine / Port Operations (sites) →
  departments → teams. Nothing is hard-coded to AML in the target.

## 7. Security model

Summary (details in `SECURITY_MODEL.md` + `RLS_MATRIX.md` + `RBAC_MODEL.md`):

- Real authentication (identity provider) with backend-issued session/credential; **no** localStorage passwords,
  no client-only admin gate, no hard-coded credentials.
- RBAC with granular permissions (roles at platform, government, organization, site levels).
- Tenant isolation enforced in the database/backend (authorization helpers per row/document, e.g.
  `authUserHasOrgAccess(orgId)`, `authUserHasPermission(orgId, perm)`), plus security rules matching.
- Storage scoped `organizations/{org}/sites/{site}/...` with server-side authorization on every read/write.
- Tamper-resistant audit trail for sensitive operations.
- Secrets out of client code; client never holds service-role credentials.

## 8. Offline model

Details in `OFFLINE_SYNC_ARCHITECTURE.md`. Requirements: structured local persistence, pending-mutation
queue with retry count/timestamps, deterministic sync ordering, idempotency (no duplicate incidents/JSAs),
conflict handling, connectivity detection, per-record sync states, attachment sync strategy.

## 9. Government model

Details in `GOVERNMENT_PLATFORM.md`. Explicitly-authorized regulatory access layer: Liberia → County →
Company → Site → Department → Work Zone → Event drill-down; inspection/compliance tooling; national
analytics from authorized backend queries; separate government roles; cross-org access granted per record
scope, never blanket.

## 10. SaaS model

- Plans/subscriptions/feature-flags/usage modeled in schema (Phase 12), billing deferred until core is stable.
- Each org: isolated data, users, branding, settings, files, analytics.

## 11. Engineering phases (fixed order)

| # | Phase | Status |
|---|---|---|
| 00 | Architecture audit + engineering documentation | COMPLETE (this session) |
| 01 | Multi-tenant organization database foundation | COMPLETE (applied + smoke-verified on Supabase project, 2026-09-03) |
| 02 | Authentication + identity (Supabase Auth) | COMPLETE (GoTrue auth + bootstrap_first_owner + admin gate replacement; live-probe-verified 2026-09-03) |
| 03 | RBAC + permissions | COMPLETE (applied + live-probe-verified on Supabase project, 2026-09-03) |
| 04 | Mining company + site hierarchy | COMPLETE (site_members + organizational units + worker registry + org invites, site-scoped authz helpers + org-admin RPCs; live-probe-verified 2026-09-03) |
| 05 | Database migration | COMPLETE (2026-09-10, session 17: **fresh-start cutover per owner directive — ADR-014**; Firestore import WAIVED; migrations `…097`/`…098` applied — `safety_notices` + acks + soft-delete RPC; `notices.js` cut over to PostgREST for signed-in users; verify-phase05 42/42 PASS self-cleaning; legacy Firestore channel = fallback-only pending full retirement approval; session-8 import prep retained on disk) |
| 06 | RLS + security enforcement | COMPLETE (live-verified on Supabase project 2026-09-03: site-scope SELECT matrix, least-privilege workers registry, org UPDATE gate, append-only server-side audit_log + triggers on all 7 tenant-management tables incl. sites; RLS/audit probe + cascade-delete regression probe all-PASS) |
| 07 | Incident + evidence management | COMPLETE (2026-09-04, live-verified on `vuniwebbrvpgxscdsfei`: migrations `…060`/`…061` applied; RLS_MATRIX §1.2 incidents + storage live; verify-phase07 all-PASS; Phase 06 regression green; see IMPLEMENTATION_STATUS) |
| 08 | JSA + inspection + corrective actions | COMPLETE (2026-09-04, live-verified: jsas/jsa_steps + inspections + CAPA tables with RLS + audit; verify-phase08 all-PASS; Phase 06/07 regression green) |
| 09 | Emergency response + SOS | COMPLETE (2026-09-04, live-verified on `vuniwebbrvpgxscdsfei`: emergency_events + acks + escalations + responders + append-only emergency_log with lifecycle guards, RLS_MATRIX §1.2 policies, 5 audit triggers (19 total); verify-phase09 all-PASS; Phase 06/07/08 regression green) |
| 10 | Offline-first synchronization | COMPLETE (2026-09-08, client-side offline-first layer shipped + live-verified; see IMPLEMENTATION_STATUS) |
| 11 | Government regulatory command center | COMPLETE (2026-09-09, live-verified on Supabase project: government_grants explicit-authorization table + helpers/RPCs + 16 grant-gated regulator SELECT policies + audit; regulator bootstrap/grant lifecycle + command-center client; see IMPLEMENTATION_STATUS) |
| 12 | SaaS + enterprise administration | COMPLETE (2026-09-09, live-verified on Supabase project: plans/subscriptions modeled (billing deferred), site/settings/subscription RPCs, grant-expiry administration (5-arg issue + extend), platform bootstrap/list/status layer, server-side `gov_national_overview` aggregate, dedicated subscriptions audit trigger; probe 31/31 self-cleaning; see IMPLEMENTATION_STATUS) |
| 13 | Production hardening + security certification | COMPLETE (2026-09-10, live-verified on Supabase project: secret-leak incident remediated (committed service-role key + DB password removed — **rotations still REQUIRED**, SECURITY_CERTIFICATION §2); automated security scan in `npm test` (0 CRITICAL); durable probe suite = one command; migration `…096` applied (max_sites enforcement + audited grant-expiry sweep); verify-phase13 27/27 self-cleaning; full regression all-PASS; XSS suite/rate limiting/MFA/media re-encode/DR drill remain open control rows — see IMPLEMENTATION_STATUS + SECURITY_CERTIFICATION) |

Live per-phase detail: `IMPLEMENTATION_STATUS.md`.

## 12. Non-negotiable requirements

1. Company A can never access Company B's data/files/events/settings/analytics/audit — enforced server-side and
   **demonstrated by automated tenant-isolation tests**.
2. No hard-coded admin credentials; no localStorage authentication; no client-only authorization.
3. No silent data loss: every offline mutation is queued, retried, idempotent, and user-visible in sync state.
4. Emergency/SOS flows: lifecycle, acknowledgement, escalation, audit — including offline behavior.
5. Media in object storage with per-org authorization, not base64-in-database at scale.
6. Audit logs exist for the listed sensitive operations and are not casually editable/deletable.
7. Official safety metrics (TRIR, LTIFR, etc.) use documented industry-standard formulas and assumptions; no invented formulas.
8. AI never makes safety decisions silently; AI output is advisory and reviewable.
9. AML data becomes tenant #1 via migration; no AML hard-coding remains in application code.
10. Documentation is updated at the end of every meaningful task (IMPLEMENTATION_STATUS, SESSION_HANDOFF, CHANGELOG minimum).
