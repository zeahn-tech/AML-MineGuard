# MineGuard Liberia — Architecture

| Field | Value |
|---|---|
| Doc status | BASELINE from Phase 00 audit + target locked to Supabase (ADR-008, 2026-09-03). Phases 01–12 landed: multi-tenant foundation, auth, RBAC, site hierarchy, RLS/audit enforcement, safety-domain tables (incidents/JSA/inspections/emergency), offline-first sync, the government grant-gated regulator command center (2026-09-09), and the SaaS/enterprise administration layer (plans/subscriptions modeled with billing deferred; site/settings/subscription/platform RPCs; grant-expiry administration; server-side `gov_national_overview` aggregate — 2026-09-09). |
| Last updated | 2026-09-09 |

---

## 1. Current architecture (as-built, audited)

### 1.1 Frontend

Two static HTML apps, no framework, no bundler, no modules:

- **`index.html` (worker app)** — single page, bottom-nav tabs: Home, Glossary, PPE, JSA, Incident/Report,
  SOS/Emergency, Notices. Loads `data.js` → `lang.js` → `firebase.js` → `notices.js` → `app.js`
  (`index.html:1361-1365`). EN/FR toggle stored in `mineguard_lang`.
- **`admin.html` (admin dashboard)** — separate 3,055-line page with a client-side login screen,
  sidebar panels: Overview, Incidents, JSAs, Analytics, Workers, Recently Deleted, Notices, Settings.
  Loads `firebase.js` plus a large inline script.
- Content dictionaries (`data.js`) and translations (`lang.js`) are static JS; glossary/PPE/first-aid work offline.

### 1.2 PWA / service worker (`sw.js`)

- Cache-first app shell (`mineguard-v10`): both HTML pages, all JS/CSS, icons, AML logo; offline navigation
  fallback to cached page; Firestore and font requests bypass the cache.
- Emergency notification: SW polls the `emergency_sos` collection over REST (with the embedded API key) and
  shows a local notification for any `active` doc; also handles `sync`/`periodicsync` tag `mineguard-sos-poll`
  and a `push` handler (no push subscription infrastructure exists in the client).
- No update strategy beyond `skipWaiting` + cache-bump; version check for the APK lives in `index.html`
  (`CURRENT_VERSION` vs `version.json` on GitHub Pages).

### 1.3 Data layer (`firebase.js`)

- Firestore REST v1 (`firestore.googleapis.com/v1/projects/aml-mineguard/...`) authenticated **by API key only**
  (`?key=AIza…` embedded in `firebase.js`, `sw.js`, and `firebase_rest_test.html`). No Firebase Auth anywhere.
- Helpers: `restAdd` (POST), `restQuery` (runQuery, orderBy createdAt DESC, limit default 500), `restUpdate`
  (PATCH + updateMask), `restDelete` / `restDeleteAll` (DELETE).
- Collections: `incidents`, `jsas`, `audit_log`, `notices`, `emergency_sos`.
- Local mirror: every write lands in localStorage first (`mineguard_incidents`, `mineguard_jsas`,
  `mineguard_notices`, `mineguard_sos_state`, …), then a best-effort REST write; back-patching of `_id`
  matched by timestamp+name heuristics. **No write queue, retry, or dedupe exists** — offline writes never
  retry later.
- Connectivity check on load + `online`/`offline` events; polling subscriptions: incidents 15 s (admin),
  notices 15 s (firebase.js) + 30 s (notices.js), SOS 5 s.

### 1.4 Authentication (current — insecure, must be replaced)

- **Worker side: none.** Identity is free text (`mg_worker_name`), device id auto-generated
  (`mg_worker_device_id`), all in localStorage.
- **Admin side: client-only.** `admin.html` compares typed credentials to `localStorage.mg_admin_user`/
  `mg_admin_pass`, defaulting to hard-coded `admin`/`mineguard2024` (`admin.html:1629-1641`); success just
  hides `#loginScreen`. Settings panel lets anyone rewrite those localStorage values.
- **Data plane: anonymous.** Every REST call is unauthenticated; there is no way for Firestore rules to tell
  users apart, and no per-user or per-org scoping on any query or write.

### 1.5 Media

Photos are client-compressed (max 1024 px, quality 0.6), base64-embedded in incident docs; oversized docs get
photos silently dropped to fit ~995 KB. No object storage.

### 1.6 Realtime/notifications

Polling + `BroadcastChannel` (same-device multi-tab) + SW local notifications. No push service, no device
subscriptions, no targeting beyond "any active SOS doc → every device that has ever opened the app".

### 1.7 Deployment

GitHub Pages `https://eman1992hub.github.io/AML-MineGuard/` (README + hard-coded in `version.json`/
`index.html`). APK `MineGuard.apk` shipped for Android; `version.json` update nag. No CI/CD, no env
management, no server, no backups automation in-repo.

## 2. Architectural weaknesses (summary)

1. Unauthenticated, API-key-only data plane shared by every device and both roles (C2/C3 in SECURITY_MODEL).
2. localStorage-as-database + fake sync → silent cross-device data loss (H3).
3. Single-tenant content assumptions hard-coded in UI/asset layer (AML branding, "Nimba Mine" defaults) (H1).
4. Poll-everything realtime does not scale to thousands of devices or a government command center (H2).
5. 3,055-line monolith page + duplicated Firestore serialization in 4+ files (M1).
6. No pagination: full collections downloaded into the browser every poll (H4).

## 3. Target architecture (Supabase, ADR-008 — decided 2026-09-03)

```
┌─ Clients (vanilla PWA retained) ───────────────────────────────────┐
│ Worker app / Admin console / Government portal                     │
│   - plain fetch → PostgREST (+ Auth) — no build, no SDK required   │
│   - offline: sync queue replacing localStorage-as-DB (Phase 10)    │
└───────────────┬────────────────────────────────────────────────────┘
                │ HTTPS: apikey (anon) + Bearer session token
┌───────────────▼────────────────────────────────────────────────────┐
│ Supabase                                                           │
│  - PostgreSQL + RLS  → database-enforced tenant isolation          │
│    (auth_user_has_org_access / current_user_org_ids helpers)       │
│  - Auth (GoTrue): sessions, org memberships (Phase 02)             │
│  - Storage: organizations/{org}/sites/{site}/…, RLS-scoped         │
│  - Server-authoritative ops (Phase 06+): emergency, notices, audit │
└────────────────────────────────────────────────────────────────────┘
```

Target architecture decisions: `DECISIONS.md` ADR-001 (current-vs-target gap) and ADR-008 (Supabase path).
Concrete Phase 01 state: `supabase/migrations/20260903000000_tenant_foundation.sql` + `supabase/seed.sql`.
Detail by concern: frontend/branding per tenant; realtime via subscriptions scoped by org; offline per
`OFFLINE_SYNC_ARCHITECTURE.md`; emergency per `EMERGENCY_RESPONSE_ARCHITECTURE.md`; government per
`GOVERNMENT_PLATFORM.md`; deployment per `PRODUCTION_READINESS.md`.

## 4. Frontend target (high level)

- Keep the offline-first, mobile-first worker experience and the existing industrial visual identity.
- Organization-aware branding: platform → organization → site identity; remove AML hard-coding
  (`index.html` banner/logo, `admin.html` site defaults, manifest description).
- Console surfaces: worker app (report/JSA/notices/SOS), site/org admin, platform admin, government portal —
  one codebase, role-gated surfaces, never security by hidden UI.
- Accessibility and touch-target standards applied to existing templates.

## 5. Backend target (high level)

- Real identity with per-user org memberships (users can hold roles across multiple orgs when authorized).
- Server-side authorization on every query/mutation/storage op via reusable helpers
  (`authUserHasOrgAccess`, `authUserHasSiteAccess`, `authUserHasPermission`…).
- Records are org-scoped at write time from server-side identity, never from client-supplied org IDs.
- Emergency activation, notice publication, audit entries, and CAPA transitions are server operations
  with validation + audit, not raw client writes.
- Storage object paths `organizations/{orgId}/sites/{siteId}/{domain}/{id}/…` authorized server-side.
