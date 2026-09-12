# MineGuard Liberia — Authentication Gate & Entry Routing

| Field | Value |
|---|---|
| Doc status | AS-BUILT (session 19, 2026-09-12): centralized auth gate + destination resolver implemented, live-verified (`scripts/verify-auth-gate.mjs` 21/21 PASS, self-cleaning) |
| Last updated | 2026-09-12 |

## 1. Root cause of the pre-gate defect

`index.html` dismissed its splash on a fixed 1.5s timer and called `initApp()`
unconditionally — **no session check existed on the entry path**. The Worker
Screen (tabs: home, JSAs, incidents, notices, SOS) therefore ran
unauthenticated with identity = free-text `mg_worker_name` in localStorage.
The header \u201cSign In\u201d chip (auth-ui.js) signed in but returned to the same
screen — authentication was not a gate.

## 2. Screen classification

### PUBLIC (unauthenticated)
- Splash / branding / language selection
- Static safety reference content (glossary, PPE, first-aid, emergency
  procedures) — public-by-design safety information
- Authentication gate itself (sign in / create account / accept invitation /
  forgot password)

### AUTHENTICATED (session required)
- Worker workspace: reports, JSAs, incident capture, SOS activation, notice
  acknowledgements — all write tenant data through the sync engine and RLS
- Personal profile / organization display

### ROLE/ORG PROTECTED (session + authorization required)
- `admin.html` — company administration (owner/admin membership; gated since
  the org-lifecycle remediation via `resolveActiveOrg`)
- Government command center, platform admin — protected by existing RBAC/RLS

## 3. Architecture of the gate

`auth-gate.js` (loaded after `supabase-auth.js`, before `auth-ui.js`):

- **`MG_GATE.resolveEntry(finish)`** — the ONLY path that dismisses the
  splash. Flow: restore Supabase session → expired/invalid? clear protected
  state, `finish('AUTH_REQUIRED')` → valid? fetch memberships
  (`fetchMyMemberships`) → `finish(resolveFromMemberships(mems))`.
- **`resolveFromMemberships(mems)`** — the centralized destination resolver:
  `AUTH_REQUIRED` / `NO_ORGANIZATION` / `SELECT_ORGANIZATION` /
  `WORKER_WORKSPACE` / `COMPANY_ADMIN`. Reads **only server rows**
  (RLS-filtered) — client-stored org/role values are never consulted.
- **`MG_GATE.showGate(reason)`** — shows the gate overlay with a
  human-readable reason (used by sign-out and failed session restore).
- Reuses the splash visual identity; language switcher remains available on
  the gate.

`index.html`: splash dismissal is now entry-gated (the 1.5s timer only
shows a loading state; `resolveEntry` decides). No tenant UI renders before
authentication resolves — no flicker of protected data.

## 4. Routing after authentication

| Membership state | Destination |
|---|---|
| No active membership | Onboarding / gate message (create org, claim, join) |
| Single worker membership | Worker workspace |
| Single owner/admin membership | `admin.html` |
| Multiple memberships | Organization selector (explicit choice, validated against active membership) |

`auth-ui.js routeAfterAuth()` applies the resolver after sign-in/sign-up —
no same-screen dead end. The worker screen's org context always comes from
the authenticated membership, never from a client parameter.

## 5. Logout

`signOut()`: detach sync/listeners → `supabase.auth.signOut()` → clear
selected-org preference and private tenant state → `MG_GATE.showGate()`.
Refresh token is killed server-side; the short-lived access token remains
valid until exp (standard stateless-JWT semantics, 1-hour expiry — documented
limitation). Browser back after logout shows the gate; protected data only
re-renders after a fresh session.

## 6. Session restoration

Refresh: `resolveEntry` runs before any tenant UI. Expired → protected state
cleared, gate shown with \u201cWe could not restore your session\u201d. Suspended /
removed members: their membership rows are filtered by RLS/status, so the
resolver routes them to the correct (restricted) destination.

## 7. Security boundaries

- The gate is a **UX boundary only** — Supabase Auth + RLS remain the data
  boundary. Probes prove unauthenticated tenant reads return 0 rows and a
  forged selected-org ID yields 0 server rows for non-members.
- No RLS policies were modified in this remediation.
- SW cache bumped (v12→v13 pattern) and `auth-gate.js` precached so stale
  shells cannot bypass the gate.

## 8. Test coverage

`scripts/verify-auth-gate.mjs` (21 checks, self-cleaning): static gate
wiring (9), resolver outcomes vs live data (6: no-org, worker, admin,
multi-org, empty), security K (forged org id → 0 rows), security A
(unauthenticated reads → 0 rows ×2), logout G (204 + refresh token dead),
session J (garbage token → 401). Wired into `scripts/run-all-probes.mjs`.

## 9. Known limitations

- Access-token validity until expiry after remote logout (standard GoTrue
  JWT semantics; mitigated by 1-hour expiry + local state clear).
- Worker Screen remains a single static shell; authenticated portion is
  hidden behind the gate rather than split into a separate route — deliberate
  to preserve offline/PWA architecture.
