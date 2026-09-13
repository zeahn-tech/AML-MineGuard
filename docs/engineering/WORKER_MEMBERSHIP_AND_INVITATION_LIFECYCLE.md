# MineGuard Liberia — Worker Membership & Invitation Lifecycle

| Field | Value |
|---|---|
| Doc status | AS-BUILT (session 21, 2026-09-13): worker join requests + admin review + notifications + push foundation implemented, live-verified (`scripts/verify-worker-join.mjs` 49/49 PASS, `scripts/verify-push-foundation.mjs` 9/9 PASS, both self-cleaning) |
| Last updated | 2026-09-13 |

## 1. Overview

MineGuard supports THREE separate membership paths. They share the same
`organization_members` rows and the same RBAC/RLS/audit machinery — there is no
parallel membership system:

```text
A. CREATE ORGANIZATION   → user becomes owner of a new tenant (…099 lifecycle)
B. JOIN EXISTING ORG     → worker requests membership; org admin approves (session 21, …110–…114)
C. INVITATION            → org admin invites a worker by email/token (Phase 04, org_invites)
```

## 2. Worker account creation & onboarding

The admin sign-in screen (`admin.html` `#loginClaimWrap`) presents the three
paths to a signed-in user with no active membership:

- **Create New Organization** — commercial onboarding (`create_organization`).
- **Claim Existing Organization** — one-shot bootstrap only (memberless seeded orgs).
- **Join an Existing Organization** — search + request membership (session 21).
- **Invitation** — open an invite link/token and accept it after signing in.

The worker app (`index.html`) gate surfaces `NO_ORGANIZATION` with guidance
pointing at invitation / admin-screen join / self-create. Nothing auto-assigns
a user to an organization.

## 3. Discovery: organization search (§6 security)

`organization_search_joinable(p_query text)` — SECURITY DEFINER SQL TVF,
`grant` to `authenticated` only:

- returns ONLY `id, name, org_type, county` of ACTIVE organizations;
- only orgs that opted in: `settings.allow_worker_join_requests = 'true'`
  (jsonb; **restrictive default = false → not discoverable**);
- no settings, membership, site, incident or private data is exposed;
- anonymous calls are denied (401 — probe-verified).

Opt-in toggle: Organization panel settings card (`join-requests.js`
`renderOptInToggle`) → `org_update_settings`.

## 4. Join request lifecycle (§7–§14)

Table `organization_join_requests` (…110):
`id, organization_id, user_id, requested_role, status, created_at, updated_at,
reviewed_at, reviewed_by, rejection_reason, metadata`.

- `requested_role` is **SERVER-SET** (`worker`/`contractor` only) — the RPC
  signature has no role parameter; forged args are rejected (probe: 404/400).
- `status ∈ {pending, approved, rejected, cancelled}`.
- `unique (organization_id, user_id)` — one request per pair; a
  previously-reviewed request is superseded on re-apply (upsert).
- RLS: SELECT for the requester (own rows) and org admins; **no
  INSERT/UPDATE/DELETE policies — RPC-only writes (default deny)**.
- Audit: `trg_audit_organization_join_requests` → append-only `audit_log`.

### Submit — `organization_request_join(p_organization_id uuid)`

Server-verified inside one transaction: authenticated caller (`auth.uid()`),
org exists + active + opted in, caller not already an active member, no
duplicate pending request. Notifies every active owner/admin via
`notifications`. Friendly errors surface through `join-requests.js`
(`friendlyError`): duplicate pending / already a member / not accepting
requests / session expired.

### Review — `organization_review_join_request(p_request_id, p_approve, p_rejection_reason)`

1. `require_org_admin(org)` (Phase 04 guard) — server-side authorization;
2. `SELECT … FOR UPDATE` row lock + `status='pending'` re-check → **only one
   of two concurrent reviews succeeds** (loser gets "already been processed");
3. org must still be active;
4. approve → upserts an ACTIVE `worker` membership (same row family as
   invitations; captured by the existing `trg_audit_organization_members`);
   reject → records reviewer + optional reason (≤500 chars, reviewer-facing),
   **never creates membership**;
5. requester notified either way (`join_request_approved` /
   `join_request_rejected`; rejection body exposes no internal details);
6. audit rows land via the existing capture triggers.

Review UX: admin card in the Organization panel + notification-bell
"Review Request" deep link (`join-requests.js renderAdminCard`/`reviewFlow`).
Approve/Reject have loading states, duplicate-click protection and explicit
success/failure alerts — there is no silent no-op.

## 5. Pending request ≠ membership (§15)

Until approved, the requester holds NO membership: RLS is unchanged for every
tenant table. Probe-verified: a pending requester sees **0** org incidents and
**0** organization rows; they cannot read join requests of orgs they don't
administer; cross-user notification reads return 0 rows.

## 6. Worker workspace after approval (§16–§18)

- Approval creates `role='worker', status='active'` — the worker resolves to
  the WORKER workspace only (`auth-gate.js` destination resolver).
- `admin.html` hard-refuses worker-role accounts (`showWorkerRefusal`) with
  guidance instead of a blank screen; workers cannot call admin RPCs
  (`org_add_member`, `org_update_member_role` → 400, probe-verified).
- Worker report submission keeps flowing through the existing incident
  pipeline; organization/site context is resolved server-side (RLS + RPC
  authorization), never from client-provided IDs.
- The security boundary is layered: UI guard → route/gate resolution →
  RPC `require_org_admin` → RLS. Hiding buttons is never the control.

## 7. Admin workspace + switching (§19–§20, §35)

`auth-ui.js` account chip offers **Admin Dashboard** / **Worker Workspace**
links when the resolved role permits; the choice is stored in
`sessionStorage.mg_workspace` (a UI preference only — it never changes the
database role or grants/denies anything by itself; authorization is always
re-resolved server-side per request).

## 8. Role changes (§21–§23)

- Promote: `org_update_member_role(worker → admin)` — the promoted user's next
  authorization resolution grants admin RPCs (probe: 204 then success).
- Downgrade: `admin → worker` — the next resolution **removes** admin-RPC
  authorization (probe: 400 on revalidation). Sessions are revalidated
  per-request from live membership rows; cached UI role is cosmetic only.
- Role model follows the Phase 03 catalog (worker / site roles / admin /
  owner / government / platform); no parallel roles were created.

## 9. Invitations (§24–§26, coexisting flow)

Phase 04 `org_invites` is untouched and probe-verified in the same run:
secure 64-char token invite → `org_accept_invite` → ACTIVE worker membership;
email-matched single-use (reuse by another account denied); expiry/revocation
carried over from Phase 04. No raw IDs act as invitation credentials; no
secrets ride in URLs.

## 10. Notifications (§9, §27–§28)

Table `notifications` (…110): user-scoped, written ONLY by server RPCs
(no INSERT policy), own-row SELECT + read-marking (`mark_notification_read`
is scoped to `auth.uid()` — cross-user mark-read is a no-op, probe-verified).
Kinds: `join_request_received`, `join_request_approved`,
`join_request_rejected` (+ `invitation_accepted` reserved).

Client: `join-requests.js` renders the 🔔 bell (unread badge, 60s poll), the
panel lists notifications with unread highlight, and marks visible rows read.
Join-request notifications carry `metadata.request_id` and a Review button
(shown only to org admins; the review is still server-authorized).

## 11. Push notifications (§10, §32 — additional channel, NOT authoritative)

Foundation shipped in …113 + `push-client.js`:

- `push_subscriptions` — per-user Web Push subscriptions (RFC 8030/8291):
  endpoint stored as SHA-256 hash, `p256dh`/`auth` keys stored server-side and
  never returned by any read path; `unique (user_id, endpoint_hash)`;
  RLS own-row only; **writes RPC-only** (`register_push_subscription` /
  `deregister_push_subscription`, identity = `auth.uid()`).
- Client: `push-client.js` subscribes on "enable notifications"
  (`app.js`), unsubscribes on disable; degrades to a graceful no-op until a
  VAPID key is provisioned (`MG_CONFIG.VAPID_PUBLIC_KEY`); never blocks or
  crashes the join/approval flows.
- Display: the existing SW `push`/`notificationclick` handlers show payloads.
- **Not yet wired**: the sender (VAPID keys + a web-push delivery worker) —
  documented as a standing limitation. In-app notifications remain the
  authoritative channel; push failure never blocks approval (probe asserts
  RPC-level guarantees only).

## 12. Offline considerations (§33)

Membership approval is authorization-sensitive and happens server-side; the
offline queue never fabricates approved membership or admin roles. The gate
and admin page resolve destinations from live membership data; offline UI
distinguishes pending sync from granted access.

## 13. Multi-organization users (§34)

The destination resolver validates the **selected** organization against
active memberships server-side; `memberships[0]` is never authoritative.

## 14. Duplicate/race prevention (§14, §38)

- unique `(organization_id, user_id)` — no duplicate request rows;
- pending pre-check + unique backstop — no duplicate pending requests;
- `FOR UPDATE` + status re-check — no duplicate approvals;
- unique `(organization_id, user_id)` on `organization_members` — no
  duplicate memberships.

## 15. Cross-tenant isolation (§15, §29–§30)

Probe-verified: org A members cannot enumerate org B's roster (0 rows);
pending requesters see no tenant data; join-request list is
`require_org_admin`-gated server-side (…112 — the …110 TVF relied on the
client gate only, fixed); notifications are own-row only; anonymous and
cross-tenant RPC calls are denied.

**Roster visibility note**: Phase 00 foundation RLS deliberately lets
org-mates read their OWN org's roster (`members_select_self_or_org`) — that is
membership resolution, not an escalation. The boundary is org-scoping.

## 16. Audit logging (§31)

Captured by existing triggers into append-only `audit_log`:
`organization_join_requests.insert/.update` (requested_role, status,
status_previous, requested_by, reviewed_by), `organization_members.insert/
.update` (approvals, role changes), `organizations.insert` (probe orgs),
`org_invites.*` (invitation flow). No passwords/tokens/secrets in metadata.

## 17. Migrations (in apply order)

| Migration | Purpose |
|---|---|
| `20260903000110_worker_join_requests.sql` | join-request table + RPCs + notifications + search TVF |
| `20260903000111_join_request_audit_cases.sql` | audit-capture cases for the two new tables (verbatim …090 republish + 2 cases) |
| `20260903000112_join_requests_list_authz.sql` | **security fix**: server-side `require_org_admin` gate on the list TVF |
| `20260903000113_push_subscriptions.sql` | push foundation (subscription store + RPCs) |
| `20260903000114_restore_phase04_permissions.sql` | restore Phase 04 `organizational_units.*` permission rows lost in the catalog wipe (probe-caught regression) |

## 18. Testing

- `scripts/verify-worker-join.mjs` — **49/49 PASS**, self-cleaning (fixtures,
  users, requests, notifications, audit rows removed; residue recounted).
- `scripts/verify-push-foundation.mjs` — **9/9 PASS**, self-cleaning.
- Wired into `scripts/run-all-probes.mjs` (`join`, `push`).
- Full regression re-run: phases 04–13 + org-lifecycle + regulator +
  auth-gate all PASS (phase 07/08/09 catalog counts updated 23 → 24 for the
  new trigger; phase 04's `organizational_units.update` finding fixed by …114).
- `security-scan`: 0 CRITICAL / 16 HIGH (documented classified baseline).
  `xss-audit`: clean (9 files incl. `join-requests.js`).

## 19. Known limitations

- Push **sender** (VAPID keys + delivery worker) not yet provisioned; the
  store, RPCs, client subscription path and SW display handler are ready.
- Rejection reason is reviewer-facing (stored on the request row); workers
  receive a neutral notification only (by design, §13/§27).
- `requested_role` supports `worker`/`contractor` (server-set); further roles
  come from admin promotion through existing RBAC, never from the request.
