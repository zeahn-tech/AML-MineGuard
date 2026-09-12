# MineGuard Liberia — Organization Lifecycle

| Field | Value |
|---|---|
| Doc status | AS-BUILT (session 18, 2026-09-10): self-service creation + ownership transfer implemented, live-verified (`scripts/verify-org-lifecycle.mjs` 30/30 PASS self-cleaning) |
| Last updated | 2026-09-10 |

## 1. Overview

MineGuard is ONE platform, MANY tenants. Every organization is an isolated tenant
(users, memberships, sites, workers, incidents, JSAs, inspections, CAPA, emergency
records, notices, documents, analytics, settings, audit rows, storage objects).
Company A can never access Company B's data unless an explicitly granted
government/platform mechanism (Phase 11 `government_grants`, Phase 12 platform
admin) permits it — enforced by RLS on every table.

Tenant model:

```
MineGuard Platform
├── ArcelorMittal Liberia          (mining_company — seeded tenant #1)
│   ├── Nimba Mine
│   └── Port Operations
├── Mining Company B               (self-service created, …099)
│   ├── Site A
│   └── Site B
├── Contractor C                   (self-service created)
├── Service Provider D             (self-service created)
├── Government Regulatory Org      (provisioned via authorized bootstrap ONLY)
└── Platform Admin Org             (provisioned via authorized bootstrap ONLY)
```

## 2. Organization types

| Type | Self-service creatable? | Provisioned via |
|---|---|---|
| `mining_company` | ✅ YES (default) | `create_organization()` |
| `contractor` | ✅ YES | `create_organization()` |
| `service_provider` | ✅ YES (added `…099`) | `create_organization()` |
| `regulator` | ❌ NEVER | Government administration only |
| `platform` | ❌ NEVER | `bootstrap_first_platform_admin()` only |

The server rejects regulator/platform in the public RPC (`cannot be self-registered`).
MineGuard makes NO claim of official Government of Liberia authorization — regulator
orgs are placeholders until formal provisioning occurs.

## 3. Lifecycle diagram

```
 Sign up (GoTrue email/password)
        │  email verification (Supabase Auth)
        ▼
 ┌─ Signed in, no active memberships ─────────────────────────┐
 │  "Welcome to MineGuard"                                    │
 │  • Create New Organization  ← normal path (…099 RPC)       │
 │  • Claim Existing Organization ← bootstrap-only (…020 RPC) │
 │  • Join an Organization ← invitation from an admin         │
 └──────────────┬─────────────────────────────────────────────┘
                │ create_organization(name, type, county)
                ▼  [ATOMIC: org + owner + subscription]
 Organization created (slug collision-safe; owner = auth.uid())
                ▼
 Owner Dashboard → "Add your first mining site" (site_create)
                ▼
 Operate: invite admins/members (org_send_invite) → org_accept_invite
                ▼
 Multi-membership users: Organization switcher (UI state only)
                ▼
 Optional: ownership transfer (org_transfer_ownership, owner-only)
                ▼
 Suspension / closure: platform admin RPCs (Phase 12) — audited
```

## 4. Stage-by-stage

### 4.1 Registration + email verification
- GoTrue `/auth/v1/signup`; email confirmation handled by Supabase Auth.
- No passwords are ever stored by MineGuard; only the GoTrue session lives in
  `localStorage.mg_auth_session` (PWA standard).

### 4.2 Create organization (server-authoritative)
- RPC `create_organization(p_name, p_org_type, p_county)` — SECURITY DEFINER,
  fixed `search_path`, migration `20260903000099_org_lifecycle.sql`.
- Validation: session required; name 1–120 chars; type whitelist
  (mining_company/contractor/service_provider).
- Slug: server-generated from the name (`ABC Mining Liberia` →
  `abc-mining-liberia`); on collision `-2`, `-3`, … (deterministic, capped at 50
  attempts); UUID remains the primary key. Duplicate exact names are rejected by
  the pre-existing `organizations_name_lower_uidx` unique index.
- Atomicity: org INSERT + owner membership INSERT + starter subscription INSERT
  happen inside ONE function body — a failure anywhere rolls back everything;
  no orphaned orgs, no ownerless orgs.
- Ownership: role `owner`, status `active`, `created_by = auth.uid()`. The client
  cannot supply owner_user_id / role / status / organization_id — there is no such
  parameter.
- Audit: existing `trg_audit_organizations` + `trg_audit_organization_members`
  triggers capture both rows with actor = auth.uid().

### 4.3 Subscription initialization
- A `subscriptions` row on the seeded `starter` plan (Phase 12 model) is created
  in the same transaction. No billing provider, no charges, no fabricated status —
  `max_sites: 3` enforcement (Phase 13) applies immediately.

### 4.4 First-site onboarding
- Owner lands on the dashboard; the Organization panel shows **"Add your first
  mining site"** when `sites.length === 0` (client hint, not a security gate).
- Creation goes through the EXISTING `site_create` RPC (`sites.create` permission
  + plan cap enforced server-side). No bypass.

### 4.5 Administrator invitation + member onboarding
- Unchanged Phase 04 flow: `org_send_invite` (sha256 one-time token, email-match
  accept) → `org_accept_invite`. Self-service membership INSERT remains limited to
  the user's own row in the inert `member/invited` state (no escalation possible).

### 4.6 Organization switching
- Users may hold memberships in many orgs (owner of A, safety manager of B,
  regulator role of G). The dashboard uses `MG_AUTH.resolveActiveOrg()`:
  - validates the stored preference against CURRENT active memberships;
  - falls back to first active owner/admin, then first active membership;
  - returns null when there are no active memberships.
- The selected org is UI state (`mg_selected_org`), NEVER a security boundary —
  every read/write is RLS-scoped by the session, so an unauthorized org id in
  localStorage grants nothing (verified by probe: outsider reads 0 rows).
- The switcher renders only when the user has >1 active membership; options are
  orgs the server already confirmed.

### 4.7 Ownership transfer
- RPC `org_transfer_ownership(p_organization_id, p_new_owner_user_id)`:
  - caller must be the CURRENT active owner (admins cannot seize);
  - target must be an active non-owner member of the SAME org;
  - atomic swap: target → owner, previous owner → admin (org is never ownerless);
  - self-transfer rejected; all changes audit-captured by the membership trigger.
- `org_update_member_role` continues to block re-roleing/removing owners.

### 4.8 Suspension / restoration / closure
- Platform-level: `platform_update_organization_status` (Phase 12, platform-scope
  role only) — audited. Org deletion cascades with audit retention (Phase 06 probe).

### 4.9 Membership removal
- `org_remove_member` (org admin) with owner protection; members can withdraw
  their own `invited` row (Phase 02 policies).

### 4.10 Logout
`MG_AUTH.signOut()` + dashboard `doLogout()`:
1. dashboard listeners detached (`detachAllListeners`);
2. sync engine context re-resolved on `mg-auth-change` (org cache dropped);
3. selected-org preference removed (`mg_selected_org`);
4. GoTrue remote logout (failures swallowed — local credentials are cleared
   regardless, so a failed remote logout cannot leave stale tokens);
5. session cache cleared; `notify(null)` fires the auth-change event;
6. UI returns to the login screen; protected data is hidden.
Passwords are never stored anywhere.

### 4.11 Session restoration
- `ensureSession()` refreshes expiring tokens (60 s margin) or rejects;
- restore path re-fetches memberships and revalidates the selected org against
  CURRENT active membership — removed members and stale org ids fail closed
  (server truth, not client cache);
- suspended users have no `active` membership → no dashboard entry.

## 5. Security boundaries (summary)

| Boundary | Enforcement |
|---|---|
| Tenant isolation | RLS on every table via membership helpers; org INSERT default-deny |
| Ownership | `auth.uid()`-derived inside SECURITY DEFINER RPCs only |
| Self-service creation | whitelist of commercial types; regulator/platform blocked |
| Membership escalation | self-INSERT only `member/invited`; admin RPCs owner/admin-gated; owner immutable except via transfer RPC |
| Slug | uniqueness enforced by DB index; never security-relevant |
| Audit | trigger-captured, append-only, actor = auth.uid() |

## 6. Verification

`scripts/verify-org-lifecycle.mjs` — 30/30 PASS, self-cleaning (catalog, happy
path, denials incl. forged owner/role/status, slug collision, duplicate name,
transfer rules + single-owner invariant, audit capture, tenant isolation,
first-site authorization). Wired into `scripts/run-all-probes.mjs` (`olc`).
