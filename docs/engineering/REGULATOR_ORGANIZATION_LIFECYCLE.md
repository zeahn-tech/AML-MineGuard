# MineGuard Liberia — Regulator Organization Lifecycle

| Field | Value |
|---|---|
| Doc status | AS-BUILT (session 20, 2026-09-12): regulator claim/provision remediation implemented and live-verified (`scripts/verify-regulator-lifecycle.mjs` 33/33 PASS, self-cleaning; catalog reseed fidelity-verified) |
| Last updated | 2026-09-12 |
| Related | `ORGANIZATION_LIFECYCLE.md`, `GOVERNMENT_PLATFORM.md`, `RBAC_MODEL.md`, `SECURITY_MODEL.md`, `IMPLEMENTATION_STATUS.md` |

## 1. Purpose of regulator organizations

A regulator organization (`org_type = 'regulator'`) is the government tenant of the
platform: the national regulatory authority that oversees mining companies. It is
fundamentally different from commercial tenants:

```text
COMMERCIAL ORGANIZATION (mining_company / contractor / service_provider)
        ↓ self-service: authenticated user → create_organization() → owner

REGULATOR ORGANIZATION (regulator)
        ↓ controlled: platform admin provisions; a memberless regulator org is
          claimable exactly once by a brand-new (orgless) authenticated user

PLATFORM ORGANIZATION (platform)
        ↓ highly restricted: one-shot platform bootstrap only (Phase 12)
```

## 2. Root cause of the original "button does nothing" defect

The "Claim Regulator Organization" button in the government/bootstrap view reported
results through `statusLine()`, which writes to `el("govStatus")` — an element that
only exists inside `renderPanel()` (the regulator command-center view). In the
bootstrap view the node does not exist, so **every outcome (success or failure) was
invisible**: the classic silent no-op. Server-side, the RPC surface
(`bootstrap_first_regulator_admin`, Phase 11 `…090`, guarded in `…091`) was functional
but starved of claimable orgs, and the error message surfaced nowhere.

## 3. Final lifecycle

```text
NOT PROVISIONED
      ↓ provision_regulator_organization(p_name, p_county)   [platform admin only]
PROVISIONED (active, zero members, no subscription)
      ↓ bootstrap_first_regulator_admin()                    [orgless user, one-shot]
ACTIVE (first official = national_regulatory_admin)
      ↓ further officials via regulator role management / invitations
ACTIVE
      ↓ platform admin (suspend/restore) or archive
SUSPENDED / ARCHIVED   (suspended orgs are never claimable)
```

Invariants (server-enforced):

- **Max one active regulator org** — `organizations_single_active_regulator_uidx`
  (partial unique index on `org_type='regulator' AND status='active'`), plus an
  in-RPC pre-check. Duplicate provisioning is rejected (HTTP 400).
- **Provisioned regulator orgs start empty** — no owner, no commercial subscription.
  Onboarding happens exclusively through the claim/role paths.
- **One-shot claim** — `bootstrap_first_regulator_admin()` (…090 as guarded by …091):
  the caller must hold **zero** active organization memberships ("caller already
  holds an active organization membership…" denial otherwise); it claims the first
  memberless active regulator org by `created_at` (`for update skip locked`) and
  assigns `national_regulatory_admin`/`active`. Role is server-set — never
  client-supplied.
- **Suspension blocks claims** — suspended orgs are excluded from the claimable
  query and the claim RPC denies against them.

## 4. Provisioning authorization (who can provision)

`provision_regulator_organization(p_name, p_county)` (migration `…100`,
SECURITY DEFINER, fixed `search_path`):

1. Session required (`auth.uid()` — anonymous → 401).
2. Caller must be an authorized platform administrator: an **active membership in
   an active platform org holding a `platform`-scoped role** (resolved via the RBAC
   catalog `roles.scope`; actor is always `auth.uid()`, never a client argument).
3. Name validation (1–120 chars), server-generated collision-safe slug, server
   UUID/timestamps.
4. Atomic: org insert + audit in one transaction; `org_type='regulator'` and
   `status='active'` are server-set constants — a caller cannot steer them.

All non-authorized callers (orgless users, commercial owners, anonymous) are denied
before any row is written.

## 5. Membership lifecycle (government roles)

Roles used inside a regulator org (existing Phase 03 catalog — none invented):

| Role | Purpose |
|---|---|
| `national_regulatory_admin` | Configures the regulator org; manages inspector accounts and grants |
| `government_safety_inspector` | Conducts inspections, reviews authorized org data |
| `government_compliance_officer` | Monitors compliance/notices/CAPAs on authorized orgs |
| `government_analyst` | Read-only national analytics |

- First official: the claim (above) → `national_regulatory_admin`.
- Subsequent officials: regulator-admin invitation / `org_add_member` role
  management (existing Phase 04+ paths) — never self-service elevation. The
  `organization_members_role_check` constraint (extended by `…092` for government
  roles and `…101` for platform roles) whitelists values; assignability is governed
  by RPC authorization + RLS, not the constraint alone.
- Membership transitions (created/activated/removed) are captured by the existing
  `organization_members` append-only audit trigger.

## 6. RLS / security model

- RLS stays enabled on every table; **no policy was weakened or removed** in this
  remediation.
- `organization_members` INSERT remains default-deny for direct writes: probe-verified
  `403` on a forged direct INSERT of a regulator membership.
- The regulator does NOT gain blanket tenant visibility by existing: cross-tenant
  oversight requires an explicit `government_grants` authorization (Phase 11).
  Probe-verified: a regulator member sees **0** incidents/organizations of a target
  company without a grant.
- The claim/provision RPCs are the only write surfaces; both derive the actor from
  `auth.uid()` and take no client-controlled user/role/org-id that could steer
  privilege.

## 7. Audit logging

Captured by the existing append-only `audit_log` triggers (verified in probe):
`organizations.insert` (provisioning), `organizations.update` (status changes),
`organization_members.insert` (claim / role assignment, includes actor + role).
Claim denials are observable client-side (explicit message) and server-side via the
raised exceptions. No secrets or tokens are written to audit metadata.

## 8. Client UX (gov-admin.js / org-admin.js)

- `regulatorClaimStatus()` TVF wrapper (`supabase-auth.js`) resolves state from the
  **server** before any button is offered: `none_provisioned` / `claimable` /
  `already_claimed` / (suspended → none). The claim surface renders the matching
  state — a button that is guaranteed to fail is not shown.
- Claim flow: state check → **confirmation modal** (organization name shown) →
  loading state → RPC → inline result. Success, already-claimed, not-authorized,
  no-eligible-org, session-expired, and unexpected-error outcomes all render a
  human-readable message in the claim surface (silent no-op eliminated; technical
  detail logged to console, raw internals never shown).
- Organization panel (`org-admin.js`): regulator orgs render as **Government
  Regulator** with regulator-appropriate actions; commercial-only actions are not
  offered to regulator users. Organization switching continues to use the
  membership-validated `resolveActiveOrg` model (no `list[0]`).

## 9. RBAC catalog restoration (…102)

Forensic finding during authorization wiring: the catalog tables `roles`,
`permissions`, `role_permissions`, `plans` were **empty on the live project** (schema
intact, data rows gone — likely from earlier ad-hoc live SQL), which silently broke
every permission-gated surface. Migration `…102` re-inserted all rows **verbatim**
from the authoritative seed blocks (`…030` §1–§3, `…073` §1 additions, `…094` plans):

- 16 roles (3 platform + 4 government + 9 organization), 62 permissions, 3 plans,
  428 role→permission bundles.
- Fidelity tool: `scripts/check-reseed-fidelity.mjs` — block-scoped exact-set
  comparison against the source migrations → **PASS** before apply.
- Live verification: counts match; no duplicate codes; owner bundle = 62;
  `national_regulatory_admin` bundle = 22.

## 10. Testing

`scripts/verify-regulator-lifecycle.mjs` — **33/33 PASS**, self-cleaning:

- static: server-driven claim state, inline result reporting, confirmation modal,
  wrapper wiring, SW cache bump
- provisioning: platform-admin success; orgless/commercial-owner/anonymous denials;
  duplicate prevention; no owner membership; no commercial subscription; server-set
  type/status; non-regulator type impossible
- claim: claimable → success (role/status server-set); second claim denied; member
  caller denied (orgless-only guard, with 504 retry); already_claimed state;
  suspended org never claimable + claim denied
- forgery: direct membership INSERT 403; no alternative RPC surface (404); forged
  named args to the 0-arg RPC rejected (404/400 — no client-controlled identity)
- audit: `organizations.insert` + `organization_members.insert` captured
- isolation: 0 target-org incidents / organizations without a grant

Regression (all live, self-cleaning): phase 04, 06, 06-cascade, 07, 08, 09, 10, 11
(48/48 after fixture de-seeding), 12 (31/31), 13 (27/27), org-lifecycle (30/30),
auth-gate (21/21), org-lifecycle re-run idempotent. `security-scan` 0 CRITICAL /
16 classified HIGH (baseline); `xss-audit` clean.

## 11. Known limitations

- There is **no platform-admin UI console** yet; provisioning is executed by a
  platform-role holder via the RPC (probe/API-level), as recorded in Phase 12.
- Claim eligibility is intentionally narrow (orgless users only). Government users
  who already belong to another org must be onboarded by a regulator admin
  (invitation/role management) — by design, not a gap.
- `service_provider` orgs share the commercial self-service path; no
  regulator-specific distinction beyond `org_type` exists for them (none required).
- The regulator claim TVF exposes only the first claimable org; if multiple
  memberless regulator orgs ever exist (currently impossible for active ones due to
  the unique index), the older org wins deterministically by `created_at`.
