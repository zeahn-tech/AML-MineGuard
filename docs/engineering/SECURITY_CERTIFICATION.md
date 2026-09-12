# MineGuard Liberia — Security Certification (Phase 13)

| Field | Value |
|---|---|
| Doc status | LIVE — certification evidence for the Phase 13 hardening pass |
| Last updated | 2026-09-10 |
| Related | `SECURITY_MODEL.md` (controls), `RLS_MATRIX.md` (policy matrix), `TESTING_STRATEGY.md` (§5 scans), `PRODUCTION_READINESS.md` (checklist), `IMPLEMENTATION_STATUS.md` (per-phase evidence) |

This document records what has been **demonstrated** (with the producing artifact named), what is
**classified and accepted** (with rationale), and what remains **open**. Certification vocabulary:
`DEMONSTRATED` (automated artifact exists and last ran green) · `ACCEPTED` (residual risk with recorded
rationale + owner action) · `OPEN` (not yet built/verified). Nothing here claims third-party accreditation.

## 1. Control certification summary

| # | Control | Status | Evidence artifact |
|---|---|---|---|
| 1 | Real authentication (no hard-coded/localStorage credentials) | DEMONSTRATED | Phase 02 probes; Phase 13 scan rule `legacy hard-coded admin credential` (0 hits); `mineguard2024` purge in `supabase-auth.js` |
| 2 | Server-enforced tenant isolation, both directions, direct-API proven | DEMONSTRATED | `scripts/verify-phase04/06/07/08/09/10/11/12.mjs` cross-tenant matrices (0-row reads, 403 writes) |
| 3 | RBAC: granular permission catalog; self-promotion impossible | DEMONSTRATED | Phase 03 `verify-rbac.mjs` (30/30); Phase 02 membership RLS negative tests |
| 4 | Site-scoped least privilege (no transitive site access) | DEMONSTRATED | `verify-phase04.mjs` (58/58), `verify-phase06.mjs` site-scope matrix |
| 5 | Storage authorization resolves through row RLS (path knowledge grants nothing) | DEMONSTRATED | Phase 07 `verify-phase07.mjs` storage upload/download allowed+blocked matrix |
| 6 | Append-only, actor-pinned audit trail (trigger-sourced, client cannot write) | DEMONSTRATED | `verify-phase06.mjs` forged-INSERT 403 + actor checks; 21 audit triggers (Phase 06–12 migrations) |
| 7 | Government access = explicit grant records only; revocation immediate; expiry enforced | DEMONSTRATED | `verify-phase11.mjs` (48/48), `verify-phase12.mjs` expiry tests; Phase 13 `regulator_expire_due_grants` sweep |
| 8 | Grant/service lifecycle: forward-only emergency lifecycle, immutable identity pins | DEMONSTRATED | `verify-phase09.mjs` lifecycle + spoof-rejection matrix |
| 9 | Plan limits enforced server-side (`max_sites`) | DEMONSTRATED | Migration `…096` applied live 2026-09-10; `verify-phase13.mjs` 27/27 (cap denial + upgrade + no-subscription back-compat) |
| 10 | Offline mutations: idempotent, ordered, conflict-safe, never silently dropped | DEMONSTRATED | `verify-phase10.mjs` (14/14) running the real engine |
| 11 | Secret-leak scan in CI | DEMONSTRATED | `scripts/security-scan.mjs` (exit 1 on CRITICAL), wired into `npm test` |
| 12 | Sensitive schema/columns never mirrored into audit metadata | DEMONSTRATED | Probe assertions: invite tokens, incident body text, emergency message text — 0 leaks |
| 13 | Platform administration gated + audited (suspend/list/status) | DEMONSTRATED | `verify-phase12.mjs` platform gating + explicit P0001 denial |
| 14 | XSS audit on all render paths | DEMONSTRATED (static layer) | `scripts/xss-audit.mjs` (2026-09-10): 63 HTML sink statements across all 8 client render files audited; every dynamic interpolation escaped (`escHtml`/`escapeHtml`) or allowlisted as reviewed-safe (static data.js fields, numeric bars, fixed-literal ternaries); ~30 genuine escapes added in admin.html/app.js/notices.js (JSA tasks, worker names, badges, locations, descriptions, witnesses, contact names/numbers, filters, photo src/onclick, statuses, deletedBy). Wired into `npm test` (fails closed). Dynamic adversarial-input testing (feeding XSS payloads through the running app) remains an E2E-layer item |
| 15 | Rate limiting on write endpoints | OPEN | Not built (PostgREST/Supabase-level concern; record as deployment action) |
| 16 | MFA for admin/government roles | OPEN | Not built (Supabase Auth supports it; enablement + policy work outstanding) |
| 17 | Media re-encode on ingest | OPEN | Client-side compression exists; server-side re-encode not built |

## 2. Secrets incident (found + remediated Phase 13, rotation REQUIRED)

`scripts/run-probes.sh` previously hard-coded, committed to git:

1. **Supabase service-role JWT** — full database bypass, RLS-blind. Worst-case exposure.
2. **Supabase DB password** (`postgresql://postgres:<password>@db.…`).

Remediation in repo: both removed from the file; the runner now requires env-injected credentials
(`SUPABASE_ACCESS_TOKEN`, public keys from `config.js`); the Phase 13 scan permanently rejects this
pattern class (service-role JWTs, `sbp_` tokens, postgres URLs with passwords).

**REQUIRED USER ACTIONS (cannot be done from the repo):**

- [ ] **Rotate the service-role JWT** — Supabase Dashboard → Project Settings → API → rotate
      `service_role` key. The old JWT remains valid until rotated and lives in git history.
- [ ] **Rotate the DB password** — Project Settings → Database → reset password.
- [ ] Consider the access-token (`sbp_…`) rotation cadence; they were pasted in chat previously and
      should be treated as compromised-by-exposure even though they were never committed.
- [ ] If history scrubbing is required for government adoption, plan a history rewrite + force-push
      (destructive; owner decision — not executed here per repo policy).

## 3. Accepted residual risks (classified)

| Risk | Class | Rationale / action |
|---|---|---|
| Firebase WEB API key in 4 legacy files | ACCEPTED (HIGH) | Public-by-design Firebase web config (same class as Supabase publishable anon key). Action: enforce HTTP-referrer + API restrictions and lock Firestore rules in the Firebase console (C7). CRITICAL if it ever appears in a new file — the scan enforces this. |
| Probe-account password `MgProbePass!2026` in scripts | ACCEPTED (HIGH) | Throwaway users created+deleted by self-cleaning probes against the dev project; not deployment secrets. Note: dev project only — production project must not share this convention. |
| `config.js` publishable URL/anon key in client | ACCEPTED (INFO) | RLS is the security boundary by architecture (ADR-008). |
| Legacy anonymous Firestore channel still serves worker flows | ACCEPTED (HIGH, known) | Dual-read window documented since Phase 05; closes at Phase 05 cutover. Highest-priority residual risk in the platform. |

## 4. Certification gates (what stands between COMPLETE and production candidate)

Per `PRODUCTION_READINESS.md` (authoritative checklist):

1. ~~Pending live verification~~ **DONE 2026-09-10:** migration `…096` applied; `verify-phase13.mjs`
   27/27 PASS self-cleaning; full regression (04/06/06c/07/08/09/10/11/12) all-PASS.
2. **Credential rotations in §2** must be executed and logged here — STILL OPEN (user action).
3. `auth.site_url` must point at the production origin before inviting real users (recorded since Phase 02).
4. Open control rows in §1 (dynamic XSS E2E payloads, rate limiting, MFA enablement, media re-encode)
   before the "production candidate" definition in `PRODUCTION_READINESS.md` is satisfied. (The static
   XSS render-path audit is DONE and CI-wired; see §1 row 14.)
5. Wire `npm test` into CI so probe evidence becomes VERIFIED-tier.

## 5. Scan baseline (2026-09-10)

`node scripts/security-scan.mjs` → **0 CRITICAL, 16 HIGH** (4 classified Firebase web-key sites +
12 classified probe-password sites; each carries its rationale inline in the scanner). CRITICAL rules:
service-role JWT, `sbp_` access tokens, private keys, postgres URLs with passwords, `mineguard2024`
legacy credential, out-of-place API keys. Exit code 1 on any CRITICAL → `npm test` fails closed.
