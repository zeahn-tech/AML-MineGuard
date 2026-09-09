# MineGuard Liberia — Migration Plan

| Field | Value |
|---|---|
| Doc status | PLAN (Phase 05). Phase 05 prep executed session 8: read-only inventory + mapping/validation baseline (gitignored). **Session 9 (2026-09-03): Phase 06 enforcement suite GREEN** (satisfies gate §7(4)). **Session 10 (2026-09-04): incident + evidence target tables now LIVE** (migrations `…060`/`…061` applied; `verify-phase07.mjs` all-PASS). **Session 11 (2026-09-04): JSA/inspections/CAPA target tables LIVE** (`…070`–`…073`; `verify-phase08.mjs` all-PASS). **Session 12 (2026-09-04): emergency/SOS target tables LIVE** (`…080` + fixes `…081`–`…084`; `verify-phase09.mjs` all-PASS; Phase 06/07/08 regression green). Remaining cutover gates: durable user-owned Firestore export (ADR-003), remaining safety-domain target tables (notices, documents — Phase 10+), and org-owner review sign-off. |
| Last updated | 2026-09-04 (session 12) |

## 0. Rule

Do not destroy the current data model first. Order: **backup → document → map → migrate → validate → test →
keep rollback → only then remove obsolete structures.** AML/Nimba data becomes **tenant #1**, never a
hard-coded special case.

## 1. Existing data (source of truth = Firestore project `aml-mineguard`)

Volume measured 2026-09-03 (session 8) by `scripts/phase05-inventory.mjs` — a read-only `:runQuery`
inventory over the exact anonymous channel the shipped app uses (same project/key as `firebase.js`),
snapshot stored under `supabase/legacy-inventory/` (gitignored; sha256 manifest.json + report.json).
The snapshot is NOT the durable backup — a user-owned console export with an off-repo copy (ADR-003)
is still required before cutover.

| Source collection | Volume (measured) | Key fields |
|---|---|---|
| `incidents` | **4 docs** (2 soft-deleted) · 2026-07-11 → 2026-08-29 · 19 fields · 4 docs carry `photos` (2 empty arrays; 5 embedded data-URL JPEGs ≈ 881 KB decoded / ~1.17 MB base64) | name, badge, dept, datetime, location, type, severity, description, action, witnesses, photos(dataURL base64[]), status, savedAt, createdAt(ms), deleted*, resolvedAt |
| `jsas` | **4 docs** (3 soft-deleted) · 2026-07-05 → 2026-07-08 · 13 fields · 4 distinct locations (Rampard, Concentrator, WBHO Sites, Bench 12) | worker, task, location, date, hazards[{hazard,risk,control}], ppeSelected[], supervisor, savedAt, createdAt(ms), deleted* |
| `notices` | **12 docs** (10 soft-deleted) · 2026-07-04 → 2026-07-25 · 16 fields · workZone values: Tokadeh Mine (6), Uritton (5), Tokadeh (1) | title, message, type, target, workZone, createdBy, pinned, sendPush, expires, scheduledFor, createdAt(ms), readCount, ackCount, deleted*, noticeId |
| `emergency_sos` | **7 docs** (0 soft-deleted) · 2026-07-15 → 2026-07-16 · 20 fields · 7 distinct `startedAt` (each snapshot = one activation; all category Fire, site "Nimba Mine", activatedBy "admin") | snapshots: active, category, message, site, activatedBy, startedAt(ms), acknowledgements[], acknowledgedWorkers, notifiedWorkers, endedBy, deactivatedAt, durationSeconds, logs[], deleted* |
| `audit_log` | **64 docs** · 2026-06-21 → 2026-07-25 · 6 fields · actions: delete 35 / purge 16 / restore 13 · 50 rows reference docs already hard-purged from the current snapshot (expected; imported for history with `legacy_import: true`) | action, collection, docId, adminUser, timestamp, createdAt(ms) |

Plus per-device localStorage datasets (mineguard_incidents/jsas/notices, sos state/log, read/ack sets,
mg_* settings/identity) — device data migrated by the in-app upgrade flow (see §5), not centrally.

## 2. Target schema (see DATABASE_ARCHITECTURE.md §2)

## 3. Field/record mapping

| Source → Target | Mapping notes |
|---|---|
| `incidents` → `incidents` (org-scoped) | orgId = seeded AML org id; siteId ← text match against seeded sites ('Nimba Mine' defaults) else 'Unassigned' + flag list for human review; dept → department ref when resolvable (text index), else store legacy text; name/badge → worker ref when resolvable (profile seeded from distinct names), keep reporter display fields; photos → extract base64 → object storage → `incident_evidence` refs (batch job with size checks); status open→SUBMITTED (or map resolved→RESOLVED); keep original savedAt/createdAt; attach `clientId`=legacy _id where unique. |
| `jsas` → `jsas` | Same org/site/dept resolution; hazards[] array of {hazard, risk, control} → jsa steps with likelihood/severity unknown → NULL + review list (no invented scores); supervisor → ref or text; status SUBMITTED (no approvals existed). |
| `notices` → `notices` (+`notice_acks`) | org/site scope; createdBy text kept + user resolution attempt; target `all` → org-wide; read/ack counts → imported as baseline counters only if per-user ack records cannot be reconstructed (legacy counts were racy) — record that decision. |
| `emergency_sos` → `emergency_events` + `emergency_log` | Latest non-deleted snapshot per (startedAt) → event with status from active/endedBy; acknowledgements (device strings) → acknowledgement records with legacy note; log entries reconstructed from audit snapshots where available. |
| `audit_log` → `audit_log` (org-scoped, append-only) | Imported with legacy actor strings; flagged in a `legacy_import: true` metadata field; not treated as tamper-proof evidence. |
| Static content | Glossary/PPE/contacts/tips + EN/FR strings import unchanged as seed content/config. |

## 4. Order of operations (Phase 05; subject to Phase 01 decisions)

1. **Backup**: export all 5 collections (and any others found in console) to durable storage; checksums +
   two copies; verify export counts. Also snapshot per-device localStorage design doc + migration capture
   script for in-app upgrade.
2. Seed platform data: org #1 (ArcelorMittal Liberia), sites (Nimba Mine, Port Operations + console-derived
   locations), departments from text analysis, admin/system users (with real auth — Phase 02 precedes 05).
3. Build mapping + import scripts (idempotent, restartable, dry-run mode) and a **validation report**:
   record counts per collection, per-org counts, null/required violations, orphan refs, photo extraction
   failures.
4. Validate: sample N records per collection; verify photos open; verify legacy timestamps preserved.
5. Cutover: gate new writes (identity + org scope) at Phase 01/02 already; migrate readers (new clients read
   new model); dual-read window while legacy app remains for rollback; monitor error rates.
6. Retire legacy model only after rollback window passes with zero unresolved issues; delete legacy
   collections after explicit approval + final backup.

## 5. Device (localStorage) migration

In-app upgrade flow (Phase 10/05): detect legacy keys → export JSON → migrate to structured local store with
new schema + clientIds → dedupe against cloud by savedAt/clientId heuristics → mark legacy keys archived →
report counts to the user. Never delete legacy keys until user confirms migrated data looks right.

## 6. Rollback & backup strategy

- Rollback = restore from Phase 05 backups + stop new-schema writes (feature-flag); dual-read window above.
- Backups: automated scheduled export of the tenant database + object storage snapshots + daily incremental;
  restore drills documented and executed per PRODUCTION_READINESS.md §DR before Phase 05 cutover.
- Data retention: soft-deleted records retained per org policy; audit_log append-only retention policy set.

## 7. Cutover plan

Timeline gates: Phase 02 auth live → Phase 03 RBAC → Phase 04 hierarchy seeded → Phase 06 enforcement tests
green (tenant-isolation suite) — **✅ GREEN 2026-09-03 (session 9): `scripts/verify-phase06.mjs`
(RLS/audit probe) + `scripts/verify-phase06-cascade.mjs` (org cascade-delete + audit retention) all-PASS
on `vuniwebbrvpgxscdsfei`** → Phase 07 incident/evidence target tables live (✅ 2026-09-04, session 10:
migrations `…060`/`…061` applied, `verify-phase07.mjs` all-PASS; Phase 06 regression green) →
Phase 08 JSA/inspection/CAPA tables live (✅ session 11: `…070`–`…073`, `verify-phase08.mjs` all-PASS) →
Phase 09 emergency/SOS tables live (✅ session 12: `…080`–`…084`, `verify-phase09.mjs` all-PASS;
Phase 06/07/08 regression green) →
Phase 10+ notices/documents target tables →
Phase 05 import dry-run → validation report sign-off → cutover →
regression run of preserved features (glossary/PPE/JSA/incidents/notices/SOS/analytics/CSV/restore/audit/
i18n/offline install).

## 8. Execution status (Phase 05, session 8 — 2026-09-03)

**Implemented (prep only; zero database writes):**

- `scripts/phase05-inventory.mjs` — read-only Firestore inventory (all 5 collections, paged, retried on
  429, sha256 manifest). Bug fixed this session (vocab buckets + photo-retention change): photo payloads
  are now RETAINED whole in the snapshot (~1.2 MB total) so mapping can hash/type/export them; only
  pathological fields ≥ 8 MB get stripped. Run: `node scripts/phase05-inventory.mjs`.
- `scripts/phase05-map.mjs` — pure, offline, deterministic, restartable mapper (no network, no DB):
  consumes the snapshot, applies the §3 field mapping under tenant #1 (`arcelormittal-liberia`) with
  seeded-site resolution, and emits under `supabase/migration-prep/` (gitignored):
  - `payloads/{incidents,jsas,notices,emergency_events,audit_log}.ndjson` — target-shaped rows, each with
    `client_id` (legacy Firestore doc id) for idempotent apply, org/site slugs for apply-time FK
    resolution, preserved legacy `createdAt`/`savedAt`, soft-delete flags, and `legacy_*`/`*_text` fields
    where the source has no target equivalent (no silent guesses);
  - `photos.manifest.ndjson` — 5 rows (image/jpeg, decoded sha256 + bytes + suggested storage key
    `organizations/arcelormittal-liberia/sites/<slug|unassigned>/incidents/<client_id>/<i>.jpg`) — the
    Phase 07 object-storage upload work queue;
  - `mapping-report.json` — validation report (MIGRATION_PLAN §4.3 baseline) and
  - `review-lists.json` — 29 human-decision items in 4 groups + 7 proposed worker profiles + 2 proposed
    department units; decisions are recorded in `overrides.json` and re-runs are deterministic
    (payloads byte-identical across runs, verified).

**Validation evidence (recorded output, all PASS):** source counts equal inventory counts for all 5
collections (4/4/12/64/7); target rows 91 = 91 source docs; required-field violations 0; photo manifest 5
rows ≈ 881 KB decoded; audit orphans 50 (delete 25 / purge 16 / restore 9 — reference purged docs,
expected); 100% createdAt coverage on every collection; every legacy `deleted` flag preserved
(incidents 2, jsas 3, notices 10 soft-deleted imported as deleted).

**Findings the mapper refuses to guess (in review-lists.json):**
- Site/zone vocabulary does NOT match the seeded sites (Nimba Mine / Port Operations): incident/jsa
  locations Lower Gangra, Bench 6, Pit 3, Rampard, Concentrator, WBHO Sites, Bench 12 and notice
  workZones Tokadeh Mine / Uritton / Tokadeh → all flagged; org owner decides mapping or new site seeds.
- Worker badge hygiene: Nohama Dola carries AML-34 on one doc and AML-56 on another; John Sebah also
  carries AML-34 (possible badge collision); jsas-only workers (Hama Garmu, Lamapa King, John Blame,
  John Brown) have no badge → 5 review items; 7 proposed worker profiles.
- JSA supervisors (Officers, Saftey Manager, Safety Officer, Lama Brown) and incident witnesses (Tom
  Brady, Hoffa, Great, …) are free text; linked identities are Phase 05 apply-time decisions.

**Still required before any import/cutover:** (1) the durable user-owned Firestore export with a second
copy off-repo (ADR-003); (2) target safety-domain tables + RLS (Phases 06–09 create them — payloads were
validated against the documented target shape, not a live table); (3) org-owner sign-off on
`review-lists.json` answers via `overrides.json`; (4) Phase 06 tenant-isolation suite green per §7.
