# MineGuard Liberia — Offline Sync Architecture

| Field | Value |
|---|---|
| Doc status | BASELINE: current behavior (weak) + target design (Phase 10) |
| Last updated | 2026-09-03 |

## 1. Current offline behavior (as-built)

- **Shell**: service worker (`sw.js`) caches both pages and all static assets; navigation falls back to the
  cached page; Firestore traffic always goes to network (correct — must never be cached as a read store
  without authorization).
- **Data store**: localStorage keys `mineguard_incidents`, `mineguard_jsas`, `mineguard_notices`,
  `mineguard_sos_state`, `mineguard_sos_latest`, `mineguard_sos_audit_log`,
  `mineguard_sos_registered_workers`, `mineguard_notices_read`, `mineguard_notices_ack`, `mg_worker_*`,
  `mg_admin_*`, `mineguard_lang`.
- **Write path**: optimistic localStorage write → connectivity probe (`MG.ready`, up to 6 s) → if online,
  REST write + `_id` back-patch matched by heuristic (incidents: `savedAt`+`name`; JSAs: `savedAt`+`worker`
  +`task`; notices: `createdAt`+`title`). If offline → **no queued retry**; banner says "will sync when
  online" but no mechanism exists. Reconnect events only re-probe connectivity.
- **Read path**: cloud first when online (whole collection, limit ≤500), localStorage otherwise; admin
  merges local photos over cloud copies when local count is higher.
- **Connectivity**: REST probe on load + `online`/`offline` events; `MG.online` global + banner states
  (syncing/synced/offline); connectivity custom event.

### 1.1 Weaknesses (evidence)

1. Offline-created records never reach the cloud unless created during a later online session by the same
   flow — **silent loss** for data safety (violates product requirement §22).
2. No idempotency: retry (e.g., user taps Save twice) duplicates; the back-patch heuristic matches on
   non-unique keys (same name + same second timestamps, common for repeated quick reports).
3. localStorage quotas (~5 MB typical) with base64 photos; multi-photo incidents + notice cache approach the
   limit; a `QuotaExceededError` on the big write can drop the whole key.
4. localStorage is per-device and XSS-readable; clearing site data destroys "history".
5. No conflict handling (same incident edited on two devices), no ordering guarantee, no sync-state machine
   per record, no queue observability.
6. "Registered workers" count = size of a per-device array ≥ 1 → dashboard stats are fiction.

## 2. Target offline-first architecture (Phase 10)

### 2.1 Local database
Replace localStorage-as-database with a structured local store (IndexedDB-backed) with object stores:

- `outbox` (pending mutations), `records_*` (per-domain cached views: incidents, jsas, notices, emergency,
  references), `sync_meta` (per-record sync state, lastSynced cursors), `attachments` (pending photo/video
  blobs + metadata), `kv` (settings/preferences only — never credentials, never authoritative data).

### 2.2 Sync queue & retry
- Every create/update enqueues a mutation `{id (uuid), entity, op, payload, createdAt, attempts, nextAttemptAt}`.
- A sync engine (frontend + SW background sync where available) drains the queue FIFO with exponential
  backoff and a max attempt cap → surfaced to the user as "upload failed — retry" (never silent).
- Queue persistence survives reloads; sync runs on `online` events, SW `sync` events, and app foreground.

### 2.3 Idempotency & duplicate prevention
- Client-generated stable record IDs (uuid) written into every entity (`clientId`), sent with mutations;
  server upserts on `clientId` — retries cannot duplicate incidents/JSAs/SOS activations.
- Server dedupe window + unique index on `(orgId, clientId)`.

### 2.4 Conflict handling
- Every record carries `updatedAt` + `updatedBy`; server compares and either applies last-write-wins (with
  explicit banner for low-risk fields) or creates a conflict copy requiring a human decision for
  safety-critical entities (incident status, CAPA closure, emergency state) — never silent overwrite of
  safety data.

### 2.5 Connectivity detection
- Keep `online/offline` + REST probe; add periodic lightweight heartbeat; derive sync state per record:
  `pending → syncing → synced | failed | conflict`; UI shows global + per-item sync indicators.

### 2.6 Synchronization states
Per record: `LOCAL_ONLY` (queued) → `SYNCING` → `SYNCED`; failures enter `ERROR` with retry; conflicts enter
`CONFLICT`. Emergency events have a dedicated high-priority queue flushed first, and SOS activation while
offline is stored locally + marked for immediate push on reconnect (never "dropped because offline").

### 2.7 Attachment synchronization
- Photos/videos stored as blobs in IndexedDB, uploaded to object storage via resumable/retryable uploads
  with idempotency keys; DB records hold storage refs; the old "drop photos to fit a Firestore doc" behavior
  is eliminated; sync state per attachment; offline capture never reduces evidence below what the device
  captured (today's behavior can drop photos from cloud silently).

### 2.8 Migration note
Existing localStorage datasets must be exported/migrated once per device during Phase 10/05 upgrade flow
(localStorage → IndexedDB with new schema + clientId backfill). See `MIGRATION_PLAN.md` §device data.
