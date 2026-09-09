# MineGuard Liberia — Emergency Response Architecture

| Field | Value |
|---|---|
| Doc status | BASELINE + **Phase 09 LANDED + LIVE-VERIFIED (2026-09-04, project `vuniwebbrvpgxscdsfei`)**: §2 entities + lifecycle + RLS implemented (`…080` + fixes `…081`–`…084`; `verify-phase09.mjs` all-PASS). Notifications/offline fan-out remain Phase 10 (offline-first sync) + push integration (Phase 09+/13). |
| Last updated | 2026-09-03 |

## 1. Current SOS implementation (as-built)

- **Activation**: admin dashboard modal (category, message, site) writes an `emergency_sos` doc
  (`active: true`, `startedAt`, `activatedBy`, …) via REST; local state mirrors in `mineguard_sos_state`;
  audit entry appended to localStorage `mineguard_sos_audit_log` (per-device).
- **Delivery**: SW polls `emergency_sos` (REST, API key) and shows a local notification for the latest
  non-deleted doc with `active: true`; app-side poll every ~5 s + `BroadcastChannel` for same-device tabs;
  full-screen overlay, vibration, siren tone, "acknowledge" button that appends to the `acknowledgements`
  array (device/name string) and updates the doc.
- **Lifecycle**: boolean `active` only; deactivation from admin updates the doc. There is no event/state
  machine, no responders list, no escalation, no containment, no per-user acknowledgements (device-only),
  no location data, no after-action record, no linkage to incidents.
- **Offline**: activation while offline is stored locally with no retry path (see OFFLINE_SYNC §1).
- **Security**: any client with the API key can POST an `active` SOS doc or edit/deactivate any doc —
  spoofed or silenced emergency alerts are possible (SECURITY_MODEL C2/C3).
- **Scale**: every device that has ever opened the app (regardless of site/org) is notified of any active SOS.

## 2. Target emergency event system (Phase 09)

### 2.1 Entities (org-scoped)
- `emergency_events` — id, orgId, siteId, type (e.g. fire, rockfall, blast incident, medical, gas, flood,
  missing person, security), severity, status, activatedBy (user), activatedAt, exact/approximate location,
  affectedArea, message, responder assignments, resolution + after-action report refs.
- `emergency_acknowledgements` — eventId, userId, at, note, channel (app/SW notification/SMS/voice when
  added).
- `emergency_escalations` — eventId, level, escalatedTo (role/team/user), at, reason, by.
- `emergency_responders` — eventId, responder (user/team), role, status (dispatched/arrived/…).
- `emergency_log` — append-only event stream (activate/ack/respond/escalate/contain/resolve/close) for the
  audit trail; mirrors sensitive ops into `audit_log`.

### 2.2 Lifecycle
ACTIVATED → ACKNOWLEDGED → RESPONDING → CONTAINED → RESOLVED → CLOSED, with server-side transition
validation (e.g., CLOSED requires resolution record and after-action note; escalation rules per org policy).
Status is derived from event state, not client booleans.

### 2.3 Flow
1. Activation from a worker device or console: only users with `emergency.activate` for that org/site;
   server validates org/site scope; event recorded; realtime + push fan-out **scoped to org/site targets**.
2. Targeted audience per event (site + response teams + on-call roles) — not every device globally.
3. Responders acknowledge (per-user identity) and updates flow to the command view (who is acknowledged,
   outstanding, escalated).
4. Escalation: configurable rules/timeouts (e.g., unacknowledged critical after N minutes → escalate to
   site manager → org admin; government portal option per org policy).
5. Containment/resolution/closure: authorized roles with audit; after-action report attached at closure.

### 2.4 Notifications
- Push (server-managed device subscriptions, org-scoped topics) + SW notification actions (Open/Acknowledge
  → authenticated ack), plus in-app realtime. Background delivery via SW periodic/sync where push is
  unavailable; SMS/call channels are Phase 09+ integrations (see integrations note in SESSION_HANDOFF).

### 2.5 Offline behavior (explicit)
- Offline activation: create event locally with `clientId` + high-priority outbox entry; full-screen
  confirmation + "waiting to send"; auto-flush on reconnect; idempotent server upsert (no duplicate events).
- Offline acknowledgement: queued with `clientId`; device shows "acknowledged, pending sync".
- Responder view caching: site emergency contact list + procedures (static data.js) already offline; active
  event state cached locally and refreshed on connect.
- Designed and tested scenarios: activation offline → reconnect; ack offline → reconnect; two devices acking
  concurrently; failed send retry; escalation during disconnect.

### 2.6 Incident linkage & audit
Emergency events can link to incidents created during/after the event (reporter may later attach photos/
statements). Every lifecycle transition and acknowledgement is written to `emergency_log` + `audit_log`
(actor/org/resource/ts/metadata); audit records are server-written and append-only (SECURITY_MODEL §2.6).
