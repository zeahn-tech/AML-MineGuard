# MineGuard Liberia — Database Architecture

| Field | Value |
|---|---|
| Doc status | BASELINE + TARGET (decided 2026-09-03: target database = Supabase PostgreSQL, ADR-008). Phases 01–04 schema live. Phase 06 live: RLS enforcement + `audit_log` + audit triggers on 7 tenant-management tables + sites (migrations `…050`–`…053`). Phase 07 live: incidents/evidence/witnesses + storage bucket + 3 safety-domain audit triggers (10 total) — `…060`/`…061`. Phase 08 live: jsas/jsa_steps + inspections + corrective_actions + 2 audit triggers (14 total) + fix migrations `…072`/`…073`. Phase 09 live: emergency/SOS tables + 5 audit triggers (19 total) + fixes `…081`–`…084` — live-verified (`verify-phase09.mjs` all-PASS). Phase 11 live: `government_grants` (explicit regulator authorization; partial unique active-grant index) + 4 helpers + 4 RPCs + 16 grant-gated regulator SELECT policies + `government_grants` audit trigger (20 total) + fixes `…091`–`…093` — live-verified (`verify-phase11.mjs` 48/48 PASS). |
| Last updated | 2026-09-09 |

---

## 1. Current database model (Firestore project `aml-mineguard`)

Flat top-level collections, **no `organization_id`, no `user_id` scope, no subcollections, no server-side
tenant boundary**. Documents are written with `restAdd` and ordered by `createdAt` DESC. Soft delete is the
flag `deleted: true` (+ `deletedAt`, `deletedBy`); hard deletes exist via DELETE.

### 1.1 Collections and fields (as observed in code)

**`incidents`** — every incident from every site/device in one pool:
`name` (worker full name — PII), `badge`, `dept`, `datetime`, `location`, `type`, `severity`
(low/medium/high/critical), `description`, `action` (immediate actions), `witnesses`, `photos`
(base64[]; ≤3, dropped to fit doc size), `status` (`open`; admin can set e.g. resolved via
`updateIncidentStatus`), `savedAt`, `lang`, `createdAt`, `deleted`, `deletedAt`, `deletedBy`,
`resolvedAt`, `_id` (patched locally).

**`jsas`** — `worker`, `task`, `location`, `date`, `hazards` (list of {hazard, risk, control} with risk in
low/medium/high/critical), `ppe` (checked items), `supervisor`, `savedAt`, `createdAt`, `deleted`…,
`_id` (patched locally). No approval, no risk score, no review state.

**`notices`** — `title`, `message`, `type` (info/warning/critical/resolved), `target` (default `all`;
values are cosmetic — worker clients fetch all notices regardless), `workZone`, `createdBy`,
`pinned`, `sendPush` (flag only), `expires`, `scheduledFor`, `createdAt`, `readCount`, `ackCount`
(client-incremented counters), `deleted`, `noticeId`, `_id`.

**`emergency_sos`** — appended "state snapshots": `active` (boolean — the whole lifecycle model),
`category`, `message`, `site`, `activatedBy`, `startedAt`, `acknowledgements` (array of device/name
strings), `notifiedWorkers` (device-count estimate), `deleted`, `createdAt`, `updatedAt`, `endedBy`,
`deactivatedAt`, `durationSeconds`. Latest non-deleted doc = authoritative state (SW polls this).

**`audit_log`** — client fire-and-forget: `action` (delete/restore/purge only), `collection`, `docId`,
`adminUser` (defaults to string `'admin'`), `timestamp`, `createdAt`, extra fields. Writable by any
client; actor not authenticated; no read/update protection.

### 1.2 Current weaknesses

1. No tenant/user dimension anywhere; incidents across companies/sites collide in one collection.
2. Media (photo base64) stored in documents — doc-size tax, cost, and no authorization granularity.
3. Matching local↔cloud by timestamps+names is not unique (`savedAt`+`name`) — duplicate risk.
4. Audit is client-written and spoofable; logs of sensitive ops are missing (login, role change, …).
5. Counters (`readCount`/`ackCount`) are racy read-modify-writes from every device.
6. No indexes, constraints, foreign-key semantics, or pagination strategy in this model; queries pull the
   newest N of the whole collection. Rules/console indexes live outside this repo (unverifiable here).

## 2. Target database model — Supabase PostgreSQL (ADR-008, decided 2026-09-03)

Every tenant-owned record carries `organization_id`; site/department-level records carry their scope.
Authorization helpers (`auth_user_has_org_access(org_id)`, `auth_user_is_org_admin(org_id)`,
`current_user_org_ids()` — already concrete in `supabase/migrations/20260903000000_tenant_foundation.sql`)
are enforced by **Postgres Row Level Security** on every access — the database-enforcement layer that
replaces Firestore rules. Site-scope helper (`auth_user_has_site_access`) lands with Phase 04/06 policies.

Tables below are the roadmap; each lands with its phase. Migration mapping lives in `MIGRATION_PLAN.md`.

### 2.1 Platform & tenancy

Phase 04 concrete state (migration `20260903000040_phase04_site_hierarchy.sql`):

| Entity | Key columns / fields | Notes |
|---|---|---|
| `organizations` | id, name, slug, county, org_type, status, settings, branding, createdBy, timestamps | AML Liberia = tenant #1 seed |
| `organization_members` | orgId, userId, role, status, createdBy, timestamps | unique(orgId,userId); role in the 9 org codes |
| `sites` | id, orgId, name, location, county, status, createdBy | unique(orgId,name); Nimba Mine, Port Operations… |
| `organizational_units` | id, orgId, siteId, parentId, unit_type (department/team/work_zone), name, code, status | self-referencing hierarchy; org+site scope triggers |
| `site_members` | orgId, siteId, userId, role, status | PK(siteId,userId); role = org role codes; org↔site trigger |
| `workers` | id, orgId, siteId, departmentId, teamId, userId(optional identity link), employeeId, fullName, classification, contactPhone, status | unique(orgId,employeeId); scope triggers |
| `org_invites` | id, orgId, siteId, email, role, token, status, expiresAt, invitedBy/acceptedBy | one pending per (org,email); sha256 tokens |
| `roles`, `permissions`, `role_permissions` | system + org-scoped | 16 roles / 62 permissions / seeded bundles per RBAC_MODEL.md |

Writes to memberships/units/workers/invites go through SECURITY DEFINER RPCs (`org_add_member`,
`org_send_invite` / `org_accept_invite`, `site_assign_member`, `org_create_unit`, `worker_add`, …).
RLS as of Phase 06 (migration `20260903000050_phase06_rls_audit.sql` + fixes `…051`–`…053`):
`organizations` SELECT (members) + UPDATE (owner/admin via `organizations.manage`, INSERT platform);
`sites` + `organizational_units` SELECT = org members OR active members of the row's site
(`auth_user_has_site_access`); `workers` SELECT = least privilege (`workers.view`/`users.view` at org
scope or the reader's own site — plain workers never list the roster); `organization_members` own-row
or org; `site_members` own-row or org; `org_invites` org-members only. All tenant writes remain
RPC-gated (SECURITY DEFINER) or service-role — no direct INSERT/UPDATE/DELETE policies for end users.
Audit triggers on ALL 7 tenant-management tables (incl. `sites` — fix `…053`) write to `audit_log`
(§2.5). Safety-domain tables + their policies land Phases 07–09.

### 2.2 Workforce & identity

| Entity | Notes |
|---|---|
| `users` | Supabase Auth identity (`auth.users`); the app never stores passwords |
| `workers` | LIVE Phase 04: orgId, siteId, deptId/teamId, employee id, classification, contact, status, optional userId link (Phase 05 mapping); safety profile (training, certs) extends in Phase 08 |
| `site_members` | LIVE Phase 04: site-scoped role grants (role codes shared with organization_members) |
| `sessions`/tokens | short-lived credentials managed by Supabase Auth; invite tokens in `org_invites` |

### 2.3 Safety domain (all org-scoped)

Phase 07 concrete (migration `20260903000060_phase07_incidents.sql` + `…061_storage_evidence.sql`):

| Entity | Key columns / fields | Notes |
|---|---|---|
| `incidents` | id, organization_id, site_id?, department_id?, client_id (unique), reported_by_user_id (server-set from auth.uid(); immutable after insert), reported_by_name, badge, dept_text, incident_type, severity (low/medium/high/critical), status (lifecycle DRAFT→CLOSED), incident_datetime, location_text, description, immediate_action, witnesses_text, impact_text, investigation_notes, closure_notes, resolved_at, site_notice_scope, deleted, legacy_status, saved_at, created_by | RLS: org-wide roles owner/admin/safety_manager/safety_officer; site roles site_manager/supervisor; worker own-only + site_notice_scope broadcast; hard-delete = owner/admin/safety_manager only. Triggers: reporter set/pinned (before insert/update); org/site scope check; updated_at; audit. |
| `incident_evidence` | id, organization_id, site_id?, incident_id FK (cascade), storage_path (unique, object key), kind (photo/document/video/other), content_type, size_bytes, sha256, captured_at, uploaded_by | org/site mirrored from incident; uploaded_by = auth.uid() server-side. RLS follows incident view/update/delete. |
| `incident_witnesses` | id, organization_id, site_id?, incident_id FK (cascade), full_name, badge, role_text, statement, created_by | org/site mirrored from incident. RLS follows incident view/update (no DELETE policy per RLS_MATRIX §1.2). |

Incident-evidence storage bucket: private `incident-evidence` (10 MB; image/jpeg,image/png,image/webp,application/pdf,video/mp4). Object key layout: `organizations/{org}/sites/{site}/incidents/{incident_uuid_or_client_id}/{file}`; policies resolve through the incident's own RLS. |

Remaining safety-domain tables (Phase 08–09): `jsas` (+ `jsa_steps` with likelihood/severity/score/controls/residual risk), `risk_matrices` (configurable per org), `inspections`, `inspection_templates`, `inspection_items`, `inspection_findings`, `corrective_actions` (CAPA: owner, due date, priority, evidence, verification, closure, overdue), `notices`, `notice_targets`, `notice_acks` (per-user acknowledgements), `documents` (policies/SOPs/permits — object refs), `equipment` (+ inspections/defects — Phase 08+), `training`/`certifications` (Phase 08+).

### 2.4 Emergency (see EMERGENCY_RESPONSE_ARCHITECTURE.md)

Phase 09 concrete (migration `20260903000080_phase09_emergency_sos.sql` + fixes `…081`–`…084`):

| Entity | Key columns / fields | Notes |
|---|---|---|
| `emergency_events` | id, organization_id, site_id?, client_id (unique), category, message, contact_number, assembly_point, severity (low/medium/high/critical), status (lifecycle ACTIVATED→ACKNOWLEDGED→RESPONDING→CONTAINED→RESOLVED→CLOSED, forward-only), location_text, affected_area, activated_by (server-pinned auth.uid(); immutable), resolved_by (immutable), resolution_note, after_action_note, site_notice_scope (default true), deleted, activated_by_text/ended_by_text/started_at/deactivated_at/duration_seconds/notified_workers_legacy (Phase 05 mapper parity) | RLS: org-wide roles (owner/admin/safety_manager/safety_officer/site_manager) view/insert; supervisor site-scope view; worker/contractor site-notice-scope view + own ack; resolve/close = emergency.resolve holders; no DELETE policy (purge is audited service-role, Phase 12). Guards: activated_by pinned; forward-only lifecycle; resolved_by immutable; legacy deactivation records resolver server-side. |
| `emergency_acknowledgements` | event_id FK (cascade), acked_by (server-pinned), acked_at, note, channel (app/push/sms/voice/radio), client_id | unique(event_id, acked_by) = idempotent retries; immutable (no UPDATE/DELETE policies). |
| `emergency_escalations` | event_id, level, escalated_to, escalated_to_user?, reason, created_by | INSERT = response-chain gate (supervisor and above, org or site scope); workers ack-only. |
| `emergency_responders` | event_id, responder_user?, responder_text, role, status (dispatched→…→stood_down), dispatched_at, arrived_at, client_id | INSERT/UPDATE = response-chain gate; no created_by column (child guard handles per-table). |
| `emergency_log` | event_id, entry_type (activated/acknowledged/responding/escalated/contained/resolved/closed/note), actor_user_id, detail jsonb | Append-only lifecycle stream written ONLY by `trg_emergency_log_capture`; SELECT-only grant; itself audited via trg_audit_capture. |

### 2.5 Governance & operations

`audit_log` (id, orgId, actorUserId, actorName, action, resource, resourceId, metadata jsonb, source,
createdAt) — **LIVE Phase 06–09**: RLS = SELECT for org members with `audit_logs.view`; INSERT/UPDATE/DELETE
privileges revoked from anon+authenticated (append-only). Rows are written ONLY by the SECURITY
DEFINER trigger `trg_audit_capture()` (extended in `20260903000060_phase07_incidents.sql`, then
`…070`/`…071` Phase 08 and `…080` Phase 09) on **19 audited tables** (Phase 06: organization_members,
site_members, sites, organizational_units, workers, org_invites, organizations; Phase 07: incidents,
incident_evidence, incident_witnesses; Phase 08: jsas, jsa_steps, inspections, corrective_actions;
Phase 09: emergency_events, emergency_acknowledgements, emergency_escalations, emergency_responders,
emergency_log) with actor from `auth.uid()` + actor email. Curated metadata: incident
severity/status/type/deleted/client_id (no description); evidence kind/size/content_type/sha256
(no storage path); witness name/badge (no statement); emergency category/severity/status/actor
(no message text); one-time invite tokens never mirrored. source='trigger'.
Org hard-delete + cascade deletes retain rows as platform-scope history (`organization_id` null —
fixes `…051`/`…052`; `sites` trigger added by `…053`). Remaining safety-domain triggers
(notices/documents) + `source='rpc'/'service'` writers + platform/government audit readers land
Phases 10–12. Governance tables later: `plans`, `subscriptions`, `organization_usage`,
`feature_flags` (Phase 12, schema-ready); `notifications` (targeted, org-scoped).

## 3. Indexing / constraints / integrity (target)

- Unique constraints: org slug; (orgId, userId) membership; (orgId, employeeId); (orgId, notice/capa no.).
- Indexes for the hot query set: org-scoped incident/JSA lists by createdAt; open CAPAs by dueDate; notices
  by status/severity/expiry; inspection schedules by dueDate; audit by actor/resource/time; emergency by
  status+time.
- Soft delete = flag + `deletedBy`/`deletedAt` + audit entry; hard purge is admin-only with audit.

## 4. Migration strategy

Full mapping table + ordering + rollback/backup plan: `MIGRATION_PLAN.md`. Summary: back up `aml-mineguard`
(all 5 collections) before anything; seed organization #1 (ArcelorMittal Liberia) and its sites (already
seeded in `supabase/seed.sql`); migrate records under org #1 with field mapping (target = Supabase Postgres);
validate counts/spot checks; keep dual-write or export fallback until cutover verification.
