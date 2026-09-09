# MineGuard Liberia — Mining Domain Model

| Field | Value |
|---|---|
| Doc status | TARGET + current mappings. Phase 09 (2026-09-04) made emergency concrete: `emergency_events`/`emergency_acknowledgements`/`emergency_escalations`/`emergency_responders`/`emergency_log` (§2 Emergency Event) live in Supabase with RLS + lifecycle guards + audit triggers — live-verified (`verify-phase09.mjs` all-PASS). Phase 08 (2026-09-04) made JSAs, inspections, and corrective actions concrete. Phase 07 (2026-09-04) made incidents concrete + private storage bucket. Notices / documents remain TARGET-only (Phase 10+). |
| Last updated | 2026-09-04 |

## 1. Hierarchy

```
Platform (MineGuard)
├── Organization  (e.g. ArcelorMittal Liberia — tenant; the security boundary)
│   ├── Site (e.g. Nimba Mine, Port Operations, Tokadeh)
│   │   ├── Department (Mining Operations, Processing, Maintenance, Safety, …)
│   │   │   └── Team / Work Zone (Pit 3, Bench 12, Crusher Bay, …)
│   │   └── Workers / Supervisors / Safety Officers (assigned to dept/team)
│   ├── Contractor organizations (scoped under host org/site)
│   └── (County / region attribute for regulatory roll-ups: Nimba, Bong, …)
└── Government / Regulatory platform (separate tenant space with explicit grants)
```

Drill-down for regulators and analytics: **Liberia → County → Company → Site → Department → Work Zone → Event**.

Seed tenant (Phase 05 migration): Organization = ArcelorMittal Liberia; Sites = Nimba Mine, Port Operations;
Departments/teams seeded from existing incident/JSA text values where mappable; existing records imported
under this org.

## 2. Core entities

| Entity | Definition | Key org-scoped fields |
|---|---|---|
| Organization | Legal/operating company tenant | name, slug, county, status, branding, risk-matrix config |
| Site | Physical mining/perimeter location | name, location, county, timezone, status |
| Department / Team / Work Zone | Organizational and physical subdivisions | orgId, siteId, parentId, type |
| Worker | Employee/contractor person (safety profile) | employeeId, orgId, siteId, dept/team, classification, contact (limited), status |
| User | Platform identity (may map to one or more workers/members) | email, name, auth subject, status |
| Incident | Safety event report | orgId, siteId, location, dept, reporter/worker, type, severity, datetime, description, evidence refs, witnesses, injuries/env/equipment impact, status lifecycle, investigation, closure |
| Evidence | Incident photos/video/files | orgId, siteId, incidentId, storage ref, type, capturedAt, uploadedBy |
| JSA | Job Safety Analysis (task-level) | orgId, siteId, dept, task, activity, steps[{hazard, risk, likelihood, severity, score, existing controls, additional controls, residual}], responsible, dueDate, approver, status |
| Risk Matrix | Configurable likelihood×severity matrix per org | orgId, name, cells → score/band/color |
| Inspection | Scheduled/adhoc site inspection | orgId, siteId, templateId, inspector, date, status, findings |
| Inspection Finding | Failure/observation from item | inspectionId, item, pass/fail, observation, photo refs, linked CAPA, deadline |
| Corrective Action (CAPA) | Remediation workflow | orgId, source type/id, owner, dueDate, priority, evidence, status (open/due-soon/overdue/completed/verified/closed) |
| Notice | Targeted safety communication | orgId, siteId, severity, audience targets (site/dept/team/role/workers), schedule, expiry, pin, acks |
| Emergency Event | Serious-event lifecycle record | orgId, siteId, type, severity, activatedBy, activatedAt, location, status lifecycle, responders, acks, escalation, resolution, after-action report |
| Document | Policy/SOP/permits/certs/forms | orgId, siteId(opt), category, storage ref, version, status |
| Training/Certification | Competency records (Phase 08+) | workerId, course, issue/expiry, provider, evidence |
| Equipment | Machinery registry + safety inspections (Phase 08+) | orgId, siteId, class, inspection schedule, defects, operator history |
| Audit Log | Append-only sensitive-op record | orgId, actor, action, resource, ts, metadata |

## 3. Statuses

| Domain | Status flow |
|---|---|
| Incident | DRAFT → SUBMITTED → ACKNOWLEDGED → UNDER_INVESTIGATION → CORRECTIVE_ACTION_REQUIRED → PENDING_VERIFICATION → RESOLVED → CLOSED (superset of today's `open`/resolved) |
| Emergency | ACTIVATED → ACKNOWLEDGED → RESPONDING → CONTAINED → RESOLVED → CLOSED (today: boolean `active` only) |
| CAPA | OPEN → (overdue state derived) → COMPLETED → VERIFIED → CLOSED |
| Notice | SCHEDULED → ACTIVE → EXPIRED / ARCHIVED |
| Worker | ACTIVE / SUSPENDED / TERMINATED |

## 4. Current→target field mapping

Current free-text fields on the worker form (`inc-name`, `inc-dept`, `inc-location`) become references in the
target model (worker profile, department, work zone) while keeping fast free-text capture for workers;
mapping details are in `MIGRATION_PLAN.md`.
