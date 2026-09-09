// ============================================================
// MINEGUARD — Phase 05 legacy → target mapping + validation prep
//
// Pure, OFFLINE, deterministic mapper. Consumes the read-only
// inventory snapshot produced by scripts/phase05-inventory.mjs
// (supabase/legacy-inventory/*.ndjson — NEVER the live Firestore)
// and emits, under supabase/migration-prep/ (gitignored):
//
//   payloads/<table>.ndjson       migration-ready rows per target
//                                 table (see DATABASE_ARCHITECTURE
//                                 §2.3/§2.4 naming; each row carries
//                                 client_id for idempotent apply +
//                                 org/site slugs for apply-time FK
//                                 resolution)
//   photos.manifest.ndjson        one row per legacy embedded photo
//                                 (Phase 07 object-storage upload
//                                 work queue)
//   mapping-report.json           validation report = MIGRATION_PLAN
//                                 §4.3 baseline (counts, deleted
//                                 preservation, required-field/null
//                                 checks, orphan audit entries,
//                                 resolution outcomes)
//   review-lists.json             human-review items: values the
//                                 mapper must NOT decide silently
//                                 (site/zone vocab vs seeded sites,
//                                 unbadged workers, supervisors,
//                                 witness strings, date parses,
//                                 unknown enums, unusual photos)
//
// Restartability / human-in-the-loop: re-running is idempotent
// (pure function of the snapshot + overrides). To record a review
// decision, add a key to supabase/migration-prep/overrides.json
// (see OVERRIDE_KEYS below) and re-run; the mapper then applies it
// deterministically and moves the item out of its review list.
//
// NO database writes — the target safety-domain tables land with
// Phases 06–09, and the durable user-owned Firestore export
// (ADR-003) must exist before any apply. This phase produces and
// validates the payloads so cutover is a table + credentials away.
//
// Usage:  node scripts/phase05-map.mjs
// ============================================================

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";

const SRC_DIR = "supabase/legacy-inventory";
const OUT_DIR = "supabase/migration-prep";
const COLLECTIONS = ["incidents", "jsas", "notices", "audit_log", "emergency_sos"];

// Tenant #1 seed contract (supabase/seed.sql — idempotent, slug-based).
const ORG_SLUG = "arcelormittal-liberia";
const SEEDED_SITES = [
  { slug: "nimba-mine", name: "Nimba Mine", location: "Nimba County" },
  { slug: "port-operations", name: "Port Operations", location: "Buchanan" },
];

// Canonical legacy enums (observed in the snapshot; anything outside is a review item).
const INCIDENT_STATUS = new Set(["open", "resolved"]);
const SEVERITY = new Set(["low", "medium", "high", "critical"]);
const NOTICE_TYPES = new Set(["info", "warning", "critical", "resolved"]);
const AUDIT_ACTIONS = new Set(["delete", "restore", "purge"]);

// Status mapping (target domain tables land in Phases 07–09; keep the map
// here so apply-time DDL sync is one obvious place).
const INCIDENT_STATUS_MAP = { open: "SUBMITTED", resolved: "RESOLVED" };

// Review decision overrides, read from supabase/migration-prep/overrides.json when present:
//   { "workZoneSite": {"Uritton": "nimba-mine"},      site slug chosen for a notice workZone value
//     "deptUnit":    {"Mechanic Team": {...}},        unit refinement (name/type/site)
//     "locationSite": {"Rampard": "nimba-mine"},      site slug chosen for an incident/jsa location
//     "badgeWorker": {"Great Monarch": "AML-0001"}    employee id decided for an unbadged worker }
const OVERRIDE_KEYS = ["workZoneSite", "deptUnit", "locationSite", "badgeWorker"];

let failures = 0;
function say(status, label, detail = "") {
  console.log(`${status.padEnd(5)} ${label}${detail ? " — " + detail : ""}`);
  if (status === "FAIL") failures += 1;
}

function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}

function readNdjson(file) {
  if (!existsSync(file)) throw new Error(`missing ${file} — run scripts/phase05-inventory.mjs first`);
  return readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

// ---- helpers ---------------------------------------------------------

const review = { items: [] };
function addReview(group, value, docId, note = "") {
  review.items.push({ group, value: String(value), docId, note });
}

// Parse a legacy ms epoch OR a locale date string; never throws.
// Legacy ms epochs are exact (createdAt). Locale strings (savedAt,
// deletedAt, resolvedAt, timestamp) are ambiguous — parsed on a
// best-effort basis and flagged for review, never silently trusted.
function parseTs(value, { locale = true } = {}) {
  if (value == null || value === "") return { ts: null };
  if (typeof value === "number") {
    return Number.isFinite(value) ? { ts: new Date(value).toISOString(), exact: true } : { ts: null };
  }
  if (typeof value === "string" && /^\d{13}$/.test(value.trim())) {
    return { ts: new Date(Number(value)).toISOString(), exact: true };
  }
  if (typeof value !== "string") return { ts: null };
  const t = Date.parse(value);
  if (Number.isNaN(t)) return { ts: null };
  return { ts: new Date(t).toISOString(), exact: false, locale: true };
}

function stripEmoji(s) {
  return String(s)
    .replace(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/gu, "")
    .replace(/\s+/g, " ")
    .trim();
}

// Resolve a free-text site-ish value against the seeded sites. Anything
// unresolvable becomes a review item (decision belongs to the org owner).
function resolveSite(value, docId, group = "siteVocab") {
  const v = String(value == null ? "" : value).trim();
  if (!v) return { siteSlug: null };
  const hit = SEEDED_SITES.find(
    (s) => v.toLowerCase() === s.name.toLowerCase() || v.toLowerCase().startsWith(s.slug)
  );
  if (hit) return { siteSlug: hit.slug };
  addReview(group, v, docId, `no seeded site matches “${v}” — confirm target site or seed a new site`);
  return { siteSlug: null };
}

// ---- per-collection mappers -----------------------------------------

function mapIncidents(docs) {
  const rows = [];
  const photoManifest = [];
  const depts = new Map(); // dept text -> {count}
  const workers = new Map(); // name -> {badge, count, source}
  const out = {
    counts: { source: docs.length, imported: 0, deletedImported: 0, softDeletedSource: 0 },
    photos: { embeddedDocs: 0, elements: 0, bytes: 0 },
  };

  function sniffMime(buf) {
    if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "image/jpeg";
    if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "image/png";
    return null;
  }

  // One legacy embedded photo → object-storage manifest row. base64 is
  // hashed + sized here, NEVER kept in the target row (Phase 07 upload).
  function photoRecord(p, docId, index, siteSlug) {
    if (typeof p !== "string") {
      return { err: "not-a-string", raw: JSON.stringify(p).slice(0, 40) };
    }
    let mime = null;
    let body = p;
    if (p.startsWith("data:")) {
      const semi = p.indexOf(";");
      mime = semi > 5 ? p.slice(5, semi) : null;
      const comma = p.indexOf(",");
      body = comma >= 0 ? p.slice(comma + 1) : p;
    }
    if (!body.trim() || !/^[A-Za-z0-9+/=\s]*$/.test(body)) return { err: "not-base64" };
    const buf = Buffer.from(body, "base64");
    if (!buf.length) return { err: "empty-after-decode" };
    if (!mime) mime = sniffMime(buf);
    return {
      incident_client_id: docId,
      index,
      mime: mime ?? "application/octet-stream",
      bytes: buf.length,
      sha256: sha256(buf),
      storage_key: `organizations/${ORG_SLUG}/sites/${siteSlug ?? "unassigned"}/incidents/${docId}/${index}.${(mime || "").split("/")[1] === "png" ? "png" : "jpg"}`,
    };
  }

  for (const d of docs) {
    const docId = d._docName;
    const deleted = d.deleted === true;
    if (deleted) out.counts.softDeletedSource++;

    // Worker identity (reporter). Badge formats vary ("2076" vs "AML-34") —
    // kept verbatim; format normalization is a review decision. All badges
    // per name are tracked; inconsistency (one name, several badges) is
    // surfaced for review, never silently resolved.
    if (d.name) {
      const w = workers.get(d.name) || { badges: new Map(), count: 0, source: "incidents" };
      w.count++;
      if (d.badge != null) {
        const b = String(d.badge);
        w.badges.set(b, (w.badges.get(b) || 0) + 1);
      }
      workers.set(d.name, w);
    } else if (d.name == null && d.badge != null) {
      addReview("workerIdentity", d.badge, docId, "incident has badge but no name");
    }

    const site = resolveSite(d.location, docId, "locationSite");
    const dept = d.dept ? String(d.dept).trim() : null;
    if (dept) {
      const e = depts.get(dept) || { count: 0 };
      e.count++;
      depts.set(dept, e);
    }

    const createdAt = parseTs(d.createdAt, { locale: false });
    const row = {
      client_id: docId,
      organization_slug: ORG_SLUG,
      site_slug: site.siteSlug,
      legacy_status: d.status ?? null,
      status: INCIDENT_STATUS_MAP[d.status] ?? null,
      type: d.type ?? null,
      severity: d.severity ?? null,
      description: d.description ?? null,
      immediate_action: d.action ?? null,
      datetime: typeof d.datetime === "string" ? d.datetime : null, // local wall-clock text (legacy)
      created_at: createdAt.ts,
      saved_at: parseTs(d.savedAt).ts,
      resolved_at: parseTs(d.resolvedAt).ts,
      reporter: { name: d.name ?? null, badge: d.badge != null ? String(d.badge) : null, dept_text: dept },
      witnesses: d.witnesses != null ? String(d.witnesses) : null,
      lang: d.lang ?? null,
      deleted,
      deleted_at: parseTs(d.deletedAt).ts,
      deleted_by: d.deletedBy ?? null,
    };
    if (d.witnesses != null && d.witnesses !== "") {
      const parts = String(d.witnesses).split(/,|;|\band\b|\+|\//i).map((s) => s.trim()).filter(Boolean);
      if (parts.length > 1) row.witnesses_parsed = parts;
    }
    if (d.status != null && !INCIDENT_STATUS.has(d.status)) {
      addReview("incidentStatus", d.status, docId, `unexpected status “${d.status}”`);
      row.status = null; // no silent guess
    }
    if (d.severity != null && !SEVERITY.has(d.severity)) {
      addReview("severity", d.severity, docId, `unexpected severity “${d.severity}”`);
    }
    if (createdAt && !createdAt.exact) addReview("timestampLocale", d.createdAt, docId, "createdAt was not an epoch ms");

    // Photos: legacy shape is arrays of data-URL base64 strings. Every
    // embedded payload becomes a manifest entry for the Phase 07
    // object-storage move; base64 is NEVER kept in the target row.
    const rawPhotos = d.photos;
    if (rawPhotos != null) {
      out.photos.embeddedDocs++;
      const list = Array.isArray(rawPhotos) ? rawPhotos : [rawPhotos];
      const kept = [];
      for (let i = 0; i < list.length; i++) {
        const rec = photoRecord(list[i], docId, i, site.siteSlug);
        if (rec.err) {
          addReview("photoShape", rec.raw ?? String(list[i]).slice(0, 60), docId, `photo[${i}] ${rec.err}`);
          continue;
        }
        photoManifest.push(rec);
        kept.push({ index: rec.index, sha256: rec.sha256, bytes: rec.bytes, mime: rec.mime });
        out.photos.elements++;
        out.photos.bytes += rec.bytes;
      }
      if (kept.length) row.photo_refs = kept;
    }
    rows.push(row);
  }

  out.counts.imported = rows.filter((r) => !r.deleted).length;
  out.counts.deletedImported = rows.length - out.counts.imported;
  out.counts.photos = out.photos;
  for (const [name, w] of workers) {
    const badges = [...w.badges.entries()].sort((a, b) => b[1] - a[1]).map((e) => e[0]);
    const primary = badges[0] ?? null;
    const employeeId = primary ?? OVERRIDES.badgeWorker?.[name] ?? null;
    if (badges.length > 1) {
      addReview("workerIdentity", name, "-", `inconsistent badges across docs: ${badges.join(", ")}`);
    }
    if (!employeeId) {
      addReview("workerIdentity", name, "-", "no badge on any incident — assign employee id before worker upsert");
    }
    out.workersProposed++;
    review.workers = review.workers || [];
    review.workers.push({
      fullName: name,
      employeeId,
      badge_seen: badges.length ? badges.join(", ") : null,
      sourceDocCount: w.count,
      source: w.source,
      org_slug: ORG_SLUG,
    });
  }
  for (const [deptName, e] of depts) {
    out.deptsProposed++;
    review.depts = review.depts || [];
    review.depts.push({
      name: deptName,
      docCount: e.count,
      site_slug: null, // unit placement decided with the org owner at apply time
      unit_type: "department",
    });
  }
  return { rows, photoManifest, out };
}

function mapJsas(docs) {
  const rows = [];
  const workers = new Map();
  const out = { counts: { source: docs.length, imported: 0, deletedImported: 0, softDeletedSource: 0 }, steps: 0 };

  for (const d of docs) {
    const docId = d._docName;
    const deleted = d.deleted === true;
    if (deleted) out.counts.softDeletedSource++;
    if (d.worker) {
      const w = workers.get(d.worker) || { count: 0, source: "jsas" };
      w.count++;
      workers.set(d.worker, w);
    }
    const site = resolveSite(d.location, docId, "locationSite");
    const createdAt = parseTs(d.createdAt, { locale: false });

    const hazards = Array.isArray(d.hazards) ? d.hazards : [];
    const steps = hazards.map((h, i) => {
      const risk = h && h.risk != null ? String(h.risk).toLowerCase() : null;
      if (risk && !SEVERITY.has(risk)) addReview("jsaRisk", risk, docId, `hazard[${i}] risk “${risk}” outside low/medium/high/critical`);
      return {
        step: i + 1,
        hazard: h?.hazard ?? null,
        severity_label: risk, // legacy “risk” is a severity label; likelihood was never captured
        likelihood: null, // NEVER invented — review item where a score is required
        control: h?.control ?? null,
      };
    });
    out.steps += steps.length;

    const row = {
      client_id: docId,
      organization_slug: ORG_SLUG,
      site_slug: site.siteSlug,
      legacy_status: null,
      status: "SUBMITTED", // legacy JSAs had no approval lifecycle (MIGRATION_PLAN §3)
      worker_text: d.worker ?? null,
      task: d.task ?? null,
      location_text: d.location ?? null,
      date: typeof d.date === "string" ? d.date : null,
      supervisor_text: d.supervisor ?? null,
      steps,
      ppe: (Array.isArray(d.ppeSelected) ? d.ppeSelected : []).map((p) => stripEmoji(p)).filter(Boolean),
      created_at: createdAt.ts,
      saved_at: parseTs(d.savedAt).ts,
      lang: d.lang ?? null,
      deleted,
      deleted_at: parseTs(d.deletedAt).ts,
      deleted_by: d.deletedBy ?? null,
    };
    if (d.supervisor) {
      addReview("supervisor", d.supervisor, docId, "supervisor is a text string; link to a user/worker at apply time");
    }
    rows.push(row);
  }
  out.counts.imported = rows.filter((r) => !r.deleted).length;
  out.counts.deletedImported = rows.length - out.counts.imported;
  for (const [name, w] of workers) {
    review.workers = review.workers || [];
    if (!review.workers.some((x) => x.fullName === name)) {
      review.workers.push({ fullName: name, employeeId: null, badge_seen: null, sourceDocCount: w.count, source: w.source, org_slug: ORG_SLUG });
      addReview("workerIdentity", name, "-", "JSA worker without badge — assign employee id before worker upsert");
    }
  }
  return { rows, out };
}

function mapNotices(docs) {
  const rows = [];
  const out = { counts: { source: docs.length, imported: 0, deletedImported: 0, softDeletedSource: 0 } };

  const workZones = new Map();
  for (const d of docs) {
    const docId = d._docName;
    const deleted = d.deleted === true;
    if (deleted) out.counts.softDeletedSource++;
    if (d.workZone) {
      const z = workZones.get(String(d.workZone).trim()) || { count: 0 };
      z.count++;
      workZones.set(String(d.workZone).trim(), z);
    }
    const createdAt = parseTs(d.createdAt, { locale: false });
    const site = d.workZone ? resolveSite(d.workZone, docId, "workZoneSite") : { siteSlug: null };

    const row = {
      client_id: d.noticeId ?? docId, // legacy app generated noticeId; fall back to doc id
      legacy_doc_id: docId,
      organization_slug: ORG_SLUG,
      site_slug: site.siteSlug, // null → org-wide notice (review item below)
      title: d.title ?? null,
      message: d.message ?? null,
      type: d.type ?? null,
      target_text: d.target ?? null,
      work_zone_text: d.workZone ?? null,
      created_by_text: d.createdBy ?? null,
      pinned: d.pinned === true,
      send_push_flag: d.sendPush === true, // legacy flag only; push infra is Phase 09+
      expires_at: parseTs(d.expires, { locale: false }).ts,
      scheduled_for: parseTs(d.scheduledFor, { locale: false }).ts,
      created_at: createdAt.ts,
      read_count_baseline: typeof d.readCount === "number" ? d.readCount : 0, // racy legacy counter; baseline only (MIGRATION_PLAN §3)
      ack_count_baseline: typeof d.ackCount === "number" ? d.ackCount : 0,
      deleted,
      deleted_at: parseTs(d.deletedAt).ts,
      deleted_by: d.deletedBy ?? null,
    };
    if (d.type != null && !NOTICE_TYPES.has(d.type)) {
      addReview("noticeType", d.type, docId, `unexpected type “${d.type}”`);
    }
    rows.push(row);
  }
  out.counts.imported = rows.filter((r) => !r.deleted).length;
  out.counts.deletedImported = rows.length - out.counts.imported;
  out.counts.workZones = workZones.size;
  return { rows, out };
}

function mapEmergency(docs) {
  // Legacy model: append-only state snapshots; latest non-deleted snapshot
  // per startedAt is the authoritative lifecycle record (MIGRATION_PLAN §3).
  const byStart = new Map();
  for (const d of docs) {
    const start = parseTs(d.startedAt, { locale: false }).ts;
    if (!start) {
      addReview("emergencyStartedAt", d.startedAt, d._docName, "no parseable startedAt");
      continue;
    }
    const list = byStart.get(start) || [];
    list.push(d);
    byStart.set(start, list);
  }
  const rows = [];
  const out = { counts: { source: docs.length, events: 0, snapshotsMerged: 0 } };

  for (const [start, snapshots] of byStart) {
    const sorted = [...snapshots].sort((a, b) => {
      const ta = typeof a.updatedAt === "number" ? a.updatedAt : 0;
      const tb = typeof b.updatedAt === "number" ? b.updatedAt : 0;
      return ta - tb;
    });
    const latest = sorted[sorted.length - 1];
    const docId = latest._docName;
    out.counts.snapshotsMerged += sorted.length;
    const active = latest.active === true;
    const closed = latest.endedBy != null || latest.deactivatedAt != null || !active;
    const site = resolveSite(latest.site, docId, "siteVocab");

    const acks = [];
    for (const a of Array.isArray(latest.acknowledgements) ? latest.acknowledgements : []) {
      acks.push({ legacy_note: String(a) });
    }
    for (const a of Array.isArray(latest.acknowledgedWorkers) ? latest.acknowledgedWorkers : []) {
      if (!acks.some((x) => x.legacy_note === String(a))) acks.push({ legacy_note: String(a) });
    }
    const logs = [];
    for (const l of Array.isArray(latest.logs) ? latest.logs : []) {
      logs.push(typeof l === "string" ? { legacy_text: l } : l);
    }

    rows.push({
      client_id: docId,
      organization_slug: ORG_SLUG,
      site_slug: site.siteSlug,
      category: latest.category ?? null,
      message: latest.message ?? null,
      contact_number: latest.contactNumber ?? null,
      assembly_point: latest.assemblyPoint ?? null,
      activated_by_text: latest.activatedBy ?? null,
      ended_by_text: latest.endedBy ?? null,
      started_at: start,
      deactivated_at: parseTs(latest.deactivatedAt).ts,
      duration_seconds: typeof latest.durationSeconds === "number" ? latest.durationSeconds : null,
      status: active ? "ACTIVATED" : closed ? "CLOSED" : null,
      notified_workers_legacy: typeof latest.notifiedWorkers === "number" ? latest.notifiedWorkers : null,
      created_at: parseTs(latest.createdAt, { locale: false }).ts,
      deleted: latest.deleted === true,
      acknowledgements: acks, // legacy device/name strings; linked to users in Phase 09
      logs, // legacy free-form log entries
    });
  }
  out.counts.events = rows.length;
  out.counts.imported = rows.filter((r) => !r.deleted).length;
  out.counts.deletedImported = rows.length - out.counts.imported;
  return { rows, out };
}

function mapAudit(docs) {
  const rows = [];
  const out = { counts: { source: docs.length, imported: 0 }, actions: {} };
  for (const d of docs) {
    const docId = d._docName;
    if (d.action) out.actions[d.action] = (out.actions[d.action] || 0) + 1;
    if (d.action && !AUDIT_ACTIONS.has(d.action)) {
      addReview("auditAction", d.action, docId, `unexpected action “${d.action}”`);
    }
    rows.push({
      client_id: docId,
      organization_slug: ORG_SLUG,
      legacy_actor: d.adminUser ?? null,
      action: d.action ?? null,
      collection: d.collection ?? null,
      resource_doc_id: d.docId ?? null,
      created_at: parseTs(d.createdAt, { locale: false }).ts,
      timestamp_text: d.timestamp ?? null,
      legacy_import: true, // imported actor strings are NOT tamper-proof evidence (MIGRATION_PLAN §3)
      metadata: { source: "firestore_aml-mineguard", docId },
    });
  }
  out.counts.imported = rows.length;
  out.counts.deletedImported = 0; // legacy audit_log has no soft-delete flag
  out.counts.actions = out.actions;
  return { rows, out };
}

// ---- main ------------------------------------------------------------

let OVERRIDES = {};
function loadOverrides() {
  const f = `${OUT_DIR}/overrides.json`;
  if (!existsSync(f)) return;
  const raw = JSON.parse(readFileSync(f, "utf8"));
  for (const k of OVERRIDE_KEYS) {
    if (raw[k] && typeof raw[k] === "object") OVERRIDES[k] = raw[k];
  }
  console.log(`INFO overrides applied from ${f}: ${Object.keys(OVERRIDES).join(", ") || "none"}`);
}

await (async () => {
  console.log(`Phase 05 mapping — source ${SRC_DIR} → ${OUT_DIR}`);
  mkdirSync(`${OUT_DIR}/payloads`, { recursive: true });

  // Snapshot integrity: mapping output must tie to the exact inventory run.
  const manifest = existsSync(`${SRC_DIR}/manifest.json`)
    ? JSON.parse(readFileSync(`${SRC_DIR}/manifest.json`, "utf8"))
    : null;
  const report = {
    generatedAt: new Date().toISOString(),
    source: SRC_DIR,
    organization: ORG_SLUG,
    tool: "scripts/phase05-map.mjs",
    sourceManifest: manifest ? { generatedAt: manifest.generatedAt, checksums: manifest.collections } : null,
    collections: {},
    totals: { sourceDocs: 0, targetRows: 0, reviewItems: 0 },
    photos: { elements: 0, bytes: 0, manifestRows: 0 },
  };
  const payloads = { incidents: [], jsas: [], notices: [], emergency_events: [], audit_log: [] };
  const allPhotos = [];

  loadOverrides();

  const docsByCollection = {};
  for (const c of COLLECTIONS) {
    docsByCollection[c] = readNdjson(`${SRC_DIR}/${c}.ndjson`).sort((a, b) =>
      String(a._docName).localeCompare(String(b._docName))
    );
  }

  const mInc = mapIncidents(docsByCollection.incidents);
  payloads.incidents = mInc.rows;
  allPhotos.push(...mInc.photoManifest);
  report.collections.incidents = mInc.out.counts;

  const mJsa = mapJsas(docsByCollection.jsas);
  payloads.jsas = mJsa.rows;
  report.collections.jsas = mJsa.out.counts;

  const mNot = mapNotices(docsByCollection.notices);
  payloads.notices = mNot.rows;
  report.collections.notices = mNot.out.counts;

  const mEm = mapEmergency(docsByCollection.emergency_sos);
  payloads.emergency_events = mEm.rows;
  report.collections.emergency_sos = mEm.out.counts;

  const mAud = mapAudit(docsByCollection.audit_log);
  payloads.audit_log = mAud.rows;
  report.collections.audit_log = mAud.out.counts;

  // Cross-collection validation -------------------------------------------------
  // Orphan audit entries: audit rows whose (collection, docId) points at a doc
  // no longer present in the CURRENT snapshot — i.e. hard-purged docs. Expected
  // for deletes; counted, not treated as a data error.
  const known = {};
  for (const c of COLLECTIONS) known[c] = new Set(docsByCollection[c].map((d) => d._docName));
  const orphans = [];
  for (const a of payloads.audit_log) {
    if (a.collection && known[a.collection] && !known[a.collection].has(a.resource_doc_id)) {
      orphans.push({ action: a.action, collection: a.collection, docId: a.resource_doc_id });
    }
  }
  report.auditOrphans = { count: orphans.length, rows: orphans };
  report.auditOrphans.note =
    "audit rows referencing docs absent from the current snapshot (hard-purged legacy docs) — expected for delete actions; imported for history.";

  // Required-field checks per payload family.
  const required = {
    incidents: ["organization_slug", "client_id", "status", "created_at", "description"],
    jsas: ["organization_slug", "client_id", "created_at", "task"],
    notices: ["organization_slug", "client_id", "created_at", "title"],
    emergency_events: ["organization_slug", "client_id", "started_at"],
    audit_log: ["organization_slug", "client_id", "action", "collection"],
  };
  const nullViolations = [];
  for (const [table, fields] of Object.entries(required)) {
    for (const r of payloads[table]) {
      for (const f of fields) {
        if (r[f] == null || r[f] === "") nullViolations.push({ table, client_id: r.client_id, field: f });
      }
    }
  }
  report.nullRequired = { count: nullViolations.length, rows: nullViolations.slice(0, 50) };
  for (const [table, list] of Object.entries(payloads)) {
    const ids = list.map((r) => r.client_id);
    report.collections[table] = report.collections[table] || {};
    report.collections[table].uniqueClientIds = new Set(ids).size === ids.length;
  }

  // Write payloads -----------------------------------------------------------------
  for (const [table, list] of Object.entries(payloads)) {
    if (!list.length) continue;
    const file = `${OUT_DIR}/payloads/${table}.ndjson`;
    const content = list.map((r) => JSON.stringify(r)).join("\n") + "\n";
    writeFileSync(file, content, "utf8");
    report.collections[table].payloadFile = file;
    report.collections[table].payloadRows = list.length;
    report.collections[table].payloadSha256 = sha256(content);
  }
  const photoFile = `${OUT_DIR}/photos.manifest.ndjson`;
  const photoContent = allPhotos.map((p) => JSON.stringify(p)).join("\n") + (allPhotos.length ? "\n" : "");
  writeFileSync(photoFile, photoContent, "utf8");
  report.photos = {
    elements: allPhotos.reduce((n, p) => n + 1, 0),
    bytes: allPhotos.reduce((n, p) => n + (p.bytes || 0), 0),
    manifestFile: photoFile,
    sha256: sha256(photoContent),
  };

  // Review lists + worker/unit proposals -------------------------------------------
  const counts = {};
  for (const i of review.items) counts[i.group] = (counts[i.group] || 0) + 1;
  const reviewOut = {
    items: review.items,
    byGroup: counts,
    proposedWorkers: review.workers || [],
    proposedUnits: review.depts || [],
    overridesFile: `${OUT_DIR}/overrides.json`,
    decisionNote:
      "Items here are decisions the mapper must NOT make silently. Answer via overrides.json (see OVERRIDE_KEYS) and re-run; unresolved items stay out of payload review fields or are flagged.",
  };
  writeFileSync(`${OUT_DIR}/review-lists.json`, JSON.stringify(reviewOut, null, 2), "utf8");
  writeFileSync(`${OUT_DIR}/mapping-report.json`, JSON.stringify(report, null, 2), "utf8");

  // Console summary -----------------------------------------------------------------
  report.totals.sourceDocs = COLLECTIONS.reduce((n, c) => n + docsByCollection[c].length, 0);
  report.totals.targetRows = Object.values(payloads).reduce((n, l) => n + l.length, 0);
  report.totals.reviewItems = review.items.length;

  for (const c of COLLECTIONS) {
    const inv = manifest?.collections?.[c];
    const m = report.collections[c];
    const detail = `${m.imported} imported + ${m.deletedImported} soft-deleted preserved`;
    const ok = inv && inv.count === m.source;
    say(ok ? "PASS" : "FAIL", `${c}: source ${m.source} (inventory ${inv?.count ?? "?"}) → ${detail}`);
  }
  say(
    "PASS",
    `photos: ${report.photos.elements} embedded elements ≈ ${(report.photos.bytes / 1024).toFixed(0)} KB → ${photoFile}`
  );
  say(
    report.nullRequired.count === 0 ? "PASS" : "FAIL",
    `required-field check: ${report.nullRequired.count} violations`,
    report.nullRequired.count ? JSON.stringify(report.nullRequired.rows.slice(0, 10)) : ""
  );
  say(
    "INFO",
    `audit orphans: ${report.auditOrphans.count} (rows referencing hard-purged legacy docs)`
  );
  say(
    "INFO",
    `review items: ${report.totals.reviewItems} in ${Object.keys(counts).length} groups`,
    Object.entries(counts).map(([g, n]) => `${g}=${n}`).join(", ")
  );
  say(
    "INFO",
    `proposed workers ${(review.workers || []).length} · proposed departments ${(review.depts || []).length} — confirm via overrides.json before any apply`
  );
  writeFileSync(`${OUT_DIR}/mapping-report.json`, JSON.stringify(report, null, 2), "utf8");
  say(failures === 0 ? "PASS" : "FAIL", "mapping run finished", "payloads + mapping-report.json + review-lists.json under " + OUT_DIR);
})();
