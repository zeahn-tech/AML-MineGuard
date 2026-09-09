// ============================================================
// MINEGUARD — Phase 05 legacy-data inventory (read-only)
//
// Reads the five legacy Firestore collections of project
// `aml-mineguard` over the exact anonymous `:runQuery` channel the
// shipped worker app uses (firebase.js embedded public API key —
// REST, read-only semantics; no writes are ever issued here).
//
// Outputs, under supabase/legacy-inventory/ (gitignored):
//   <collection>.ndjson — one decoded doc per line. Photo base64 is
//       RETAINED (photos run ~80–150 KB each; the legacy total here is
//       ~1 MB) so Phase 05 mapping can hash/type/export it. Only
//       pathological fields (>= 8 MB) are stripped to {"__stripped":<len>}.
//   report.json         — per-collection stats: count (incl.
//       soft-deleted), deleted count, createdAt coverage/range,
//       field census (union + presence), photo-payload stats,
//       free-text vocabularies (dept / location / workZone) with
//       distinct counts and sample values, anomaly flags;
//   manifest.json       — file list + sha256 checksums + run info.
//
// Purpose: turn MIGRATION_PLAN §1 "Volume: unknown" into recorded
// evidence and produce the Phase 05 validation-report baseline
// (MIGRATION_PLAN §4.3) BEFORE any import runs. This is NOT the
// durable backup (ADR-003 still requires a user-owned console
// export with a second copy off-repo).
//
// Usage:  node scripts/phase05-inventory.mjs
// ============================================================

import { writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";

const COLLECTIONS = ["incidents", "jsas", "notices", "audit_log", "emergency_sos"];
const OUT_DIR = "supabase/legacy-inventory";
const STRIP_AT = 8_000_000; // chars — safeguard for pathological fields only;
// real photo payloads (~80–150 KB each) are retained whole for Phase 05 mapping
const MAX_DOCS = 20000; // safety ceiling per collection

// Public client config embedded in firebase.js (same as the production app).
const FB = {
  projectId: "aml-mineguard",
  apiKey: "AIzaSyCPqKNe7zyTfBqLT6Gh7Cx2-f7jSf1gvTg",
};
const BASE =
  `https://firestore.googleapis.com/v1/projects/${FB.projectId}/databases/(default)/documents`;

const PHOTO_KEYS = new Set(["photos", "photo", "photoData", "evidence", "images", "attachments"]);

let failures = 0;
function report(status, label, detail = "") {
  console.log(`${status.padEnd(5)} ${label}${detail ? " — " + detail : ""}`);
  if (status === "FAIL") failures += 1;
}

// Decode a Firestore Value proto into plain JS. Long strings and
// long string arrays are replaced with small markers and recorded in
// `meta` so the caller can still report photo-payload statistics.
function decodeValue(v, meta, path) {
  if (v == null) return null;
  if ("nullValue" in v) return null;
  if ("booleanValue" in v) return v.booleanValue;
  if ("integerValue" in v) {
    const n = Number(v.integerValue);
    return Number.isSafeInteger(n) ? n : v.integerValue;
  }
  if ("doubleValue" in v) return v.doubleValue;
  if ("timestampValue" in v) return v.timestampValue;
  if ("stringValue" in v) {
    const s = v.stringValue;
    if (s.length >= STRIP_AT) {
      meta.strippedChars += s.length;
      meta.strippedCount += 1;
      return { __stripped: s.length };
    }
    return s;
  }
  if ("bytesValue" in v) return { __bytes: v.bytesValue.length };
  if ("referenceValue" in v) return v.referenceValue;
  if ("geoPointValue" in v) return v.geoPointValue;
  if ("arrayValue" in v) {
    const arr = v.arrayValue.values || [];
    const isStrArr = arr.length > 0 && arr.every((x) => x.stringValue !== undefined);
    const allLen = isStrArr
      ? arr.reduce((n, x) => n + x.stringValue.length, 0)
      : arr.reduce((n, x) => n + (x.stringValue ? x.stringValue.length : 0), 0);
    const leafPath = String(path).split(".").pop().replace(/\[\]$/, "");
    if (arr.length && allLen >= STRIP_AT && isStrArr) {
      meta.strippedChars += allLen;
      meta.strippedCount += arr.length;
      if (PHOTO_KEYS.has(leafPath)) {
        meta.photoChars += allLen;
        meta.photoElems += arr.length;
        meta.photoArrays += 1;
      }
      return { __strippedArray: arr.length, __chars: allLen };
    }
    return arr.map((x, i) => decodeValue(x, meta, path + "[]"));
  }
  if ("mapValue" in v) {
    const out = {};
    for (const k of Object.keys(v.mapValue.fields || {})) {
      out[k] = decodeValue(v.mapValue.fields[k], meta, path ? path + "." + k : k);
    }
    return out;
  }
  return null;
}

function pushVocab(vocab, value, max) {
  if (value == null) return;
  const k = String(value).trim();
  if (!k) return;
  vocab.counts[k] = (vocab.counts[k] || 0) + 1;
  if (vocab.sample.length < max && !vocab.sample.includes(k)) vocab.sample.push(k);
}

async function fetchPage(cursor, collection, attempt = 0) {
  const q = {
    structuredQuery: {
      from: [{ collectionId: collection }],
      orderBy: [{ field: { fieldPath: "__name__" }, direction: "ASCENDING" }],
      limit: 500,
      ...(cursor ? { startAfter: { values: [{ referenceValue: cursor }] } } : {}),
    },
  };
  const res = await fetch(`${BASE}:runQuery?key=${FB.apiKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(q),
  });
  if (res.status === 429 && attempt < 4) {
    await new Promise((r) => setTimeout(r, 900 * (attempt + 1)));
    return fetchPage(cursor, collection, attempt + 1);
  }
  if (!res.ok) throw new Error(`HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

async function inventoryCollection(collection) {
  const meta = {
    strippedChars: 0,
    strippedCount: 0,
    photoChars: 0,
    photoElems: 0,
    photoArrays: 0,
  };
  const census = { keys: {} };
  const counts = {
    total: 0,
    deleted: 0,
    createdAtMissing: 0,
    createdAtRange: null,
    photoDocs: 0,
    photoArrays: 0,
    photoElems: 0,
    photoChars: 0,
    empty: 0,
  };
  const vocab = {
    dept: { counts: {}, sample: [] },
    location: { counts: {}, sample: [] },
    workZone: { counts: {}, sample: [] },
  };
  const lines = [];
  let cursor = null;
  let ceilingHit = false;

  for (;;) {
    const page = await fetchPage(cursor, collection);
    const docs = page.filter((r) => r && r.document);
    if (!docs.length) break;
    for (const r of docs) {
      if (counts.total >= MAX_DOCS) {
        ceilingHit = true;
        break;
      }
      const d = r.document;
      const doc = decodeValue({ mapValue: { fields: d.fields || {} } }, meta, "");
      doc._docName = (d.name || "").split("/").pop();
      counts.total++;
      const keys = Object.keys(doc).filter((k) => k !== "_docName");
      if (!keys.length) counts.empty++;
      for (const k of keys) census.keys[k] = (census.keys[k] || 0) + 1;
      if (doc.deleted === true) counts.deleted++;
      if (!("createdAt" in doc)) counts.createdAtMissing++;
      const ts = doc.createdAt ?? doc.savedAt ?? null;
      if (ts != null) {
        const t = typeof ts === "number" ? ts : Date.parse(ts);
        if (!isNaN(t)) {
          if (!counts.createdAtRange) counts.createdAtRange = [t, t];
          else {
            if (t < counts.createdAtRange[0]) counts.createdAtRange[0] = t;
            if (t > counts.createdAtRange[1]) counts.createdAtRange[1] = t;
          }
        }
      }
      // Photo-payload stats measured over the DECODED doc (photos are
      // retained whole now), not over strip markers.
      const photoKeys = ["photos", "photo", "photoData", "evidence", "images", "attachments"];
      let hasPhoto = false;
      for (const k of photoKeys) {
        if (!(k in doc)) continue;
        hasPhoto = true;
        const v = doc[k];
        if (Array.isArray(v)) {
          counts.photoArrays++;
          for (const el of v) {
            if (typeof el === "string") {
              counts.photoElems++;
              counts.photoChars += el.length;
            }
          }
        } else if (typeof v === "string") {
          counts.photoElems++;
          counts.photoChars += v.length;
        }
      }
      if (hasPhoto) counts.photoDocs++;
      if ("dept" in doc) pushVocab(vocab.dept, doc.dept, 80);
      if ("location" in doc) pushVocab(vocab.location, doc.location, 80);
      if ("workZone" in doc) pushVocab(vocab.workZone, doc.workZone, 80);
      lines.push(JSON.stringify(doc));
    }
    if (ceilingHit) break;
    const last = docs[docs.length - 1];
    cursor = last.document.name;
    if (docs.length < 500 || page.some((x) => x && !x.document)) break;
  }

  // Sample vocabularies: most frequent values (report.json keeps full counts).
  const vocabReport = {};
  for (const [name, v] of Object.entries(vocab)) {
    const entries = Object.entries(v.counts).sort((a, b) => b[1] - a[1]);
    vocabReport[name] = {
      distinct: entries.length,
      top: entries.slice(0, 15).map(([value, n]) => ({ value, n })),
    };
  }

  return {
    collection,
    counts: {
      ...counts,
      photoPayload: {
        docsWithField: counts.photoDocs,
        arrays: counts.photoArrays,
        elements: counts.photoElems,
        chars: counts.photoChars,
        approxKB: Math.round(counts.photoChars / 1024),
      },
      strippedPayloadKB: Math.round(meta.strippedChars / 1024),
    },
    census: { fieldCount: Object.keys(census.keys).length, fieldPresence: census.keys },
    vocab: vocabReport,
    lines,
  };
}

async function main() {
  console.log(`Legacy Firestore read-only inventory — project ${FB.projectId}`);
  mkdirSync(OUT_DIR, { recursive: true });
  const manifest = {
    generatedAt: new Date().toISOString(),
    source: `read-only :runQuery (firebase.js anonymous channel) on ${FB.projectId}`,
    note: "NOT the durable backup — a user-owned console export with an off-repo copy (ADR-003) is still required before cutover.",
    collections: {},
  };

  const results = {};
  for (const c of COLLECTIONS) {
    try {
      const inv = await inventoryCollection(c);
      const file = `${OUT_DIR}/${c}.ndjson`;
      const content = inv.lines.join("\n") + (inv.lines.length ? "\n" : "");
      writeFileSync(file, content, "utf8");
      const sha = createHash("sha256").update(content).digest("hex");
      manifest.collections[c] = {
        count: inv.counts.total,
        file,
        sha256: sha,
        bytes: Buffer.byteLength(content),
      };
      const { lines, collection, ...rest } = inv;
      results[collection] = rest;
      const ct = inv.counts;
      const range = ct.createdAtRange
        ? `${new Date(ct.createdAtRange[0]).toISOString().slice(0, 10)} → ${new Date(ct.createdAtRange[1]).toISOString().slice(0, 10)}`
        : "n/a";
      const vocabBits = Object.entries(inv.vocab)
        .filter(([, v]) => v.distinct > 0)
        .map(([name, v]) => `${name}: ${v.distinct} distinct`)
        .join(" · ");
      report(
        "PASS",
        `${c}: ${ct.total} docs (${ct.deleted} soft-deleted) · createdAt missing ${ct.createdAtMissing} · range ${range}`,
        `${inv.census.fieldCount} fields · photos ≈ ${ct.photoPayload.approxKB} KB (${ct.photoPayload.elements} elems / ${ct.photoPayload.arrays} docs) · stripped ${ct.strippedPayloadKB} KB · ${vocabBits}`
      );
    } catch (e) {
      report("FAIL", `${c}: ${e.message}`);
    }
  }

  writeFileSync(`${OUT_DIR}/report.json`, JSON.stringify(results, null, 2), "utf8");
  writeFileSync(`${OUT_DIR}/manifest.json`, JSON.stringify(manifest, null, 2), "utf8");
  report(failures === 0 ? "PASS" : "FAIL", "inventory run finished", "report.json + manifest.json written under " + OUT_DIR);
}

await main();
process.exit(failures === 0 ? 0 : 1);
