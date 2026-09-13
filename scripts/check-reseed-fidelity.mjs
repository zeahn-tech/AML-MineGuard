// One-off fidelity check: does …102 reseed reproduce the authoritative
// seed blocks of …030 (+…073) and …094 verbatim? Pure file analysis, no network.
import { readFileSync, readdirSync } from "node:fs";

const DIR = "supabase/migrations";
const files = readdirSync(DIR).sort();

function load(pred, label) {
  const f = files.find(pred);
  if (!f) throw new Error("migration not found: " + label);
  return readFileSync(DIR + "/" + f, "utf8");
}

const m030 = load((f) => f.startsWith("20260903000030"), "030");
const m073 = load((f) => f.startsWith("20260903000073"), "073");
const m094 = load((f) => f.startsWith("20260903000094"), "094");
const m102 = readFileSync(DIR + "/20260903000102_reseed_catalog.sql", "utf8");

// ---- block extraction -------------------------------------------------------
function blockBetween(text, startMarker, endMarker) {
  const i = text.indexOf(startMarker);
  if (i < 0) return "";
  const j = text.indexOf(endMarker, i);
  return j < 0 ? text.slice(i) : text.slice(i, j + endMarker.length);
}

function tuples(block, re) {
  const out = [];
  let m;
  while ((m = re.exec(block)) !== null) out.push(m.slice(1).map((s) => s.trim()));
  return out;
}

// ---- permission/role/plan sets ----------------------------------------------
function allInsertTuples(text, table, tupleRe) {
  // Process every `insert into <table>` segment; take each up to its terminator.
  const out = new Map();
  const parts = text.split("insert into " + table);
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i];
    const end = seg.search(/on conflict|returning|;\s*\n/);
    const body = end >= 0 ? seg.slice(0, end) : seg;
    for (const t of tuples(body, tupleRe)) if (!out.has(t[0])) out.set(t[0], t[1]);
  }
  return out;
}

const perms030 = allInsertTuples(m030, "public.permissions", /'([a-z_]+\.[a-z_]+)'\s*,\s*'([a-z_]+)'/g);
const perms073 = allInsertTuples(m073, "public.permissions", /'([a-z_]+\.[a-z_]+)'\s*,\s*'([a-z_]+)'/g);
const srcPerms = new Map([...perms030, ...perms073]);

const roles030 = allInsertTuples(m030, "public.roles", /'([a-z_]+)'\s*,\s*'[^']+'\s*,\s*'(platform|government|organization)'/g);

const plans094 = allInsertTuples(m094, "public.plans", /'([a-z_]+)'\s*,\s*'[^']+'\s*,\s*(null|\d+)\s*,\s*(null|\d+)\s*,\s*('\{[^}]*\}')/g);

const perms102 = allInsertTuples(m102, "public.permissions", /'([a-z_]+\.[a-z_]+)'\s*,\s*'([a-z_]+)'/g);
const roles102 = allInsertTuples(m102, "public.roles", /'([a-z_]+)'\s*,\s*'[^']+'\s*,\s*'(platform|government|organization)'/g);
const plans102 = allInsertTuples(m102, "public.plans", /'([a-z_]+)'\s*,\s*'[^']+'\s*,\s*(null|\d+)\s*,\s*(null|\d+)\s*,\s*('\{[^}]*\}')/g);

let bad = 0;
function diffSets(label, src, tgt, fmt) {
  const missing = [...src.keys()].filter((k) => !tgt.has(k));
  const extra = [...tgt.keys()].filter((k) => !src.has(k));
  const attrDiff = [...src.keys()].filter((k) => tgt.has(k) && src.get(k) !== tgt.get(k));
  console.log(`${label}: source=${src.size} target=${tgt.size} missing=${missing.length} extra=${extra.length} attrDiff=${attrDiff.length}`);
  if (missing.length) { bad++; console.log("  MISSING:", missing.join(", ")); }
  if (extra.length) { bad++; console.log("  EXTRA:", extra.join(", ")); }
  if (attrDiff.length) { bad++; console.log("  ATTR-DIFF:", attrDiff.map((k) => `${k}: src=${fmt(src.get(k))} tgt=${fmt(tgt.get(k))}`).join("; ")); }
}

diffSets("permissions", srcPerms, perms102, (v) => v);
diffSets("roles", roles030, roles102, (v) => v);
diffSets("plans", plans094, plans102, (v) => v);

// ---- role→permission bundles (statement-scoped) ------------------------------
function bundlesOf(text, permUniverse) {
  const map = new Map(); // roleCode -> Set(permissionCode)
  const parts = text.split("insert into public.role_permissions");
  for (let i = 1; i < parts.length; i++) {
    const stmt = parts[i].split(/insert into public\./).find((s) => true) || parts[i];
    const body = stmt.slice(0, stmt.indexOf(";") >= 0 ? stmt.indexOf(";") : stmt.length);
    // roles
    const roleIn = body.match(/where r\.code\s+in\s*\(([^)]*)\)/);
    const roleEq = body.match(/where r\.code\s*=\s*'([a-z_]+)'/);
    const roles = roleIn ? [...roleIn[1].matchAll(/'([a-z_]+)'/g)].map((x) => x[1]) : roleEq ? [roleEq[1]] : [];
    // permission set
    let perms = [];
    const exclNe = body.match(/p\.code\s*<>\s*'([a-z_]+\.[a-z_]+)'/);
    const permIn = body.match(/p\.code\s+in\s*\(([^)]*)\)/);
    if (permIn) {
      perms = [...permIn[1].matchAll(/'([a-z_]+\.[a-z_]+)'/g)].map((x) => x[1]);
    } else if (exclNe) {
      perms = [...permUniverse.keys()].filter((p) => p !== exclNe[1]);
    } else {
      perms = [...permUniverse.keys()]; // cross join = all
    }
    for (const r of roles) {
      if (!map.has(r)) map.set(r, new Set());
      for (const p of perms) map.get(r).add(p);
    }
  }
  return map;
}

const srcBundles = bundlesOf(m030 + "\n" + m073, srcPerms);
const tgtBundles = bundlesOf(m102, perms102);

const allRoles = [...new Set([...srcBundles.keys(), ...tgtBundles.keys()])].sort();
for (const role of allRoles) {
  const s = srcBundles.get(role) || new Set();
  const t = tgtBundles.get(role) || new Set();
  const missing = [...s].filter((p) => !t.has(p));
  const extra = [...t].filter((p) => !s.has(p));
  if (missing.length || extra.length) {
    bad++;
    console.log(`BUNDLE DIFF ${role}: src=${s.size} tgt=${t.size}`);
    if (missing.length) console.log("  missing in 102:", missing.join(", "));
    if (extra.length) console.log("  extra in 102:", extra.join(", "));
  } else {
    console.log(`BUNDLE OK ${role} (${s.size} perms)`);
  }
}

console.log(bad === 0 ? "\nFIDELITY: PASS — reseed matches authoritative seeds" : `\nFIDELITY: FAIL (${bad} diffs)`);
process.exit(bad === 0 ? 0 : 1);
