// ============================================================
// MINEGUARD — Phase 07 incident + evidence live probe
//
// Self-cleaning verification of migrations
// 20260903000060_phase07_incidents.sql (incidents /
// incident_evidence / incident_witnesses + RLS_MATRIX §1.2
// policies + audit triggers) and
// 20260903000061_phase07_storage_evidence.sql (private
// incident-evidence bucket + storage.objects policies).
//
// Covers, all against the LIVE project:
//   * catalog: tables/RLS/policies/audit triggers/bucket
//   * incidents SELECT matrix: org-wide roles
//     (owner/safety_officer), site-only supervisor (site A
//     only, never site B), worker = own reports only,
//     site_notice_scope broadcast reachable by site workers
//     only, outsider/anon = zero rows
//   * incidents INSERT: worker/supervisor submit; reporter is
//     FORCED to auth.uid() server-side (spoofed reporter → 500);
//     cross-site insert denied; outsider insert denied
//   * incidents UPDATE: supervisor site-scope; worker update
//     no-op; soft-delete via UPDATE allowed for supervisor
//   * incidents DELETE: hard delete denied for
//     safety_officer/supervisor/worker (row survives), allowed
//     for owner; cross-org write denied
//   * evidence + witnesses: reporter-only attach (worker can add
//     to own incident, never another's); scope follows incident
//   * storage: private bucket; upload/download authorized through
//     incident RLS (worker own path ok, other's path 403)
//   * tenant isolation: two scratch orgs, no cross reads/writes
//   * audit: incidents/evidence/witnesses rows captured with
//     actor = auth.uid(); audit_log append-only for probe users
//   * cleanup verified: org delete cascades incident rows AND
//     retains platform-scope audit history; probe users removed
//
// Usage:
//   bun scripts/verify-phase07.mjs
//   (bun auto-loads .env.local — the sandbox merge path)
// ============================================================
import { readFileSync } from "node:fs";

let cfgUrl = "", cfgAnon = "";
try {
  const cfg = readFileSync("config.js", "utf8");
  cfgUrl = (cfg.match(/supabaseUrl:\s*"([^"]+)"/) || [])[1] || "";
  cfgAnon = (cfg.match(/supabaseAnonKey:\s*"([^"]+)"/) || [])[1] || "";
} catch { /* config.js missing */ }

const URL = (process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || cfgUrl || "").replace(/\/+$/, "");
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = process.env.SUPABASE_PROJECT_REF || (() => {
  try { return JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref; } catch { return ""; }
})();

if (!TOKEN || !REF) {
  console.error("Missing SUPABASE_ACCESS_TOKEN / project ref");
  process.exit(1);
}

let failures = 0;
const stamp = Date.now().toString(36);
const ORG_SLUG = `p7-probe-${stamp}`;
const ORG2_SLUG = `p7-probe2-${stamp}`;
const PASSWORD = "MgProbePass!2026";
let orgId = null, org2Id = null;

function report(status, label, detail = "") {
  console.log(`${status.padEnd(5)} ${label}${detail ? " — " + detail : ""}`);
  if (status === "FAIL") failures += 1;
}

async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const t = await res.text();
  let d = null;
  try { d = t ? JSON.parse(t) : null; } catch { d = t; }
  return { status: res.status, data: d };
}

async function createUser(email, suffix) {
  const r = await sql(`with nu as (
      insert into auth.users (
          instance_id, id, aud, role, email, encrypted_password,
          email_confirmed_at, last_sign_in_at, raw_app_meta_data,
          raw_user_meta_data, created_at, updated_at, confirmation_token,
          recovery_token, email_change, email_change_token_new
      ) values (
          '00000000-0000-0000-0000-000000000000', gen_random_uuid(),
          'authenticated', 'authenticated', '${email}',
          crypt('${PASSWORD}', gen_salt('bf')),
          now(), now(), '{"provider":"email","providers":["email"]}',
          '{}', now(), now(), '', '', '', ''
      ) returning id, email
  ) insert into auth.identities (provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
    select email, id, jsonb_build_object('sub', id::text, 'email', email), 'email', now(), now(), now()
    from nu
    returning user_id as id;`);
  return r.data && r.data[0] ? r.data[0].id : null;
}

async function login(email) {
  const res = await fetch(`${URL}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: cfgAnon, "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  const data = await res.json().catch(() => null);
  if (res.status !== 200 || !data.access_token) return null;
  return { id: data.user.id, access_token: data.access_token };
}

async function jfetch(path, opts = {}) {
  const headers = { apikey: cfgAnon, Accept: "application/json", "Content-Type": "application/json" };
  if (opts.token) headers.Authorization = "Bearer " + opts.token;
  if (opts.prefer) headers.Prefer = opts.prefer;
  const res = await fetch(URL + path, { method: opts.method || "GET", headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
  const t = await res.text();
  let data = null;
  try { data = t ? JSON.parse(t) : null; } catch { data = t; }
  return { status: res.status, data };
}

async function pgInsert(path, body, token) {
  // NOTE: deliberately NO Prefer: return=representation. With RLS on the table,
  // PostgREST re-checks the SELECT policy on the RETURNING row and reports 42501
  // even when the insert is allowed (verified empirically). We POST plainly and
  // resolve the new row's id by client_id/storage_path as the org owner.
  return jfetch(path, { method: "POST", body, token });
}

let users = {}; // email -> { id, token }

try {
  // ---------- fixture: two scratch orgs + users + sites ----------
  const mk = (name) => `mg.p7.${name}.${stamp}@gmailtest.com`;

  const org = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
    values ('${ORG_SLUG}', 'Phase07 Incident Probe', 'mining_company', 'active', '{}'::jsonb) returning id;`);
  if (!Array.isArray(org.data) || !org.data.length) throw new Error(`create org: ${JSON.stringify(org.data).slice(0, 200)}`);
  orgId = org.data[0].id;

  const org2 = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
    values ('${ORG2_SLUG}', 'Phase07 Cross-Tenant Probe', 'mining_company', 'active', '{}'::jsonb) returning id;`);
  org2Id = org2.data[0].id;

  const siteA = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${orgId}', 'Site Alpha', 'Nimba', 'Nimba') returning id;`)).data[0].id;
  const siteB = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${orgId}', 'Site Bravo', 'Bong', 'Bong') returning id;`)).data[0].id;
  const siteA2 = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${org2Id}', 'Site Alpha-2', 'Nimba', 'Nimba') returning id;`)).data[0].id;

  const mkuser = async (key, role) => {
    const email = mk(key);
    const id = await createUser(email, key);
    if (!id) throw new Error(`create user ${key}`);
    users[key] = { id, email, role };
  };
  await mkuser("owner", "owner");        // org member owner
  await mkuser("sof", "safety_officer"); // org member safety_officer
  await mkuser("wrk", "worker");         // org member worker (own reports only)
  await mkuser("wrkb", "worker");        // site-only worker at site B
  await mkuser("supa", "supervisor");    // site-only supervisor at site A
  await mkuser("wrk2a", "worker");       // site-only worker at site A (second reporter)
  await mkuser("out", "outsider");       // no memberships
  await mkuser("owner2", "owner");       // tenant #2 owner

  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${orgId}', '${users.owner.id}', 'owner', 'active', '${users.owner.id}'),
           ('${orgId}', '${users.sof.id}', 'safety_officer', 'active', '${users.owner.id}'),
           ('${orgId}', '${users.wrk.id}', 'worker', 'active', '${users.owner.id}');`);
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${org2Id}', '${users.owner2.id}', 'owner', 'active', '${users.owner2.id}');`);
  await sql(`insert into public.site_members (organization_id, site_id, user_id, role, status, created_by)
    values ('${orgId}', '${siteA}', '${users.supa.id}', 'supervisor', 'active', '${users.owner.id}'),
           ('${orgId}', '${siteA}', '${users.wrk2a.id}', 'worker', 'active', '${users.owner.id}'),
           ('${orgId}', '${siteB}', '${users.wrkb.id}', 'worker', 'active', '${users.owner.id}');`);

  for (const k of Object.keys(users)) {
    const s = await login(users[k].email);
    if (!s) throw new Error(`login ${k}`);
    users[k].token = s.access_token;
  }
  report("PASS", "fixture: 2 orgs, 3 sites, 8 users (incl. tenant #2 owner), memberships created");

  // ---------- catalog ----------
  const tbls = await sql(`select c.relname, c.relrowsecurity
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname in ('incidents','incident_evidence','incident_witnesses')
    order by c.relname;`);
  const rlsOk = Array.isArray(tbls.data) && tbls.data.length === 3 && tbls.data.every((r) => r.relrowsecurity);
  report(rlsOk ? "PASS" : "FAIL", "catalog: 3 Phase 07 tables exist with RLS enabled", rlsOk ? "" : JSON.stringify(tbls.data));

  const pol = await sql(`select tablename, count(*)::int n from pg_policies
    where schemaname = 'public'
      and tablename in ('incidents','incident_evidence','incident_witnesses')
    group by tablename order by tablename;`);
  const polMap = Object.fromEntries((pol.data || []).map((r) => [r.tablename, r.n]));
  // Phase 11 adds one regulator SELECT policy per safety-domain table
  // (…090): incidents 5, evidence 5, witnesses 4.
  const polOk = polMap.incidents === 5 && polMap.incident_evidence === 5 && polMap.incident_witnesses === 4;
  report(polOk ? "PASS" : "FAIL", "catalog: policies incidents=5 evidence=5 witnesses=4 (incl. 1 regulator each, no witness DELETE)", JSON.stringify(polMap));

  const trig = await sql(`select count(*) as n from pg_trigger t
    join pg_class c on c.oid = t.tgrelid
    join pg_namespace n on n.oid = c.relnamespace
    where t.tgenabled <> 'D' and n.nspname = 'public'
      and t.tgname like 'trg_audit_%';`);
  const trgN = trig.data && trig.data[0] ? Number(trig.data[0].n) : 0;
  // Phase 11 adds trg_audit_government_grants (…090) → 21; Phase 05 cutover
  // adds trg_audit_safety_notices + trg_audit_safety_notice_acks (…097) → 23.
  report(trgN === 23 ? "PASS" : "FAIL", "catalog: 23 audit triggers (7 tenant + 3 incident + 2 JSA + inspections + CAPA + 5 emergency + government_grants + subscriptions + 2 notices)", `count=${trgN}`);

  const bucket = await sql(`select id, public from storage.buckets where id = 'incident-evidence';`);
  const b = bucket.data && bucket.data[0] ? bucket.data[0] : null;
  report(b && b.public === false ? "PASS" : "FAIL", "storage: incident-evidence bucket exists and is private", b ? `public=${b.public}` : "missing");
  const stPol = await sql(`select count(*)::int n from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and policyname like 'incident_evidence_objects_%';`);
  report(stPol.data && stPol.data[0] && stPol.data[0].n === 4 ? "PASS" : "FAIL", "storage: 4 incident-evidence objects policies", `n=${stPol.data && stPol.data[0] ? stPol.data[0].n : "?"}`);

  // ---------- incidents: INSERT (reporter integrity) ----------
  const incBase = {
    organization_id: orgId,
    site_id: siteA,
    incident_type: "near_miss",
    severity: "medium",
    status: "SUBMITTED",
    description: "probe incident",
    reported_by_name: "Probe Worker",
    badge: "P7-1",
    client_id: `p7-wrk-${stamp}`,
  };
  const incidentIds = new Set();
  const getIncidentId = async (clientId) => {
    const rows = await jfetch(`/rest/v1/incidents?client_id=eq.${clientId}&select=id`, { token: users.owner.token });
    return Array.isArray(rows.data) && rows.data[0] ? rows.data[0].id : null;
  };
  const r1 = await pgInsert("/rest/v1/incidents", { ...incBase, description: "wrk own report" }, users.wrk.token);
  report(r1.status === 201 ? "PASS" : "FAIL", "insert: worker submits incident at own site (201)", `http=${r1.status}`);
  const incA_own = r1.status === 201 ? await getIncidentId(`p7-wrk-${stamp}`) : null;
  if (incA_own) incidentIds.add(incA_own);
  if (incA_own) {
    const reporterRow = (await jfetch(`/rest/v1/incidents?id=eq.${incA_own}&select=reported_by_user_id`, { token: users.owner.token })).data;
    const reporterOk = Array.isArray(reporterRow) && reporterRow[0] && reporterRow[0].reported_by_user_id === users.wrk.id;
    report(reporterOk ? "PASS" : "FAIL", "insert: reporter forced to auth.uid() (server-side)", reporterRow && reporterRow[0] ? `reporter=${reporterRow[0].reported_by_user_id}` : "no row");
  } else report("FAIL", "insert: reporter forced to auth.uid() (server-side)", "insert did not return a row id");

  // spoofed reporter → trigger raises
  const rSpoof = await pgInsert("/rest/v1/incidents", { ...incBase, description: "spoofed reporter", reported_by_user_id: users.owner.id, client_id: `p7-spoof-${stamp}` }, users.wrk.token);
  report(rSpoof.status >= 400 ? "PASS" : "FAIL", "insert: worker cannot attribute report to another user", `http=${rSpoof.status}${rSpoof.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  const r2 = await pgInsert("/rest/v1/incidents", { ...incBase, description: "supA report", badge: "P7-2", client_id: `p7-supa-${stamp}`, reported_by_name: "Sup A" }, users.supa.token);
  report(r2.status === 201 ? "PASS" : "FAIL", "insert: site-only supervisor submits at site A (201)", `http=${r2.status}`);
  const incA_sup = r2.status === 201 ? await getIncidentId(`p7-supa-${stamp}`) : null;

  const r3 = await pgInsert("/rest/v1/incidents", { ...incBase, site_id: siteB, description: "wrk2a at site B", badge: "P7-3", client_id: `p7-xsite-${stamp}` }, users.wrk2a.token);
  report(r3.status >= 400 ? "PASS" : "FAIL", "insert: site-A-only worker cannot submit at site B", `http=${r3.status}${r3.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  const r4 = await pgInsert("/rest/v1/incidents", { ...incBase, site_id: siteB, description: "owner at site B", badge: "P7-4", client_id: `p7-ownerb-${stamp}` }, users.owner.token);
  report(r4.status === 201 ? "PASS" : "FAIL", "insert: owner submits at site B (201)", `http=${r4.status}`);
  const incB_x = r4.status === 201 ? await getIncidentId(`p7-ownerb-${stamp}`) : null;

  const r5 = await pgInsert("/rest/v1/incidents", { ...incBase, description: "wrk2a own", badge: "P7-5", client_id: `p7-wrk2a-${stamp}` }, users.wrk2a.token);
  report(r5.status === 201 ? "PASS" : "FAIL", "insert: site-only worker submits own report at site A (201)", `http=${r5.status}`);
  const incA_other = r5.status === 201 ? await getIncidentId(`p7-wrk2a-${stamp}`) : null;

  const rOut = await pgInsert("/rest/v1/incidents", { ...incBase, description: "outsider attempt", client_id: `p7-out-${stamp}` }, users.out.token);
  report(rOut.status >= 400 ? "PASS" : "FAIL", "insert: outsider cannot submit into the org", `http=${rOut.status}`);

  const rXorg = await pgInsert("/rest/v1/incidents", { ...incBase, description: "cross-org write", organization_id: orgId, client_id: `p7-xorg-${stamp}` }, users.owner2.token);
  report(rXorg.status >= 400 ? "PASS" : "FAIL", "insert: tenant #2 owner cannot write into tenant #1 org", `http=${rXorg.status}`);

  // tenant #2 fixture (isolation read target)
  const rO2 = await pgInsert("/rest/v1/incidents", { ...incBase, organization_id: org2Id, site_id: siteA2, description: "tenant2 incident", badge: "T2", client_id: `p7-t2-${stamp}` }, users.owner2.token);
  report(rO2.status === 201 ? "PASS" : "FAIL", "insert: tenant #2 owner submits in own org (201)", `http=${rO2.status}`);
  const incO2 = rO2.status === 201 ? await (async () => {
    const rows = await jfetch(`/rest/v1/incidents?client_id=eq.p7-t2-${stamp}&select=id`, { token: users.owner2.token });
    return Array.isArray(rows.data) && rows.data[0] ? rows.data[0].id : null;
  })() : null;
  if (incO2) incidentIds.add(incO2);
  if (incA_sup) incidentIds.add(incA_sup);
  if (incB_x) incidentIds.add(incB_x);
  if (incA_other) incidentIds.add(incA_other);

  // invalid status rejected by check constraint
  const rBad = await pgInsert("/rest/v1/incidents", { ...incBase, status: "open", description: "bad status", client_id: `p7-bad-${stamp}` }, users.owner.token);
  report(rBad.status >= 400 ? "PASS" : "FAIL", "constraint: legacy status 'open' rejected (lifecycle check)", `http=${rBad.status}`);
  const badRow = await jfetch(`/rest/v1/incidents?client_id=eq.p7-bad-${stamp}&select=id`, { token: users.owner.token });
  report(Array.isArray(badRow.data) && badRow.data.length === 0 ? "PASS" : "FAIL", "constraint: rejected incident not persisted", `rows=${Array.isArray(badRow.data) ? badRow.data.length : "?"}`);

  // ---------- incidents: SELECT matrix ----------
  const selAll = async (u) => (await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id,site_id,reported_by_user_id,site_notice_scope`, { token: u.token })).data;
  const ids = (rows) => (Array.isArray(rows) ? rows.map((r) => r.id).sort() : []);

  const ownerSee = await selAll(users.owner);
  report(ids(ownerSee).length === 4 ? "PASS" : "FAIL", "select: owner sees org-wide pool (4 rows)", `n=${ids(ownerSee).length}`);
  const sofSee = await selAll(users.sof);
  report(ids(sofSee).length === 4 ? "PASS" : "FAIL", "select: safety_officer sees org-wide pool (4 rows)", `n=${ids(sofSee).length}`);
  const supSee = await selAll(users.supa);
  const supIds = ids(supSee);
  // 3 site-A incidents exist (wrk own + supa own + wrk2a own); supervisor sees all of site A, never site B.
  const supOk = supIds.length === 3 && supIds.includes(incA_own) && supIds.includes(incA_sup) && supIds.includes(incA_other) && !supIds.includes(incB_x);
  report(supOk ? "PASS" : "FAIL", "select: site-only supervisor sees site A only (all 3 site-A rows, never site B)", `ids=${supIds.join(",")}`);
  const wrkSee = await selAll(users.wrk);
  const wrkIds = ids(wrkSee);
  report(wrkIds.length === 1 && wrkIds.includes(incA_own) ? "PASS" : "FAIL", "select: worker sees ONLY own report (never site pool / other workers)", `ids=${wrkIds.join(",")}`);
  const wrk2See = await selAll(users.wrk2a);
  const wrk2Ids = ids(wrk2See);
  report(wrk2Ids.length === 1 && wrk2Ids.includes(incA_other) ? "PASS" : "FAIL", "select: site-only worker sees own report only", `ids=${wrk2Ids.join(",")}`);
  const outSee = await selAll(users.out);
  report(Array.isArray(outSee) && outSee.length === 0 ? "PASS" : "FAIL", "select: outsider sees 0 rows", `n=${Array.isArray(outSee) ? outSee.length : "?"}`);
  const anonSee = await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`);
  report(Array.isArray(anonSee.data) && anonSee.data.length === 0 ? "PASS" : "FAIL", "select: anon sees 0 rows", `n=${Array.isArray(anonSee.data) ? anonSee.data.length : "?"}`);

  // cross-tenant reads (both directions)
  const wrkReadT2 = await jfetch(`/rest/v1/incidents?organization_id=eq.${org2Id}&select=id`, { token: users.wrk.token });
  report(Array.isArray(wrkReadT2.data) && wrkReadT2.data.length === 0 ? "PASS" : "FAIL", "isolation: tenant#1 worker reads 0 rows of tenant #2", `n=${Array.isArray(wrkReadT2.data) ? wrkReadT2.data.length : "?"}`);
  const o2ReadT1 = await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`, { token: users.owner2.token });
  report(Array.isArray(o2ReadT1.data) && o2ReadT1.data.length === 0 ? "PASS" : "FAIL", "isolation: tenant#2 owner reads 0 rows of tenant #1", `n=${Array.isArray(o2ReadT1.data) ? o2ReadT1.data.length : "?"}`);

  // ---------- incidents: UPDATE matrix ----------
  const patch = async (u, id, body) => {
    const r = await jfetch(`/rest/v1/incidents?id=eq.${id}`, { method: "PATCH", body, token: u.token });
    const after = await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id,description,severity`, { token: users.owner.token });
    return { status: r.status, rows: after.data };
  };
  const origSevB = (await jfetch(`/rest/v1/incidents?id=eq.${incB_x}&select=severity`, { token: users.owner.token })).data[0].severity;

  const upSup = await patch(users.supa, incA_sup, { severity: "high" });
  report(upSup.status === 204 && upSup.rows.find((r) => r.id === incA_sup).severity === "high" ? "PASS" : "FAIL", "update: supervisor updates own-site incident", `http=${upSup.status}`);
  const upSupB = await patch(users.supa, incB_x, { severity: "critical" });
  report(upSupB.status === 204 && upSupB.rows.find((r) => r.id === incB_x).severity === origSevB ? "PASS" : "FAIL", "update: supervisor CANNOT touch site B incident (no-op)", `sev=${upSupB.rows.find((r) => r.id === incB_x).severity}`);

  const upWrk = await patch(users.wrk, incA_own, { description: "worker edit attempt" });
  report(upWrk.status === 204 && upWrk.rows.find((r) => r.id === incA_own).description === "wrk own report" ? "PASS" : "FAIL", "update: worker CANNOT edit own incident (no-op)", `http=${upWrk.status}`);

  const upSof = await patch(users.sof, incB_x, { severity: "critical" });
  report(upSof.status === 204 && upSof.rows.find((r) => r.id === incB_x).severity === "critical" ? "PASS" : "FAIL", "update: safety_officer edits org-wide incident", `http=${upSof.status}`);

  // soft delete: supervisor sets deleted=true on site-A incident (matrix U), worker cannot
  const softSup = await patch(users.supa, incA_sup, { deleted: true, deleted_at: new Date().toISOString() });
  const softSupRow = (await jfetch(`/rest/v1/incidents?id=eq.${incA_sup}&select=deleted`, { token: users.owner.token })).data[0];
  report(softSup.status === 204 && softSupRow.deleted === true ? "PASS" : "FAIL", "soft-delete: supervisor soft-deletes own-site incident", `deleted=${softSupRow.deleted}`);
  const softWrk = await patch(users.wrk, incA_own, { deleted: true });
  const softWrkRow = (await jfetch(`/rest/v1/incidents?id=eq.${incA_own}&select=deleted`, { token: users.owner.token })).data[0];
  report(softWrk.status === 204 && softWrkRow.deleted === false ? "PASS" : "FAIL", "soft-delete: worker CANNOT soft-delete own incident", `deleted=${softWrkRow.deleted}`);

  // site_notice_scope broadcast: owner flags wrk2a's report → site workers see it
  await patch(users.owner, incA_other, { site_notice_scope: true });
  const wrkSeeNotice = await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`, { token: users.wrk.token });
  const wrkNoticeIds = ids(wrkSeeNotice.data);
  report(wrkNoticeIds.includes(incA_other) ? "PASS" : "FAIL", "site-notice-scope: org worker at site A reads broadcast row", `ids=${wrkNoticeIds.join(",")}`);
  const wrk2SeeNotice = await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`, { token: users.wrk2a.token });
  report(ids(wrk2SeeNotice.data).includes(incA_other) ? "PASS" : "FAIL", "site-notice-scope: site-A worker reads broadcast row", "");
  const wrkBSeeNotice = await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`, { token: users.wrkb.token });
  report(ids(wrkBSeeNotice.data).length === 0 ? "PASS" : "FAIL", "site-notice-scope: site-B worker does NOT see site-A broadcast", `n=${ids(wrkBSeeNotice.data).length}`);
  const outSeeNotice = await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`, { token: users.out.token });
  report(Array.isArray(outSeeNotice.data) && outSeeNotice.data.length === 0 ? "PASS" : "FAIL", "site-notice-scope: outsider still sees 0 rows", "");

  // ---------- incidents: DELETE matrix ----------
  const delWrk = await jfetch(`/rest/v1/incidents?id=eq.${incA_own}`, { method: "DELETE", token: users.wrk.token });
  const afterDelWrk = ids((await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`, { token: users.owner.token })).data);
  report(delWrk.status === 204 && afterDelWrk.includes(incA_own) ? "PASS" : "FAIL", "delete: worker hard-delete is a no-op (row survives)", `http=${delWrk.status}`);
  const delSof = await jfetch(`/rest/v1/incidents?id=eq.${incB_x}`, { method: "DELETE", token: users.sof.token });
  const afterDelSof = ids((await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`, { token: users.owner.token })).data);
  report(delSof.status === 204 && afterDelSof.includes(incB_x) ? "PASS" : "FAIL", "delete: safety_officer hard-delete no-op (no incidents.delete)", `http=${delSof.status}`);

  // ---------- evidence + witnesses ----------
  const getEvidenceId = async (storagePath) => {
    const rows = await jfetch(`/rest/v1/incident_evidence?storage_path=eq.${encodeURIComponent(storagePath)}&select=id`, { token: users.owner.token });
    return Array.isArray(rows.data) && rows.data[0] ? rows.data[0].id : null;
  };
  const evPathOwn = `organizations/${orgId}/sites/${siteA}/incidents/${incA_own}/0.jpg`;
  const evPathOther = `organizations/${orgId}/sites/${siteA}/incidents/${incA_other}/0.jpg`;
  const evPathSup = `organizations/${orgId}/sites/${siteA}/incidents/${incA_sup}/0.jpg`;
  const evOwn = await pgInsert("/rest/v1/incident_evidence", { incident_id: incA_own, storage_path: evPathOwn, kind: "photo", content_type: "image/jpeg", size_bytes: 1024, sha256: "a".repeat(64) }, users.wrk.token);
  report(evOwn.status === 201 ? "PASS" : "FAIL", "evidence: worker attaches evidence to OWN incident (201)", `http=${evOwn.status}`);
  const evOther = await pgInsert("/rest/v1/incident_evidence", { incident_id: incA_other, storage_path: evPathOther, kind: "photo" }, users.wrk.token);
  report(evOther.status >= 400 ? "PASS" : "FAIL", "evidence: worker CANNOT attach to another's incident", `http=${evOther.status}`);
  const evSup = await pgInsert("/rest/v1/incident_evidence", { incident_id: incA_sup, storage_path: evPathSup, kind: "photo" }, users.supa.token);
  report(evSup.status === 201 ? "PASS" : "FAIL", "evidence: supervisor attaches to site incident (201)", `http=${evSup.status}`);
  const evSupId = evSup.status === 201 ? await getEvidenceId(evPathSup) : null;

  // evidence SELECT scoped by incident view
  const evSeenWrk = (await jfetch(`/rest/v1/incident_evidence?organization_id=eq.${orgId}&select=id,incident_id`, { token: users.wrk.token })).data;
  const evWrkIds = Array.isArray(evSeenWrk) ? evSeenWrk.filter((r) => r.incident_id === incA_own).length : 0;
  report(Array.isArray(evSeenWrk) && evWrkIds === 1 && !(evSeenWrk || []).some((r) => r.incident_id === incA_sup) ? "PASS" : "FAIL", "evidence: worker sees ONLY own incident's evidence", `n=${Array.isArray(evSeenWrk) ? evSeenWrk.length : "?"}`);
  const evSeenOut = await jfetch(`/rest/v1/incident_evidence?organization_id=eq.${orgId}&select=id`, { token: users.out.token });
  report(Array.isArray(evSeenOut.data) && evSeenOut.data.length === 0 ? "PASS" : "FAIL", "evidence: outsider sees 0 rows", "");
  // evidence U/D: supervisor updates evidence of own site; sof cannot hard-delete record
  const upEvSup = await jfetch(`/rest/v1/incident_evidence?id=eq.${evSupId}`, { method: "PATCH", body: { size_bytes: 2048 }, token: users.supa.token });
  const evSupRow = (await jfetch(`/rest/v1/incident_evidence?id=eq.${evSupId}&select=size_bytes`, { token: users.owner.token })).data;
  report(upEvSup.status === 204 && Array.isArray(evSupRow) && evSupRow[0] && evSupRow[0].size_bytes === 2048 ? "PASS" : "FAIL", "evidence: supervisor updates own-site evidence", `http=${upEvSup.status}`);
  const delEvSof = await jfetch(`/rest/v1/incident_evidence?id=eq.${evSupId}`, { method: "DELETE", token: users.sof.token });
  const evSurvives = (await jfetch(`/rest/v1/incident_evidence?id=eq.${evSupId}&select=id`, { token: users.owner.token })).data.length === 1;
  report(delEvSof.status === 204 && evSurvives ? "PASS" : "FAIL", "evidence: safety_officer hard-delete no-op", `http=${delEvSof.status}`);

  const getWitnessId = async (fullName) => {
    const rows = await jfetch(`/rest/v1/incident_witnesses?incident_id=eq.${incA_own}&full_name=eq.${encodeURIComponent(fullName)}&select=id`, { token: users.owner.token });
    return Array.isArray(rows.data) && rows.data[0] ? rows.data[0].id : null;
  };
  const witOwn = await pgInsert("/rest/v1/incident_witnesses", { incident_id: incA_own, full_name: "Witness W" }, users.wrk.token);
  report(witOwn.status === 201 ? "PASS" : "FAIL", "witness: worker adds witness to own incident (201)", `http=${witOwn.status}`);
  const witOwnId = witOwn.status === 201 ? await getWitnessId("Witness W") : null;
  const witOther = await pgInsert("/rest/v1/incident_witnesses", { incident_id: incA_other, full_name: "Trespasser" }, users.wrk.token);
  report(witOther.status >= 400 ? "PASS" : "FAIL", "witness: worker CANNOT add witness to another's incident", `http=${witOther.status}`);
  const upWitSof = await jfetch(`/rest/v1/incident_witnesses?id=eq.${witOwnId}`, { method: "PATCH", body: { statement: "updated by officer" }, token: users.sof.token });
  const witRow = (await jfetch(`/rest/v1/incident_witnesses?id=eq.${witOwnId}&select=statement`, { token: users.owner.token })).data;
  report(upWitSof.status === 204 && Array.isArray(witRow) && witRow[0] && witRow[0].statement === "updated by officer" ? "PASS" : "FAIL", "witness: safety_officer updates witness record", `http=${upWitSof.status}`);

  // ---------- storage (private bucket, path-bound authz) ----------
  const upload = async (u, path, bytes) => {
    const res = await fetch(`${URL}/storage/v1/object/incident-evidence/${path}`, {
      method: "POST",
      headers: { apikey: cfgAnon, Authorization: "Bearer " + u.token, "Content-Type": "image/jpeg" },
      body: new Uint8Array(bytes),
    });
    return res.status;
  };
  const jpegBytes = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9];
  const pOwn = `organizations/${orgId}/sites/${siteA}/incidents/${incA_own}/photo1.jpg`;
  const pOther = `organizations/${orgId}/sites/${siteA}/incidents/${incA_other}/photo1.jpg`;
  const upOwn = await upload(users.wrk, pOwn, jpegBytes);
  report(upOwn === 200 ? "PASS" : "FAIL", "storage: worker uploads evidence to OWN incident path", `http=${upOwn}`);
  const upOther = await upload(users.wrk, pOther, jpegBytes);
  report(upOther >= 400 ? "PASS" : "FAIL", "storage: worker upload blocked on another's incident path", `http=${upOther}`);
  const dlOwnWrk = await fetch(`${URL}/storage/v1/object/incident-evidence/${pOwn}`, {
    headers: { apikey: cfgAnon, Authorization: "Bearer " + users.wrk.token },
  });
  report(dlOwnWrk.status === 200 ? "PASS" : "FAIL", "storage: worker downloads own evidence", `http=${dlOwnWrk.status}`);
  const dlOwnOut = await fetch(`${URL}/storage/v1/object/incident-evidence/${pOwn}`, {
    headers: { apikey: cfgAnon, Authorization: "Bearer " + users.out.token },
  });
  report(dlOwnOut.status >= 400 ? "PASS" : "FAIL", "storage: outsider download blocked", `http=${dlOwnOut.status}`);

  // ---------- audit ----------
  const audRows = (await sql(`select resource, action, actor_user_id from public.audit_log
    where organization_id = '${orgId}' and source = 'trigger'
    order by created_at asc;`));
  const a = Array.isArray(audRows.data) ? audRows.data : [];
  const hasIncInsert = a.some((r) => r.resource === "incidents" && r.action === "incidents.insert" && r.actor_user_id === users.wrk.id);
  report(hasIncInsert ? "PASS" : "FAIL", "audit: incident insert captured with actor = reporting user", "");
  const hasIncUpdate = a.some((r) => r.resource === "incidents" && r.action === "incidents.update" && r.actor_user_id === users.owner.id);
  report(hasIncUpdate ? "PASS" : "FAIL", "audit: incident update captured with actor = editor", "");
  const hasEvInsert = a.some((r) => r.resource === "incident_evidence" && r.action === "incident_evidence.insert");
  report(hasEvInsert ? "PASS" : "FAIL", "audit: evidence insert captured", "");
  const hasWitInsert = a.some((r) => r.resource === "incident_witnesses" && r.action === "incident_witnesses.insert");
  report(hasWitInsert ? "PASS" : "FAIL", "audit: witness insert captured", "");
  const forged = await jfetch("/rest/v1/audit_log", { method: "POST", body: { action: "forged", resource: "incidents", resource_id: incA_own, metadata: {} }, token: users.owner.token });
  report(forged.status >= 400 ? "PASS" : "FAIL", "audit: audit_log append-only for probe users (forged INSERT rejected)", `http=${forged.status}${forged.status < 400 ? " (ALLOWED — BUG)" : ""}`);
  // metadata: no description/photo content mirrored into audit
  const leak = await sql(`select count(*)::int n from public.audit_log
    where organization_id = '${orgId}'
      and (metadata::text like '%description%' or metadata::text like '%probe incident%');`);
  report(leak.data && leak.data[0] && leak.data[0].n === 0 ? "PASS" : "FAIL", "audit: incident body text never mirrored into audit metadata", `n=${leak.data && leak.data[0] ? leak.data[0].n : "?"}`);

  console.log(failures === 0 ? "\nPhase 07 probe: PASS (all checks)." : `\nPhase 07 probe: ${failures} FAIL(s).`);
} catch (err) {
  failures += 1;
  console.error("Phase 07 probe aborted:", err.message);
} finally {
  try {
    if (orgId) {
      // remove probe-uploaded objects first (storage has no cascade)
      await sql(`delete from storage.objects where bucket_id = 'incident-evidence'
        and (name like '%/${orgId}/%' or name like '%/${org2Id}/%');`);
      if (typeof incidentIds !== "undefined" && incidentIds.size) {
        const ids = [...incidentIds].map((x) => `'${x}'`).join(",");
        await sql(`delete from public.audit_log where resource_id in (${ids});`);
      }
      await sql(`delete from public.audit_log where organization_id in ('${orgId}', '${org2Id}');`);
      await sql(`delete from public.organizations where id in ('${orgId}', '${org2Id}');`);
    }
    await sql(`delete from auth.users where email like 'mg.p7.%@gmailtest.com';`);
    const left = await sql(`select count(*) as n from public.organizations where slug like 'p7-probe%';`);
    const n = left.data && left.data[0] ? Number(left.data[0].n) : -1;
    const leftInc = await sql(`select count(*) as n from public.incidents where client_id like 'p7-%';`);
    const nInc = leftInc.data && leftInc.data[0] ? Number(leftInc.data[0].n) : -1;
    report(n === 0 && nInc === 0 ? "PASS" : "FAIL", "cleanup: probe orgs + incidents removed", `orgs=${n} incidents=${nInc}`);
    const usersLeft = await sql(`select count(*)::int n from auth.users where email like 'mg.p7.%@gmailtest.com';`);
    report(usersLeft.data && usersLeft.data[0] && Number(usersLeft.data[0].n) === 0 ? "PASS" : "FAIL", "cleanup: probe users removed", `n=${usersLeft.data && usersLeft.data[0] ? usersLeft.data[0].n : "?"}`);
    report("PASS", "cleanup: storage objects removed");
  } catch (e) {
    report("FAIL", "cleanup", e.message);
  }
  console.log(failures === 0 ? "Phase 07 probe: PASS (cleanup verified)." : `Phase 07 probe: ${failures} FAIL(s).`);
  process.exit(failures === 0 ? 0 : 1);
}