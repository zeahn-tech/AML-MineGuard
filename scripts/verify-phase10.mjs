// ============================================================
// MINEGUARD — Phase 10 offline-first sync engine live probe
//
// Runs the REAL sync engine (sync-engine.js) with an in-memory
// store (offline-store.js interface) against the LIVE project,
// exercising the production paths the browser uses:
//   * FIFO ordering + EMERGENCY priority (emergency drained first)
//   * client_id idempotency (dedupe + no duplicate server rows)
//   * retry/backoff (transport failure → attempts/backoff, then
//     a later drain succeeds)
//   * conflict detection (stale local update never overwrites a
//     newer server row; mutation lands in 'conflict' state)
//   * RLS reporter integrity (legacy reported_by_name cannot
//     spoof auth.uid() on the incidents table)
//   * attachments: blob → incident-evidence storage → evidence row
//   * tenant isolation (cross-org reads = 0)
//   * cleanup verified (orgs, storage objects, probe users gone)
//
// Usage:
//   bun scripts/verify-phase10.mjs
//   (bun auto-loads .env.local — the sandbox merge path)
// ============================================================
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

const OS = require("../offline-store.js");
const SYNC = require("../sync-engine.js");

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
const ORG_SLUG = `p10-probe-${stamp}`;
const ORG2_SLUG = `p10-probe2-${stamp}`;
const PASSWORD = "MgProbePass!2026";
let orgId = null, org2Id = null;

function report(status, label, detail = "") {
  console.log(`${status.padEnd(5)} ${label}${detail ? " — " + detail : ""}`);
  if (status === "FAIL") failures += 1;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

async function createUser(email) {
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
  const res = await fetch(URL + path, { method: opts.method || "GET", headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
  const t = await res.text();
  let data = null;
  try { data = t ? JSON.parse(t) : null; } catch { data = t; }
  return { status: res.status, data };
}

// ---- in-memory store implementing the offline-store.js interface ----
function memoryStore() {
  const kv = new Map(), outbox = new Map(), records = new Map(), atts = new Map();
  return {
    name: "memory",
    newClientId: (p) => OS.newClientId(p),
    kvGet: (k) => Promise.resolve(kv.get(k)),
    kvSet: (k, v) => Promise.resolve(kv.set(k, v)).then(() => undefined),
    outboxAdd: (m) => Promise.resolve(outbox.set(m.id, m)).then(() => undefined),
    outboxPut: (m) => Promise.resolve(outbox.set(m.id, m)).then(() => undefined),
    outboxRemove: (id) => Promise.resolve(outbox.delete(id)).then(() => undefined),
    outboxAll: () => Promise.resolve([...outbox.values()]),
    recordPut: (r) => Promise.resolve(records.set(r.client_id, r)).then(() => undefined),
    recordGet: (id) => Promise.resolve(records.get(id) || null),
    recordsByEntity: (e) => Promise.resolve([...records.values()].filter((r) => r.entity === e)),
    recordRemove: (id) => Promise.resolve(records.delete(id)).then(() => undefined),
    attachmentPut: (a) => Promise.resolve(atts.set(a.id, a)).then(() => undefined),
    attachmentsByClient: (id) => Promise.resolve([...atts.values()].filter((a) => a.client_id === id)),
    attachmentRemove: (id) => Promise.resolve(atts.delete(id)).then(() => undefined),
    clearAll: () => Promise.resolve().then(() => { kv.clear(); outbox.clear(); records.clear(); atts.clear(); }),
  };
}

let users = {};
let incidentClientIds = [];
let storagePaths = [];

try {
  // ---------- fixture ----------
  const mk = (name) => `mg.p10.${name}.${stamp}@gmailtest.com`;

  const org = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
    values ('${ORG_SLUG}', 'Phase10 Sync Probe', 'mining_company', 'active', '{}'::jsonb) returning id;`);
  if (!Array.isArray(org.data) || !org.data.length) throw new Error(`create org: ${JSON.stringify(org.data).slice(0, 200)}`);
  orgId = org.data[0].id;

  const org2 = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
    values ('${ORG2_SLUG}', 'Phase10 Cross-Tenant Probe', 'mining_company', 'active', '{}'::jsonb) returning id;`);
  org2Id = org2.data[0].id;

  const siteA = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${orgId}', 'Site Alpha', 'Nimba', 'Nimba') returning id;`)).data[0].id;

  const mkuser = async (key, role) => {
    const email = mk(key);
    const id = await createUser(email);
    if (!id) throw new Error(`create user ${key}`);
    users[key] = { id, email, role };
  };
  await mkuser("owner", "owner");     // org member + site member at site A (engine actor)
  await mkuser("worker", "worker");   // org member worker
  await mkuser("owner2", "owner");    // tenant #2 owner (isolation)
  await mkuser("out", "outsider");    // no memberships

  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${orgId}', '${users.owner.id}', 'owner', 'active', '${users.owner.id}'),
           ('${orgId}', '${users.worker.id}', 'worker', 'active', '${users.owner.id}');`);
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${org2Id}', '${users.owner2.id}', 'owner', 'active', '${users.owner2.id}');`);
  await sql(`insert into public.site_members (organization_id, site_id, user_id, role, status, created_by)
    values ('${orgId}', '${siteA}', '${users.owner.id}', 'site_manager', 'active', '${users.owner.id}');`);

  for (const k of Object.keys(users)) {
    const s = await login(users[k].email);
    if (!s) throw new Error(`login ${k}`);
    users[k].token = s.access_token;
  }
  report("PASS", "fixture: 2 orgs, 1 site, 4 users, memberships created");

  // ---------- engine #1: FIFO + emergency priority + idempotency ----------
  const store1 = memoryStore();
  const transport1 = SYNC.postgrestTransport({ url: URL, anonKey: cfgAnon, token: users.owner.token });
  const engine1 = SYNC.createEngine({
    store: store1, transport: transport1,
    auth: { getSession: () => ({ access_token: users.owner.token }) },
    url: URL, anonKey: cfgAnon, token: users.owner.token,
  });

  const legacyIncident = (i) => ({
    name: "Probe Worker " + i, dept: "Drilling Crew B", type: "fall",
    severity: "medium", datetime: new Date(Date.now() - 3600e3 * i).toISOString(),
    location: "Bench 3", description: "Phase10 ordering probe incident " + i,
    action: "First aid applied", witnesses: ["W A", "W B"], lang: "en", savedAt: Date.now(),
  });

  const sA = await engine1.submit("incidents", "insert", legacyIncident(1), {});
  const sB = await engine1.submit("incidents", "insert", legacyIncident(2), {});
  const sE = await engine1.submit("emergency_events", "insert",
    { category: "fire", message: "probe emergency", active: true, startedAt: Date.now() }, {});
  const sC = await engine1.submit("incidents", "insert", legacyIncident(3), {});
  incidentClientIds = [sA.client_id, sB.client_id, sC.client_id];

  const pendingBefore = (await store1.outboxAll()).length;
  report(pendingBefore === 4 ? "PASS" : "FAIL", "queue: 4 mutations queued (3 incidents + 1 emergency)", `n=${pendingBefore}`);

  await engine1.drain();
  const outboxAfter = await store1.outboxAll();
  report(outboxAfter.length === 0 ? "PASS" : "FAIL", "drain: outbox empty after successful drain", `n=${outboxAfter.length}`);

  // server-side order: emergency first (priority), then A, B, C FIFO
  const incRows = (await jfetch(`/rest/v1/incidents?client_id=in.(${incidentClientIds.map((c) => `"${c}"`).join(",")})&select=client_id,created_at&order=created_at.asc`, { token: users.owner.token })).data || [];
  const evRows = (await jfetch(`/rest/v1/emergency_events?client_id=eq.${sE.client_id}&select=client_id,created_at&order=created_at.asc`, { token: users.owner.token })).data || [];
  const merged = [
    ...incRows.map((r) => ({ cid: r.client_id, t: Date.parse(r.created_at) })),
    ...evRows.map((r) => ({ cid: r.client_id, t: Date.parse(r.created_at) })),
  ].sort((a, b) => a.t - b.t);
  const orderOk = merged.length === 4 && merged[0].cid === sE.client_id
    && merged[1].cid === sA.client_id && merged[2].cid === sB.client_id && merged[3].cid === sC.client_id;
  report(orderOk ? "PASS" : "FAIL", "ordering: emergency drained first, then incidents FIFO (A,B,C)", merged.map((m) => m.cid.slice(-6)).join(" > "));

  // RLS reporter integrity: legacy name cannot spoof auth.uid()
  const incA = (await jfetch(`/rest/v1/incidents?client_id=eq.${sA.client_id}&select=reported_by_user_id,reported_by_name`, { token: users.owner.token })).data || [];
  report(incA.length === 1 && incA[0].reported_by_user_id === users.owner.id && incA[0].reported_by_name === "Probe Worker 1"
    ? "PASS" : "FAIL", "rls: reported_by_user_id forced to engine actor (auth.uid), legacy name kept in reported_by_name",
    incA[0] ? `reported_by_user_id=${incA[0].reported_by_user_id}` : "no row");

  // idempotency: re-enqueue same (entity, client_id, op) → dedupe; drain → exactly 1 server row
  const adaptInc = engine1.adapterFor("incidents");
  const ctx = await engine1.resolveContext(true);
  const dupPayload = adaptInc(Object.assign({}, legacyIncident(1), { client_id: sA.client_id }), ctx);
  dupPayload.updated_at = new Date().toISOString();
  await engine1.enqueue("incidents", "insert", dupPayload, {});
  const dupPending = (await store1.outboxAll()).length;
  await engine1.drain();
  const serverCount = await jfetch(`/rest/v1/incidents?client_id=eq.${sA.client_id}&select=id`, { token: users.owner.token });
  report(dupPending === 1 && Array.isArray(serverCount.data) && serverCount.data.length === 1
    ? "PASS" : "FAIL", "idempotency: duplicate enqueue deduped; server has exactly 1 row", `pending=${dupPending} serverRows=${Array.isArray(serverCount.data) ? serverCount.data.length : "?"}`);

  // ---------- engine #2: retry + backoff on transport failure ----------
  const store2 = memoryStore();
  const realT = SYNC.postgrestTransport({ url: URL, anonKey: cfgAnon, token: users.owner.token });
  let flakyUsed = false;
  const flakyTransport = {
    insert: (entity, payload) => {
      if (!flakyUsed) { flakyUsed = true; return Promise.reject(new Error("network down (probe)")); }
      return realT.insert(entity, payload);
    },
    selectByClientId: (e, c) => realT.selectByClientId(e, c),
    update: (e, c, p) => realT.update(e, c, p),
    ping: () => realT.ping(),
  };
  const engine2 = SYNC.createEngine({
    store: store2, transport: flakyTransport,
    auth: { getSession: () => ({ access_token: users.owner.token }) },
    url: URL, anonKey: cfgAnon, token: users.owner.token,
  });
  const adaptJsa = engine2.adapterFor("jsas");
  const jsaClientId = OS.newClientId("p10jsa");
  const jsaPayload = adaptJsa({
    client_id: jsaClientId, worker: "Probe Worker", supervisor: "Super S",
    task: "Bolt tightening", location: "Bench 3", date: "2026-09-08",
    ppeSelected: ["Hard", "Steel-Toe"], lang: "en",
  }, ctx);
  jsaPayload.updated_at = new Date().toISOString();
  await engine2.enqueue("jsas", "insert", jsaPayload, {});

  await engine2.drain(); // first drain: transport throws
  const mAfterFail = (await store2.outboxAll())[0];
  const retryStateOk = mAfterFail && mAfterFail.attempts === 1 && mAfterFail.state === "pending"
    && mAfterFail.next_attempt_at && Date.parse(mAfterFail.next_attempt_at) > Date.now();
  report(retryStateOk ? "PASS" : "FAIL", "backoff: transport failure → attempts=1, pending, next_attempt_at in future",
    mAfterFail ? `attempts=${mAfterFail.attempts} state=${mAfterFail.state}` : "no mutation");

  // simulate time passing: clear the backoff window, drain again → success
  mAfterFail.next_attempt_at = new Date(Date.now() - 1000).toISOString();
  await store2.outboxPut(mAfterFail);
  await engine2.drain();
  const mAfterRetry = await store2.outboxAll();
  const jsaServer = await jfetch(`/rest/v1/jsas?client_id=eq.${jsaClientId}&select=id,task`, { token: users.owner.token });
  report(mAfterRetry.length === 0 && Array.isArray(jsaServer.data) && jsaServer.data.length === 1 && jsaServer.data[0].task === "Bolt tightening"
    ? "PASS" : "FAIL", "retry: second drain succeeds; JSA row lands with no duplicate", `outbox=${mAfterRetry.length} rows=${Array.isArray(jsaServer.data) ? jsaServer.data.length : "?"}`);

  // ---------- conflict: stale local update never overwrites newer server row ----------
  const recA = await store1.recordGet(sA.client_id);
  // bump the server row (simulate a colleague's change)
  const bump = await jfetch(`/rest/v1/incidents?client_id=eq.${sA.client_id}`, {
    method: "PATCH", body: { status: "UNDER_INVESTIGATION", investigation_notes: "colleague update" }, token: users.owner.token,
  });
  // enqueue a STALE update (updated_at backdated) via the same engine
  const stalePayload = adaptInc(Object.assign({}, legacyIncident(1), { client_id: sA.client_id }), ctx);
  stalePayload.status = "SUBMITTED";
  stalePayload.updated_at = "2020-01-01T00:00:00.000Z";
  await engine1.enqueue("incidents", "update", stalePayload, {});
  await engine1.drain();
  const conflictM = (await store1.outboxAll()).find((m) => m.client_id === sA.client_id && m.op === "update");
  const serverAfterConflict = (await jfetch(`/rest/v1/incidents?client_id=eq.${sA.client_id}&select=status,investigation_notes`, { token: users.owner.token })).data || [];
  const conflictOk = conflictM && conflictM.state === "conflict"
    && serverAfterConflict.length === 1 && serverAfterConflict[0].status === "UNDER_INVESTIGATION"
    && serverAfterConflict[0].investigation_notes === "colleague update";
  report(conflictOk ? "PASS" : "FAIL", "conflict: stale update → 'conflict' state; newer server row NOT overwritten",
    conflictM ? `state=${conflictM.state}` : "no mutation");

  // ---------- attachments: blob → storage → incident_evidence row ----------
  const blob = new Blob([new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10])], { type: "image/jpeg" });
  const att = {
    id: OS.newClientId("att"), client_id: sA.client_id, filename: "probe-evidence.jpg",
    content_type: "image/jpeg", kind: "photo", blob, captured_at: new Date().toISOString(),
  };
  await store1.attachmentPut(att);
  await engine1.syncAttachments("incidents", sA.client_id, recA.server_id, ctx);
  const evObj = await sql(`select count(*)::int n from storage.objects
    where bucket_id = 'incident-evidence' and name like '%' || '${sA.client_id}' || '%probe-evidence.jpg';`);
  const evRow = await jfetch(`/rest/v1/incident_evidence?incident_id=eq.${recA.server_id}&select=id,kind,storage_path`, { token: users.owner.token });
  const attOk = evObj.data && evObj.data[0] && Number(evObj.data[0].n) === 1
    && Array.isArray(evRow.data) && evRow.data.length === 1 && evRow.data[0].kind === "photo";
  report(attOk ? "PASS" : "FAIL", "attachments: blob uploaded to incident-evidence storage + evidence row linked",
    `objects=${evObj.data && evObj.data[0] ? evObj.data[0].n : "?"} evidenceRows=${Array.isArray(evRow.data) ? evRow.data.length : "?"}`);
  if (attOk) storagePaths.push(evRow.data[0].storage_path);

  // ---------- tenant isolation (engine writes stay tenant-scoped) ----------
  const t2Read = await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`, { token: users.owner2.token });
  const outRead = await jfetch(`/rest/v1/incidents?organization_id=eq.${orgId}&select=id`, { token: users.out.token });
  report(Array.isArray(t2Read.data) && t2Read.data.length === 0 && Array.isArray(outRead.data) && outRead.data.length === 0
    ? "PASS" : "FAIL", "isolation: tenant#2 owner + outsider read 0 rows of org#1 incidents",
    `t2=${Array.isArray(t2Read.data) ? t2Read.data.length : "?"} out=${Array.isArray(outRead.data) ? outRead.data.length : "?"}`);
  const t1ReadT2 = await jfetch(`/rest/v1/incidents?organization_id=eq.${org2Id}&select=id`, { token: users.owner.token });
  report(Array.isArray(t1ReadT2.data) && t1ReadT2.data.length === 0 ? "PASS" : "FAIL", "isolation: engine actor reads 0 rows of tenant #2",
    `n=${Array.isArray(t1ReadT2.data) ? t1ReadT2.data.length : "?"}`);

  console.log(failures === 0 ? "\nPhase 10 probe: PASS (all checks)." : `\nPhase 10 probe: ${failures} FAIL(s).`);
} catch (err) {
  failures += 1;
  console.error("Phase 10 probe aborted:", err.message);
} finally {
  try {
    if (orgId) {
      await sql(`delete from public.audit_log where organization_id in ('${orgId}', '${org2Id}');`);
      if (storagePaths.length) {
        const paths = storagePaths.map((p) => `'${p}'`).join(",");
        await sql(`delete from storage.objects where bucket_id = 'incident-evidence' and name in (${paths});`);
      }
      await sql(`delete from storage.objects where bucket_id = 'incident-evidence' and name like '%' || '${ORG_SLUG}' || '%';`);
      await sql(`delete from public.organizations where id in ('${orgId}', '${org2Id}');`);
    }
    await sql(`delete from auth.users where email like 'mg.p10.%@gmailtest.com';`);
    const leftOrg = await sql(`select count(*) as n from public.organizations where slug like 'p10-probe%';`);
    const nOrg = leftOrg.data && leftOrg.data[0] ? Number(leftOrg.data[0].n) : -1;
    const incList = incidentClientIds.length ? incidentClientIds.map((c) => `'${c}'`).join(",") : "''";
    const leftInc = await sql(`select count(*) as n from public.incidents where client_id like 'p10-%' or client_id in (${incList});`);
    const nInc = leftInc.data && leftInc.data[0] ? Number(leftInc.data[0].n) : -1;
    const leftObj = await sql(`select count(*)::int n from storage.objects where bucket_id = 'incident-evidence' and name like '%p10-%';`);
    const nObj = leftObj.data && leftObj.data[0] ? Number(leftObj.data[0].n) : -1;
    report(nOrg === 0 && nInc === 0 && nObj === 0 ? "PASS" : "FAIL", "cleanup: probe orgs + incidents + storage objects removed", `orgs=${nOrg} incidents=${nInc} objects=${nObj}`);
    const usersLeft = await sql(`select count(*)::int n from auth.users where email like 'mg.p10.%@gmailtest.com';`);
    report(usersLeft.data && usersLeft.data[0] && Number(usersLeft.data[0].n) === 0 ? "PASS" : "FAIL", "cleanup: probe users removed",
      `n=${usersLeft.data && usersLeft.data[0] ? usersLeft.data[0].n : "?"}`);
  } catch (e) {
    report("FAIL", "cleanup", e.message);
  }
  console.log(failures === 0 ? "Phase 10 probe: PASS (cleanup verified)." : `Phase 10 probe: ${failures} FAIL(s).`);
  process.exit(failures === 0 ? 0 : 1);
}