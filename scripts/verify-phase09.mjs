// ============================================================
// MINEGUARD — Phase 09 emergency response + SOS live probe
//
// Self-cleaning verification of migration
// 20260903000080_phase09_emergency_sos.sql (emergency_events /
// emergency_acknowledgements / emergency_escalations /
// emergency_responders / emergency_log + RLS_MATRIX §1.2
// emergency rows + lifecycle guards + audit triggers).
//
// Covers, all against the LIVE project:
//   * catalog: 5 tables with RLS, policies, 19 audit triggers
//   * INSERT: owner/supervisor activate; worker denied; spoofed
//     activated_by rejected; cross-site activation denied;
//     cross-org write denied; activated_by forced to auth.uid()
//   * SELECT matrix: org-wide roles, site-only supervisor (site
//     A only), worker (own-site events via site_notice_scope),
//     site-B worker exclusion, outsider/anon 0
//   * lifecycle: forward-only transitions enforced; RESOLVED→
//     ACTIVATED rejected; resolved_by immutable; legacy
//     deactivation records resolver server-side
//   * acks: worker ack (201), identity pinned, duplicate → 409,
//     spoofed acked_by rejected, ack on CLOSED event denied
//   * update gating: supervisor/safety_officer cannot resolve
//     (no-op); safety_manager/owner resolve + close
//   * emergency_log: append-only (client INSERT denied), stream
//     rows written by trigger for activation + transitions
//   * tenant isolation: two orgs, no cross reads/writes
//   * audit: event insert/transition captured with actor;
//     forged audit_log INSERT rejected
//   * cleanup verified: org cascade + probe users removed
//
// Usage:
//   bun scripts/verify-phase09.mjs
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
const ORG_SLUG = `p9-probe-${stamp}`;
const ORG2_SLUG = `p9-probe2-${stamp}`;
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

// NOTE: deliberately NO Prefer: return=representation (PostgREST re-checks the
// SELECT policy on RETURNING rows under RLS → 42501; verified in Phase 07).
// POST plainly and resolve ids by client_id as the org owner.
async function pgInsert(path, body, token) {
  return jfetch(path, { method: "POST", body, token });
}

let users = {};
let eventIds = new Set();

try {
  // ---------- fixture: two scratch orgs + users + sites ----------
  const mk = (name) => `mg.p9.${name}.${stamp}@gmailtest.com`;

  const org = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
    values ('${ORG_SLUG}', 'Phase09 Emergency Probe', 'mining_company', 'active', '{}'::jsonb) returning id;`);
  if (!Array.isArray(org.data) || !org.data.length) throw new Error(`create org: ${JSON.stringify(org.data).slice(0, 200)}`);
  orgId = org.data[0].id;

  const org2 = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
    values ('${ORG2_SLUG}', 'Phase09 Cross-Tenant Probe', 'mining_company', 'active', '{}'::jsonb) returning id;`);
  org2Id = org2.data[0].id;

  const siteA = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${orgId}', 'Site Alpha', 'Nimba', 'Nimba') returning id;`)).data[0].id;
  const siteB = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${orgId}', 'Site Bravo', 'Bong', 'Bong') returning id;`)).data[0].id;
  const siteA2 = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${org2Id}', 'Site Alpha-2', 'Nimba', 'Nimba') returning id;`)).data[0].id;

  const mkuser = async (key, role) => {
    const email = mk(key);
    const id = await createUser(email);
    if (!id) throw new Error(`create user ${key}`);
    users[key] = { id, email, role };
  };
  await mkuser("owner", "owner");          // org member owner
  await mkuser("smgr", "safety_manager");  // org member safety_manager (resolve)
  await mkuser("sof", "safety_officer");   // org member safety_officer (activate, NOT resolve)
  await mkuser("wrk", "worker");           // org member worker (ack only)
  await mkuser("supa", "supervisor");      // site-only supervisor at site A (ack/escalate; NO activate per catalog)
  await mkuser("smgrA", "site_manager");   // site-only site_manager at site A (activate site A)
  await mkuser("wrka", "worker");          // site-only worker at site A (ack)
  await mkuser("wrkb", "worker");          // site-only worker at site B
  await mkuser("out", "outsider");         // no memberships
  await mkuser("owner2", "owner");         // tenant #2 owner

  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${orgId}', '${users.owner.id}', 'owner', 'active', '${users.owner.id}'),
           ('${orgId}', '${users.smgr.id}', 'safety_manager', 'active', '${users.owner.id}'),
           ('${orgId}', '${users.sof.id}', 'safety_officer', 'active', '${users.owner.id}'),
           ('${orgId}', '${users.wrk.id}', 'worker', 'active', '${users.owner.id}');`);
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${org2Id}', '${users.owner2.id}', 'owner', 'active', '${users.owner2.id}');`);
  await sql(`insert into public.site_members (organization_id, site_id, user_id, role, status, created_by)
    values ('${orgId}', '${siteA}', '${users.supa.id}', 'supervisor', 'active', '${users.owner.id}'),
           ('${orgId}', '${siteA}', '${users.smgrA.id}', 'site_manager', 'active', '${users.owner.id}'),
           ('${orgId}', '${siteA}', '${users.wrka.id}', 'worker', 'active', '${users.owner.id}'),
           ('${orgId}', '${siteB}', '${users.wrkb.id}', 'worker', 'active', '${users.owner.id}');`);

  for (const k of Object.keys(users)) {
    const s = await login(users[k].email);
    if (!s) throw new Error(`login ${k}`);
    users[k].token = s.access_token;
  }
  report("PASS", "fixture: 2 orgs, 3 sites, 10 users, memberships created");

  // ---------- catalog ----------
  const tbls = await sql(`select c.relname, c.relrowsecurity
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname in
      ('emergency_events','emergency_acknowledgements','emergency_escalations','emergency_responders','emergency_log')
    order by c.relname;`);
  const rlsOk = Array.isArray(tbls.data) && tbls.data.length === 5 && tbls.data.every((r) => r.relrowsecurity);
  report(rlsOk ? "PASS" : "FAIL", "catalog: 5 Phase 09 tables exist with RLS enabled", rlsOk ? "" : JSON.stringify(tbls.data));

  const pol = await sql(`select tablename, count(*)::int n from pg_policies
    where schemaname = 'public'
      and tablename in ('emergency_events','emergency_acknowledgements','emergency_escalations','emergency_responders','emergency_log')
    group by tablename order by tablename;`);
  const polMap = Object.fromEntries((pol.data || []).map((r) => [r.tablename, r.n]));
  // Phase 11 (…090) adds one regulator SELECT policy per emergency table → +1 each.
  const polOk = polMap.emergency_events === 4 && polMap.emergency_acknowledgements === 3
    && polMap.emergency_escalations === 3 && polMap.emergency_responders === 4 && polMap.emergency_log === 2;
  report(polOk ? "PASS" : "FAIL", "catalog: policies events=4 acks=3(immutable) esc=3 resp=4 log=2(append-only, incl. regulator each)", JSON.stringify(polMap));

  const trig = await sql(`select count(*) as n from pg_trigger t
    join pg_class c on c.oid = t.tgrelid
    join pg_namespace n on n.oid = c.relnamespace
    where t.tgenabled <> 'D' and n.nspname = 'public'
      and t.tgname like 'trg_audit_%';`);
  // Phase 11 (…090) adds trg_audit_government_grants → 20 total.
  const trgN = trig.data && trig.data[0] ? Number(trig.data[0].n) : 0;
  report(trgN === 20 ? "PASS" : "FAIL", "catalog: 20 audit triggers (14 prior + 5 emergency + government_grants)", `count=${trgN}`);

  // ---------- INSERT matrix ----------
  const evBase = {
    organization_id: orgId,
    category: "fire",
    message: "probe emergency",
    severity: "critical",
    client_id: null,
  };
  const getEventId = async (clientId) => {
    const rows = await jfetch(`/rest/v1/emergency_events?client_id=eq.${clientId}&select=id`, { token: users.owner.token });
    return Array.isArray(rows.data) && rows.data[0] ? rows.data[0].id : null;
  };

  const r1 = await pgInsert("/rest/v1/emergency_events", { ...evBase, site_id: siteA, client_id: `p9-owner-${stamp}` }, users.owner.token);
  report(r1.status === 201 ? "PASS" : "FAIL", "insert: owner activates emergency at site A (201)", `http=${r1.status}`);
  const evA = r1.status === 201 ? await getEventId(`p9-owner-${stamp}`) : null;
  if (evA) eventIds.add(evA);

  if (evA) {
    const row = (await jfetch(`/rest/v1/emergency_events?id=eq.${evA}&select=activated_by,status,site_notice_scope`, { token: users.owner.token })).data[0];
    report(row && row.activated_by === users.owner.id ? "PASS" : "FAIL", "insert: activated_by forced to auth.uid() (server-side)", row ? `activated_by=${row.activated_by}` : "no row");
    report(row && row.status === "ACTIVATED" && row.site_notice_scope === true ? "PASS" : "FAIL", "insert: initial status ACTIVATED + site_notice_scope default true", row ? `status=${row.status}` : "no row");
  } else report("FAIL", "insert: activated_by forced to auth.uid() (server-side)", "no row id");

  const rSpoof = await pgInsert("/rest/v1/emergency_events", { ...evBase, site_id: siteA, activated_by: users.wrk.id, client_id: `p9-spoof-${stamp}` }, users.supa.token);
  report(rSpoof.status >= 400 ? "PASS" : "FAIL", "insert: supervisor cannot attribute activation to another user", `http=${rSpoof.status}${rSpoof.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  // NOTE: supervisors/workers hold emergency.view + emergency.acknowledge only —
  // activation requires emergency.activate (owner/admin/safety_manager/safety_officer/
  // site_manager bundles), matching the legacy admin-console-only SOS activation.
  const r2 = await pgInsert("/rest/v1/emergency_events", { ...evBase, category: "rockfall", client_id: `p9-supa-${stamp}` }, users.supa.token);
  report(r2.status >= 400 ? "PASS" : "FAIL", "insert: site-only supervisor CANNOT activate (no emergency.activate in catalog)", `http=${r2.status}${r2.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  const r2b = await pgInsert("/rest/v1/emergency_events", { ...evBase, site_id: siteA, category: "rockfall", client_id: `p9-smgrA-${stamp}` }, users.smgrA.token);
  report(r2b.status === 201 ? "PASS" : "FAIL", "insert: site-only site_manager activates at own site A (201)", `http=${r2b.status}`);
  const evA2 = r2b.status === 201 ? await getEventId(`p9-smgrA-${stamp}`) : null;
  if (evA2) eventIds.add(evA2);

  const rXsite = await pgInsert("/rest/v1/emergency_events", { ...evBase, site_id: siteB, client_id: `p9-xsupsite-${stamp}` }, users.supa.token);
  report(rXsite.status >= 400 ? "PASS" : "FAIL", "insert: site-A-only supervisor cannot activate at site B", `http=${rXsite.status}${rXsite.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  const rWrk = await pgInsert("/rest/v1/emergency_events", { ...evBase, site_id: siteA, client_id: `p9-wrk-${stamp}` }, users.wrka.token);
  report(rWrk.status >= 400 ? "PASS" : "FAIL", "insert: worker cannot activate (no emergency.activate)", `http=${rWrk.status}${rWrk.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  const rXorg = await pgInsert("/rest/v1/emergency_events", { ...evBase, site_id: siteA, client_id: `p9-xorg-${stamp}` }, users.owner2.token);
  report(rXorg.status >= 400 ? "PASS" : "FAIL", "insert: tenant #2 owner cannot activate into tenant #1", `http=${rXorg.status}${rXorg.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  // tenant #2 fixture event (isolation read target)
  const rO2 = await pgInsert("/rest/v1/emergency_events", { ...evBase, organization_id: org2Id, site_id: siteA2, client_id: `p9-t2-${stamp}` }, users.owner2.token);
  report(rO2.status === 201 ? "PASS" : "FAIL", "insert: tenant #2 owner activates in own org (201)", `http=${rO2.status}`);

  // ---------- SELECT matrix ----------
  const selAll = async (u) => (await jfetch(`/rest/v1/emergency_events?organization_id=eq.${orgId}&select=id,site_id`, { token: u.token })).data;
  const ids = (rows) => (Array.isArray(rows) ? rows.map((r) => r.id).sort() : []);

  const ownerSee = await selAll(users.owner);
  report(ids(ownerSee).length === 2 ? "PASS" : "FAIL", "select: owner sees org-wide pool (2 events)", `n=${ids(ownerSee).length}`);
  const smgrSee = await selAll(users.smgr);
  report(ids(smgrSee).length === 2 ? "PASS" : "FAIL", "select: safety_manager sees org-wide pool (2 events)", `n=${ids(smgrSee).length}`);
  const sofSee = await selAll(users.sof);
  report(ids(sofSee).length === 2 ? "PASS" : "FAIL", "select: safety_officer sees org-wide pool (2 events)", `n=${ids(sofSee).length}`);
  const supSee = await selAll(users.supa);
  const supIds = ids(supSee);
  report(supIds.length === 2 && supIds.includes(evA) && supIds.includes(evA2) ? "PASS" : "FAIL", "select: site-only supervisor sees site A events (2)", `ids=${supIds.join(",")}`);
  const wrkSee = await selAll(users.wrka);
  const wrkIds = ids(wrkSee);
  report(wrkIds.length === 2 && wrkIds.includes(evA) && wrkIds.includes(evA2) ? "PASS" : "FAIL", "select: site-A worker sees site A events (site_notice_scope)", `ids=${wrkIds.join(",")}`);
  const wrkOrgSee = await selAll(users.wrk);
  // org-member worker: site_effective_role falls back to the org role ('worker') at
  // every org site, so site_notice_scope broadcasts are visible org-wide (safety-positive;
  // same Phase 04 fallback semantics the Phase 07 site_notice_scope probe verified).
  report(ids(wrkOrgSee).length === 2 ? "PASS" : "FAIL", "select: org worker sees site_notice_scope broadcast events (2)", `n=${ids(wrkOrgSee).length}`);
  const wrkbSee = await selAll(users.wrkb);
  report(ids(wrkbSee).length === 0 ? "PASS" : "FAIL", "select: site-B worker does NOT see site-A events", `n=${ids(wrkbSee).length}`);
  const outSee = await selAll(users.out);
  report(Array.isArray(outSee) && outSee.length === 0 ? "PASS" : "FAIL", "select: outsider sees 0 rows", `n=${Array.isArray(outSee) ? outSee.length : "?"}`);
  const anonSee = await jfetch(`/rest/v1/emergency_events?organization_id=eq.${orgId}&select=id`);
  report(Array.isArray(anonSee.data) && anonSee.data.length === 0 ? "PASS" : "FAIL", "select: anon sees 0 rows", `n=${Array.isArray(anonSee.data) ? anonSee.data.length : "?"}`);

  // cross-tenant reads (both directions)
  const wrkReadT2 = await jfetch(`/rest/v1/emergency_events?organization_id=eq.${org2Id}&select=id`, { token: users.wrk.token });
  report(Array.isArray(wrkReadT2.data) && wrkReadT2.data.length === 0 ? "PASS" : "FAIL", "isolation: tenant#1 worker reads 0 rows of tenant #2", `n=${Array.isArray(wrkReadT2.data) ? wrkReadT2.data.length : "?"}`);
  const o2ReadT1 = await jfetch(`/rest/v1/emergency_events?organization_id=eq.${orgId}&select=id`, { token: users.owner2.token });
  report(Array.isArray(o2ReadT1.data) && o2ReadT1.data.length === 0 ? "PASS" : "FAIL", "isolation: tenant#2 owner reads 0 rows of tenant #1", `n=${Array.isArray(o2ReadT1.data) ? o2ReadT1.data.length : "?"}`);

  // ---------- UPDATE / lifecycle gating ----------
  const patch = async (u, id, body) => {
    const r = await jfetch(`/rest/v1/emergency_events?id=eq.${id}`, { method: "PATCH", body, token: u.token });
    const after = await jfetch(`/rest/v1/emergency_events?id=eq.${id}&select=status,resolved_by,message`, { token: users.owner.token });
    return { status: r.status, row: Array.isArray(after.data) && after.data[0] ? after.data[0] : null };
  };

  const upWrk = await patch(users.wrka, evA, { message: "worker tamper" });
  report(upWrk.status === 204 && upWrk.row && upWrk.row.message === "probe emergency" ? "PASS" : "FAIL", "update: worker CANNOT update event (no-op)", `http=${upWrk.status}`);

  const upSup = await patch(users.supa, evA, { status: "RESOLVED" });
  report(upSup.status === 204 && upSup.row && upSup.row.status === "ACTIVATED" ? "PASS" : "FAIL", "update: site supervisor CANNOT resolve (no emergency.resolve, no-op)", `status=${upSup.row ? upSup.row.status : "?"}`);

  const upSof = await patch(users.sof, evA, { status: "RESOLVED" });
  report(upSof.status === 204 && upSof.row && upSof.row.status === "ACTIVATED" ? "PASS" : "FAIL", "update: safety_officer CANNOT resolve (no emergency.resolve, no-op)", `status=${upSof.row ? upSof.row.status : "?"}`);

  const upSmgr = await patch(users.smgr, evA, { status: "RESOLVED", resolution_note: "contained by smgr" });
  report(upSmgr.status === 204 && upSmgr.row && upSmgr.row.status === "RESOLVED" ? "PASS" : "FAIL", "lifecycle: safety_manager resolves event (ACTIVATED→RESOLVED)", `status=${upSmgr.row ? upSmgr.row.status : "?"}`);
  if (upSmgr.row) {
    report(upSmgr.row.resolved_by === users.smgr.id ? "PASS" : "FAIL", "lifecycle: resolver recorded server-side (resolved_by = safety_manager)", `resolved_by=${upSmgr.row.resolved_by}`);
  }

  const upBack = await patch(users.owner, evA, { status: "ACTIVATED" });
  report(upBack.status >= 400 || (upBack.row && upBack.row.status === "RESOLVED") ? "PASS" : "FAIL", "lifecycle: backward transition RESOLVED→ACTIVATED rejected (forward-only)", `http=${upBack.status}`);

  const upRb = await patch(users.owner, evA, { resolved_by: users.owner.id });
  report(upRb.status >= 400 || (upRb.row && upRb.row.resolved_by === users.smgr.id) ? "PASS" : "FAIL", "lifecycle: resolved_by immutable once set", `http=${upRb.status}`);

  // close path: owner closes the resolved event
  const upClose = await patch(users.owner, evA, { status: "CLOSED", after_action_note: "after-action recorded" });
  report(upClose.status === 204 && upClose.row && upClose.row.status === "CLOSED" ? "PASS" : "FAIL", "lifecycle: owner closes event (RESOLVED→CLOSED)", `status=${upClose.row ? upClose.row.status : "?"}`);

  // ---------- acknowledgements ----------
  const ackIns = async (u, eventId, body) => pgInsert("/rest/v1/emergency_acknowledgements", { event_id: eventId, ...body }, u.token);
  const getAckId = async (eventId, userId) => {
    const rows = await jfetch(`/rest/v1/emergency_acknowledgements?event_id=eq.${eventId}&acked_by=eq.${userId}&select=id`, { token: users.owner.token });
    return Array.isArray(rows.data) && rows.data[0] ? rows.data[0].id : null;
  };

  const a1 = await ackIns(users.wrka, evA2, { note: "worker ack" });
  report(a1.status === 201 ? "PASS" : "FAIL", "ack: site-A worker acknowledges active event (201)", `http=${a1.status}`);
  const ackRow = a1.status === 201 ? (await jfetch(`/rest/v1/emergency_acknowledgements?event_id=eq.${evA2}&select=acked_by`, { token: users.owner.token })).data : null;
  report(Array.isArray(ackRow) && ackRow.some((r) => r.acked_by === users.wrka.id) ? "PASS" : "FAIL", "ack: acked_by pinned to acknowledging user", "");

  const aDup = await ackIns(users.wrka, evA2, { note: "retry" });
  report(aDup.status >= 400 ? "PASS" : "FAIL", "ack: duplicate ack rejected (unique(event,user) idempotency)", `http=${aDup.status}`);

  const aSpoof = await ackIns(users.wrka, evA2, { acked_by: users.supa.id });
  report(aSpoof.status >= 400 ? "PASS" : "FAIL", "ack: worker cannot attribute ack to another user", `http=${aSpoof.status}${aSpoof.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  const aWrkb = await ackIns(users.wrkb, evA2, {});
  report(aWrkb.status >= 400 ? "PASS" : "FAIL", "ack: site-B worker cannot ack site-A event", `http=${aWrkb.status}${aWrkb.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  const aOut = await ackIns(users.out, evA2, {});
  report(aOut.status >= 400 ? "PASS" : "FAIL", "ack: outsider cannot ack", `http=${aOut.status}`);

  // ack on CLOSED event denied (evA is CLOSED now)
  const aClosed = await ackIns(users.wrka, evA, {});
  report(aClosed.status >= 400 ? "PASS" : "FAIL", "ack: ack on CLOSED event denied", `http=${aClosed.status}${aClosed.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  // acks are immutable (no UPDATE policy)
  const ackId = await getAckId(evA2, users.wrka.id);
  if (ackId) {
    const aUpd = await jfetch(`/rest/v1/emergency_acknowledgements?id=eq.${ackId}`, { method: "PATCH", body: { note: "tampered" }, token: users.smgr.token });
    const ackAfter = (await jfetch(`/rest/v1/emergency_acknowledgements?id=eq.${ackId}&select=note`, { token: users.owner.token })).data;
    report(aUpd.status === 204 && Array.isArray(ackAfter) && ackAfter[0] && ackAfter[0].note === "worker ack" ? "PASS" : "FAIL", "ack: acks immutable (UPDATE is a no-op even for safety_manager)", `http=${aUpd.status}`);
  } else report("FAIL", "ack: acks immutable (UPDATE is a no-op even for safety_manager)", "ack row not found");

  // ---------- escalations + responders ----------
  const escIns = await pgInsert("/rest/v1/emergency_escalations", { event_id: evA2, level: 1, escalated_to: "site_manager", reason: "unacknowledged 5 min" }, users.supa.token);
  report(escIns.status === 201 ? "PASS" : "FAIL", "escalation: site supervisor escalates site event (201)", `http=${escIns.status}`);
  const escWrk = await pgInsert("/rest/v1/emergency_escalations", { event_id: evA2, level: 2 }, users.wrka.token);
  report(escWrk.status >= 400 ? "PASS" : "FAIL", "escalation: worker cannot escalate (ack-only)", `http=${escWrk.status}`);

  const respIns = await pgInsert("/rest/v1/emergency_responders", { event_id: evA2, responder_text: "rescue team", role: "rescue", status: "dispatched" }, users.smgr.token);
  report(respIns.status === 201 ? "PASS" : "FAIL", "responders: safety_manager dispatches responder (201)", `http=${respIns.status}`);
  const getRespId = async () => {
    const rows = await jfetch(`/rest/v1/emergency_responders?event_id=eq.${evA2}&select=id`, { token: users.owner.token });
    return Array.isArray(rows.data) && rows.data[0] ? rows.data[0].id : null;
  };
  const respId = respIns.status === 201 ? await getRespId() : null;
  if (respId) {
    const respUpd = await jfetch(`/rest/v1/emergency_responders?id=eq.${respId}`, { method: "PATCH", body: { status: "arrived", arrived_at: new Date().toISOString() }, token: users.smgr.token });
    const respRow = (await jfetch(`/rest/v1/emergency_responders?id=eq.${respId}&select=status`, { token: users.owner.token })).data;
    report(respUpd.status === 204 && Array.isArray(respRow) && respRow[0] && respRow[0].status === "arrived" ? "PASS" : "FAIL", "responders: responder disposition update (dispatched→arrived)", `http=${respUpd.status}`);
  }
  const respWrk = await pgInsert("/rest/v1/emergency_responders", { event_id: evA2, responder_text: "crew" }, users.wrka.token);
  report(respWrk.status >= 400 ? "PASS" : "FAIL", "responders: worker cannot dispatch responders", `http=${respWrk.status}${respWrk.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  // ---------- emergency_log (append-only stream) ----------
  const logRows = await jfetch(`/rest/v1/emergency_log?event_id=eq.${evA}&select=entry_type,actor_user_id&order=created_at.asc`, { token: users.owner.token });
  const logTypes = Array.isArray(logRows.data) ? logRows.data.map((r) => r.entry_type) : [];
  report(logTypes.includes("activated") && logTypes.includes("resolved") && logTypes.includes("closed") ? "PASS" : "FAIL", "log: trigger wrote activated/resolved/closed stream rows", `types=${logTypes.join(",")}`);
  const logWrk = await pgInsert("/rest/v1/emergency_log", { event_id: evA2, entry_type: "note", detail: {} }, users.wrka.token);
  report(logWrk.status >= 400 ? "PASS" : "FAIL", "log: client INSERT into emergency_log denied (append-only, trigger-only)", `http=${logWrk.status}${logWrk.status < 400 ? " (ALLOWED — BUG)" : ""}`);

  // ---------- audit ----------
  const audRows = (await sql(`select resource, action, actor_user_id from public.audit_log
    where organization_id = '${orgId}' and source = 'trigger' and resource like 'emergency%'
    order by created_at asc;`));
  const a = Array.isArray(audRows.data) ? audRows.data : [];
  report(a.some((r) => r.resource === "emergency_events" && r.action === "emergency_events.insert" && r.actor_user_id === users.owner.id) ? "PASS" : "FAIL", "audit: emergency event insert captured with actor = activator", "");
  report(a.some((r) => r.resource === "emergency_events" && r.action === "emergency_events.update" && r.actor_user_id === users.smgr.id) ? "PASS" : "FAIL", "audit: lifecycle transition captured with actor = resolver", "");
  report(a.some((r) => r.resource === "emergency_acknowledgements" && r.action === "emergency_acknowledgements.insert") ? "PASS" : "FAIL", "audit: acknowledgement captured", "");
  report(a.some((r) => r.resource === "emergency_log" && r.action === "emergency_log.insert") ? "PASS" : "FAIL", "audit: emergency_log stream rows visible in audit trail", "");
  const forged = await jfetch("/rest/v1/audit_log", { method: "POST", body: { action: "forged", resource: "emergency_events", resource_id: evA, metadata: {} }, token: users.owner.token });
  report(forged.status >= 400 ? "PASS" : "FAIL", "audit: audit_log append-only for probe users (forged INSERT rejected)", `http=${forged.status}${forged.status < 400 ? " (ALLOWED — BUG)" : ""}`);
  const leak = await sql(`select count(*)::int n from public.audit_log
    where organization_id = '${orgId}' and metadata::text like '%probe emergency%';`);
  report(leak.data && leak.data[0] && leak.data[0].n === 0 ? "PASS" : "FAIL", "audit: emergency message text never mirrored into audit metadata", `n=${leak.data && leak.data[0] ? leak.data[0].n : "?"}`);

  console.log(failures === 0 ? "\nPhase 09 probe: PASS (all checks)." : `\nPhase 09 probe: ${failures} FAIL(s).`);
} catch (err) {
  failures += 1;
  console.error("Phase 09 probe aborted:", err.message);
} finally {
  try {
    if (orgId) {
      if (eventIds.size) {
        const ids = [...eventIds].map((x) => `'${x}'`).join(",");
        await sql(`delete from public.audit_log where resource_id in (${ids});`);
      }
      await sql(`delete from public.audit_log where organization_id in ('${orgId}', '${org2Id}');`);
      await sql(`delete from public.organizations where id in ('${orgId}', '${org2Id}');`);
    }
    await sql(`delete from auth.users where email like 'mg.p9.%@gmailtest.com';`);
    const left = await sql(`select count(*) as n from public.organizations where slug like 'p9-probe%';`);
    const n = left.data && left.data[0] ? Number(left.data[0].n) : -1;
    const leftEv = await sql(`select count(*) as n from public.emergency_events where client_id like 'p9-%';`);
    const nEv = leftEv.data && leftEv.data[0] ? Number(leftEv.data[0].n) : -1;
    report(n === 0 && nEv === 0 ? "PASS" : "FAIL", "cleanup: probe orgs + events removed", `orgs=${n} events=${nEv}`);
    const usersLeft = await sql(`select count(*)::int n from auth.users where email like 'mg.p9.%@gmailtest.com';`);
    report(usersLeft.data && usersLeft.data[0] && Number(usersLeft.data[0].n) === 0 ? "PASS" : "FAIL", "cleanup: probe users removed", `n=${usersLeft.data && usersLeft.data[0] ? usersLeft.data[0].n : "?"}`);
  } catch (e) {
    report("FAIL", "cleanup", e.message);
  }
  console.log(failures === 0 ? "Phase 09 probe: PASS (cleanup verified)." : `Phase 09 probe: ${failures} FAIL(s).`);
  process.exit(failures === 0 ? 0 : 1);
}
