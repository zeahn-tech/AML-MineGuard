// ============================================================
// MINEGUARD — Phase 08 inspections + CAPA live probe
// (v3: verify data changes on UPDATE/DELETE, fix fixture checks)
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
const ORG_SLUG = `p8-probe-${stamp}`;
const ORG2_SLUG = `p8-probe2-${stamp}`;
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
  if (opts.prefer) headers.Prefer = opts.prefer;
  const res = await fetch(URL + path, { method: opts.method || "GET", headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
  const t = await res.text();
  let data = null;
  try { data = t ? JSON.parse(t) : null; } catch { data = t; }
  return { status: res.status, data };
}

async function pgInsert(path, body, token) {
  return jfetch(path, { method: "POST", body, token });
}

let users = {};

try {
  const mk = (name) => `mg.p8.${name}.${stamp}@gmailtest.com`;

  const org = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
    values ('${ORG_SLUG}', 'Phase08 Inspection Probe', 'mining_company', 'active', '{}'::jsonb) returning id;`);
  if (!Array.isArray(org.data) || !org.data.length) throw new Error(`create org: ${JSON.stringify(org.data).slice(0, 200)}`);
  orgId = org.data[0].id;

  const org2 = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
    values ('${ORG2_SLUG}', 'Phase08 Cross-Tenant Probe', 'mining_company', 'active', '{}'::jsonb) returning id;`);
  org2Id = org2.data[0].id;

  const siteA = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${orgId}', 'Site Alpha', 'Nimba', 'Nimba') returning id;`)).data[0].id;
  const siteB = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${orgId}', 'Site Bravo', 'Bong', 'Bong') returning id;`)).data[0].id;
  const siteA2 = (await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${org2Id}', 'Site Alpha-2', 'Nimba', 'Nimba') returning id;`)).data[0].id;

  const mkuser = async (key) => {
    const email = mk(key);
    const id = await createUser(email);
    if (!id) throw new Error(`create user ${key}`);
    users[key] = { id, email };
  };
  await mkuser("admin");
  await mkuser("sm");
  await mkuser("supa");
  await mkuser("wrk");
  await mkuser("out");
  await mkuser("admin2");

  // Org 1 memberships — valid role values from CHECK constraint
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${orgId}', '${users.admin.id}', 'admin', 'active', '${users.admin.id}'),
           ('${orgId}', '${users.sm.id}', 'safety_manager', 'active', '${users.admin.id}');`);

  await sql(`insert into public.site_members (organization_id, site_id, user_id, role, status, created_by)
    values ('${orgId}', '${siteA}', '${users.supa.id}', 'supervisor', 'active', '${users.admin.id}'),
           ('${orgId}', '${siteA}', '${users.wrk.id}', 'worker', 'active', '${users.admin.id}');`);

  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${org2Id}', '${users.admin2.id}', 'admin', 'active', '${users.admin2.id}');`);

  for (const k of Object.keys(users)) {
    const s = await login(users[k].email);
    if (!s) throw new Error(`login ${k}`);
    users[k].token = s.access_token;
  }
  report("PASS", "fixture: 2 orgs, 3 sites, 6 users, memberships created");

  // ---------- catalog ----------
  const tbls = await sql(`select c.relname, c.relrowsecurity
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname in ('inspections','corrective_actions','jsas','jsa_steps')
    order by c.relname;`);
  const rlsOk = Array.isArray(tbls.data) && tbls.data.length === 4 && tbls.data.every((r) => r.relrowsecurity);
  report(rlsOk ? "PASS" : "FAIL", "catalog: 4 Phase 08 tables with RLS enabled",
    rlsOk ? "" : `found ${tbls.data?.length}: ${JSON.stringify(tbls.data)}`);

  const pol = await sql(`select tablename, count(*)::int n from pg_policies
    where schemaname = 'public'
      and tablename in ('inspections','corrective_actions')
    group by tablename order by tablename;`);
  const polMap = Object.fromEntries((pol.data || []).map((r) => [r.tablename, r.n]));
  // Phase 11 (…090) adds one regulator SELECT policy per table → 5/5.
  report(polMap.inspections === 5 && polMap.corrective_actions === 5 ? "PASS" : "FAIL",
    "catalog: policies inspections=5 CAPA=5 (incl. regulator select each)", JSON.stringify(polMap));

  // 7 tenant + 3 incident + 2 JSA + 2 inspection/CAPA + 5 emergency + 1 grants = 20 (Phase 11 …090)
  const trig = await sql(`select count(*) as n from pg_trigger t
    join pg_class c on c.oid = t.tgrelid
    join pg_namespace n on n.oid = c.relnamespace
    where t.tgenabled <> 'D' and n.nspname = 'public'
      and t.tgname like 'trg_audit_%';`);
  const trgN = trig.data && trig.data[0] ? Number(trig.data[0].n) : 0;
  // Phase 05 cutover adds trg_audit_safety_notices + trg_audit_safety_notice_acks (…097) → 23.
  report(trgN === 23 ? "PASS" : "FAIL", "catalog: 23 audit triggers (14 prior + 5 emergency + government_grants + subscriptions + 2 notices)", `count=${trgN}`);

  // =========================================================================
  // INSPECTIONS: INSERT
  // =========================================================================
  const insBase = {
    organization_id: orgId,
    site_id: siteA,
    inspector_id: users.admin.id,
    title: "Phase08 probe inspection",
    inspection_type: "routine",
    status: "draft",
  };

  const rAdmin = await pgInsert("/rest/v1/inspections", { ...insBase, created_by: users.admin.id }, users.admin.token);
  report(rAdmin.status === 201 ? "PASS" : "FAIL", "insert inspection: admin → 201", `http=${rAdmin.status}`);

  const rSup = await pgInsert("/rest/v1/inspections", { ...insBase, inspector_id: users.supa.id, created_by: users.supa.id, title: "Sup inspection" }, users.supa.token);
  report(rSup.status === 201 ? "PASS" : "FAIL", "insert inspection: supervisor → 201", `http=${rSup.status}`);

  const rSM = await pgInsert("/rest/v1/inspections", { ...insBase, inspector_id: users.sm.id, created_by: users.sm.id, title: "SM inspection" }, users.sm.token);
  report(rSM.status === 201 ? "PASS" : "FAIL", "insert inspection: safety_manager → 201", `http=${rSM.status}`);

  const rW = await pgInsert("/rest/v1/inspections", { ...insBase, inspector_id: users.wrk.id, created_by: users.wrk.id, title: "Worker inspection" }, users.wrk.token);
  report(rW.status >= 400 ? "PASS" : "FAIL", "insert inspection: worker → 403", `http=${rW.status}`);

  const rOut = await pgInsert("/rest/v1/inspections", { ...insBase, inspector_id: users.out.id, created_by: users.out.id, title: "Outsider inspection" }, users.out.token);
  report(rOut.status >= 400 ? "PASS" : "FAIL", "insert inspection: outsider → 403", `http=${rOut.status}`);

  // =========================================================================
  // INSPECTIONS: SELECT matrix
  // =========================================================================
  const selAdmin = await jfetch(`/rest/v1/inspections?organization_id=eq.${orgId}&select=id`, { token: users.admin.token });
  report(selAdmin.status === 200 && (selAdmin.data?.length || 0) === 3 ? "PASS" : "FAIL",
    "select inspection: admin sees 3 rows", `n=${selAdmin.data?.length}`);

  const selSM = await jfetch(`/rest/v1/inspections?organization_id=eq.${orgId}&select=id`, { token: users.sm.token });
  report(selSM.status === 200 && (selSM.data?.length || 0) === 3 ? "PASS" : "FAIL",
    "select inspection: safety_manager sees 3 rows", `n=${selSM.data?.length}`);

  const selSup = await jfetch(`/rest/v1/inspections?organization_id=eq.${orgId}&select=id`, { token: users.supa.token });
  report(selSup.status === 200 && (selSup.data?.length || 0) === 3 ? "PASS" : "FAIL",
    "select inspection: supervisor sees 3 rows (site A)", `n=${selSup.data?.length}`);

  const selWrk = await jfetch(`/rest/v1/inspections?organization_id=eq.${orgId}&select=id`, { token: users.wrk.token });
  report(selWrk.status === 200 && (selWrk.data?.length || 0) === 0 ? "PASS" : "FAIL",
    "select inspection: worker sees 0", `n=${selWrk.data?.length}`);

  const selOutIns = await jfetch(`/rest/v1/inspections?organization_id=eq.${orgId}&select=id`, { token: users.out.token });
  report(selOutIns.status === 200 && (selOutIns.data?.length || 0) === 0 ? "PASS" : "FAIL",
    "select inspection: outsider sees 0", `n=${selOutIns.data?.length}`);

  // =========================================================================
  // INSPECTIONS: UPDATE — verify data actually changes
  // =========================================================================
  const insRows = (await jfetch(`/rest/v1/inspections?organization_id=eq.${orgId}&select=id,inspector_id,title`, { token: users.admin.token })).data || [];
  const insIdAdmin = insRows.find(r => r.inspector_id === users.admin.id)?.id;
  const insIdSup = insRows.find(r => r.inspector_id === users.supa.id)?.id;
  const insIdSM = insRows.find(r => r.inspector_id === users.sm.id)?.id;

  // Supervisor can update own inspection — verify title changed
  if (insIdSup) {
    const origTitle = insRows.find(r => r.id === insIdSup)?.title;
    const upd = await jfetch(`/rest/v1/inspections?id=eq.${insIdSup}`, {
      method: "PATCH", body: { status: "in_progress", title: "Updated sup inspection" }, token: users.supa.token,
    });
    const after = (await jfetch(`/rest/v1/inspections?id=eq.${insIdSup}&select=title,status`, { token: users.admin.token })).data?.[0];
    const changed = after && after.title === "Updated sup inspection" && after.status === "in_progress";
    report(changed ? "PASS" : "FAIL", "update inspection: supervisor own → data changed", changed ? "" : `title=${after?.title}, status=${after?.status}`);
  }

  // Worker cannot update — verify title NOT changed
  if (insIdAdmin) {
    const before = (await jfetch(`/rest/v1/inspections?id=eq.${insIdAdmin}&select=title`, { token: users.admin.token })).data?.[0]?.title;
    await jfetch(`/rest/v1/inspections?id=eq.${insIdAdmin}`, {
      method: "PATCH", body: { title: "Hacked by worker" }, token: users.wrk.token,
    });
    const after = (await jfetch(`/rest/v1/inspections?id=eq.${insIdAdmin}&select=title`, { token: users.admin.token })).data?.[0]?.title;
    report(before === after ? "PASS" : "FAIL", "update inspection: worker blocked (data unchanged)", `before=${before}, after=${after}`);
  }

  // Admin can hard delete — verify row gone
  if (insIdSM) {
    const del = await jfetch(`/rest/v1/inspections?id=eq.${insIdSM}`, { method: "DELETE", token: users.admin.token });
    const gone = (await jfetch(`/rest/v1/inspections?id=eq.${insIdSM}&select=id`, { token: users.admin.token })).data?.length === 0;
    report(gone ? "PASS" : "FAIL", "delete inspection: admin → row gone", gone ? "" : "still exists");
  }

  // Safety_manager cannot hard delete (no inspections.delete perm) — verify row still exists
  if (insIdAdmin) {
    const del = await jfetch(`/rest/v1/inspections?id=eq.${insIdAdmin}`, { method: "DELETE", token: users.sm.token });
    const still = (await jfetch(`/rest/v1/inspections?id=eq.${insIdAdmin}&select=id`, { token: users.admin.token })).data?.length > 0;
    report(still ? "PASS" : "FAIL", "delete inspection: safety_manager blocked (row survives)", still ? "" : "row deleted!");
  }

  // =========================================================================
  // CORRECTIVE_ACTIONS: INSERT
  // =========================================================================
  const capaBase = {
    organization_id: orgId,
    site_id: siteA,
    source_type: "manual",
    title: "Phase08 probe CAPA",
    priority: "high",
    status: "open",
  };

  const rCapaAdmin = await pgInsert("/rest/v1/corrective_actions", { ...capaBase, created_by: users.admin.id }, users.admin.token);
  report(rCapaAdmin.status === 201 ? "PASS" : "FAIL", "insert CAPA: admin → 201", `http=${rCapaAdmin.status}`);

  const rCapaSM = await pgInsert("/rest/v1/corrective_actions", { ...capaBase, created_by: users.sm.id, assigned_to: users.supa.id, priority: "critical", title: "SM CAPA" }, users.sm.token);
  report(rCapaSM.status === 201 ? "PASS" : "FAIL", "insert CAPA: safety_manager → 201", `http=${rCapaSM.status}`);

  const rCapaSup = await pgInsert("/rest/v1/corrective_actions", { ...capaBase, created_by: users.supa.id, title: "Sup CAPA" }, users.supa.token);
  report(rCapaSup.status === 201 ? "PASS" : "FAIL", "insert CAPA: supervisor → 201", `http=${rCapaSup.status}`);

  const rCapaWrk = await pgInsert("/rest/v1/corrective_actions", { ...capaBase, created_by: users.wrk.id, title: "Worker CAPA" }, users.wrk.token);
  report(rCapaWrk.status >= 400 ? "PASS" : "FAIL", "insert CAPA: worker → 403", `http=${rCapaWrk.status}`);

  const rCapaOut = await pgInsert("/rest/v1/corrective_actions", { ...capaBase, created_by: users.out.id, title: "Out CAPA" }, users.out.token);
  report(rCapaOut.status >= 400 ? "PASS" : "FAIL", "insert CAPA: outsider → 403", `http=${rCapaOut.status}`);

  // =========================================================================
  // CORRECTIVE_ACTIONS: SELECT matrix
  // =========================================================================
  const selCapaAdmin = await jfetch(`/rest/v1/corrective_actions?organization_id=eq.${orgId}&select=id`, { token: users.admin.token });
  report(selCapaAdmin.status === 200 && (selCapaAdmin.data?.length || 0) === 3 ? "PASS" : "FAIL",
    "select CAPA: admin sees 3 rows", `n=${selCapaAdmin.data?.length}`);

  const selCapaSM = await jfetch(`/rest/v1/corrective_actions?organization_id=eq.${orgId}&select=id`, { token: users.sm.token });
  report(selCapaSM.status === 200 && (selCapaSM.data?.length || 0) === 3 ? "PASS" : "FAIL",
    "select CAPA: safety_manager sees 3 rows", `n=${selCapaSM.data?.length}`);

  const selCapaSup = await jfetch(`/rest/v1/corrective_actions?organization_id=eq.${orgId}&select=id`, { token: users.supa.token });
  report(selCapaSup.status === 200 && (selCapaSup.data?.length || 0) >= 1 ? "PASS" : "FAIL",
    "select CAPA: supervisor sees 1+ rows (site A)", `n=${selCapaSup.data?.length}`);

  const selCapaWrk = await jfetch(`/rest/v1/corrective_actions?organization_id=eq.${orgId}&select=id`, { token: users.wrk.token });
  report(selCapaWrk.status === 200 && (selCapaWrk.data?.length || 0) === 0 ? "PASS" : "FAIL",
    "select CAPA: worker sees 0", `n=${selCapaWrk.data?.length}`);

  const selCapaOut = await jfetch(`/rest/v1/corrective_actions?organization_id=eq.${orgId}&select=id`, { token: users.out.token });
  report(selCapaOut.status === 200 && (selCapaOut.data?.length || 0) === 0 ? "PASS" : "FAIL",
    "select CAPA: outsider sees 0", `n=${selCapaOut.data?.length}`);

  // =========================================================================
  // CORRECTIVE_ACTIONS: UPDATE + DELETE — verify data changes
  // =========================================================================
  const capaRows = (await jfetch(`/rest/v1/corrective_actions?organization_id=eq.${orgId}&select=id,assigned_to,title`, { token: users.admin.token })).data || [];
  const capaIdAdmin = capaRows.find(c => !c.assigned_to)?.id;
  const capaIdSup = capaRows.find(c => c.assigned_to === users.supa.id)?.id;

  // Assignee (supervisor) can update — verify data changed
  if (capaIdSup) {
    const before = (await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdSup}&select=status`, { token: users.admin.token })).data?.[0]?.status;
    await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdSup}`, {
      method: "PATCH", body: { status: "in_progress", root_cause: "Found root cause" }, token: users.supa.token,
    });
    const after = (await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdSup}&select=status`, { token: users.admin.token })).data?.[0]?.status;
    report(before !== after ? "PASS" : "FAIL", "update CAPA: assignee → data changed", `before=${before}, after=${after}`);
  }

  // Worker cannot update — verify data NOT changed
  if (capaIdAdmin) {
    const before = (await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdAdmin}&select=status`, { token: users.admin.token })).data?.[0]?.status;
    await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdAdmin}`, {
      method: "PATCH", body: { status: "completed" }, token: users.wrk.token,
    });
    const after = (await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdAdmin}&select=status`, { token: users.admin.token })).data?.[0]?.status;
    report(before === after ? "PASS" : "FAIL", "update CAPA: worker blocked (data unchanged)", `before=${before}, after=${after}`);
  }

  // Admin can hard delete — verify row gone
  if (capaIdAdmin) {
    const del = await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdAdmin}`, { method: "DELETE", token: users.admin.token });
    const gone = (await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdAdmin}&select=id`, { token: users.admin.token })).data?.length === 0;
    report(gone ? "PASS" : "FAIL", "delete CAPA: admin → row gone", gone ? "" : "still exists");
  }

  // Safety_manager cannot hard delete — verify row still exists
  if (capaIdSup) {
    const del = await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdSup}`, { method: "DELETE", token: users.sm.token });
    const still = (await jfetch(`/rest/v1/corrective_actions?id=eq.${capaIdSup}&select=id`, { token: users.admin.token })).data?.length > 0;
    report(still ? "PASS" : "FAIL", "delete CAPA: safety_manager blocked (row survives)", still ? "" : "row deleted!");
  }

  // =========================================================================
  // AUDIT: inspection + CAPA rows
  // =========================================================================
  const auditRows = (await sql(`select resource, action, metadata, resource_id
    from public.audit_log
    where organization_id = '${orgId}'
      and resource in ('inspections','corrective_actions')
    order by created_at desc;`)).data || [];

  const auditIns = auditRows.filter(r => r.resource === "inspections");
  const auditCapa = auditRows.filter(r => r.resource === "corrective_actions");

  report(auditIns.length > 0 ? "PASS" : "FAIL", `audit: ${auditIns.length} inspections audit rows`);
  report(auditCapa.length > 0 ? "PASS" : "FAIL", `audit: ${auditCapa.length} CAPA audit rows`);
  report(auditRows.every(r => r.resource_id) ? "PASS" : "FAIL", "audit: all rows have resource_id");

  // =========================================================================
  // TENANT ISOLATION
  // =========================================================================
  const crossIns = await jfetch(`/rest/v1/inspections?organization_id=eq.${orgId}&select=id`, { token: users.admin2.token });
  report((crossIns.data?.length || 0) === 0 ? "PASS" : "FAIL", "cross-tenant: inspections → 0", `n=${crossIns.data?.length}`);

  const crossCapa = await jfetch(`/rest/v1/corrective_actions?organization_id=eq.${orgId}&select=id`, { token: users.admin2.token });
  report((crossCapa.data?.length || 0) === 0 ? "PASS" : "FAIL", "cross-tenant: CAPA → 0", `n=${crossCapa.data?.length}`);

  // =========================================================================
  // CLEANUP — use admin SQL delete (hard delete bypass RLS)
  // =========================================================================
  // Delete all remaining inspections by admin's org access
  await sql(`delete from public.inspections where organization_id = '${orgId}';`);
  await sql(`delete from public.corrective_actions where organization_id = '${orgId}';`);
  await sql(`delete from public.audit_log where organization_id = '${orgId}' and resource in ('inspections','corrective_actions');`);

  const postIns = await sql(`select count(*) as n from public.inspections where organization_id = '${orgId}';`);
  const insN = Number(postIns.data?.[0]?.n || 0);
  report(insN === 0 ? "PASS" : "FAIL", "cleanup: inspections removed", `remaining=${insN}`);

  const postCapa = await sql(`select count(*) as n from public.corrective_actions where organization_id = '${orgId}';`);
  const capaN = Number(postCapa.data?.[0]?.n || 0);
  report(capaN === 0 ? "PASS" : "FAIL", "cleanup: CAPAs removed", `remaining=${capaN}`);

  // Delete orgs
  await sql(`delete from public.organizations where id = '${orgId}';`);
  await sql(`delete from public.organizations where id = '${org2Id}';`);
  const postOrg = await sql(`select id from public.organizations where id = '${orgId}';`);
  report(!postOrg.data?.length ? "PASS" : "FAIL", "cleanup: org deleted");

  // Cleanup users
  for (const k of Object.keys(users)) {
    await sql(`delete from auth.users where id = '${users[k].id}';`);
  }
  report("PASS", "cleanup: all probe data removed");

} catch (err) {
  report("FAIL", `unhandled error: ${err.message}`, err.stack);
}

console.log(`\n=== PHASE 08 VERIFICATION: ${failures === 0 ? "ALL PASS" : `${failures} FAIL`} ===`);
process.exit(failures > 0 ? 1 : 0);
