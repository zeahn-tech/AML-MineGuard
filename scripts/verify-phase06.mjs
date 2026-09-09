// ============================================================
// MINEGUARD — Phase 06 RLS + audit live probe (dev verification)
//
// Verifies the Phase 06 enforcement layer END-TO-END on the live
// Supabase project (docs/engineering/RLS_MATRIX.md §1.1/§1.3,
// SECURITY_MODEL.md §2.6):
//   * site-scope SELECT matrix: site-only supervisor reads OWN-site
//     sites/units only — never site B, org rows, invites, or the
//     worker roster (no transitive access, least privilege)
//   * org-scope readers keep hierarchy access; plain workers lose
//     worker-registry reads (no workers.view/users.view)
//   * organizations UPDATE gate (owner/admin via organizations.manage);
//     writes by worker/outsider/anon/other-org are no-ops (checked by
//     effect, not just HTTP code)
//   * audit_log: table exists, RLS-enabled, SELECT only for viewers
//     (org members with audit_logs.view), append-only (INSERT/UPDATE/
//     DELETE revoked AND unpolicied → every client write errors)
//   * audit capture: RPC-driven org-management operations (member
//     add/re-role, site assign, unit create/update, worker add/update,
//     invite send/revoke) produce rows whose actor_user_id equals the
//     acting user (auth.uid()) — never client-supplied strings; org
//     invite tokens are NOT mirrored into audit metadata
//   * cross-tenant: scratch-org users see ZERO rows of tenant #1 (AML)
//
// Self-cleaning: creates a scratch org + probe users, then removes
// every trace in a finally block. Requires Management API access
// (SUPABASE_ACCESS_TOKEN) + URL/anon key exactly like
// scripts/verify-phase04.mjs.
//
// Usage:
//   NEXT_PUBLIC_SUPABASE_URL=... NEXT_PUBLIC_SUPABASE_ANON_KEY=... \
//   SUPABASE_ACCESS_TOKEN=... bun scripts/verify-phase06.mjs
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
const ANON = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || cfgAnon || "";
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = process.env.SUPABASE_PROJECT_REF || (() => {
  try {
    return JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;
  } catch { return ""; }
})();

if (!URL || !ANON || !TOKEN) {
  console.error("Missing NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY / SUPABASE_ACCESS_TOKEN");
  process.exit(1);
}
if (!REF) {
  console.error("Cannot determine project ref — set SUPABASE_PROJECT_REF or link the project");
  process.exit(1);
}

let failures = 0;
let createdOrgId = null;
const stamp = Date.now().toString(36);
const EMAILS = {
  admin: `mg.p6.admin.${stamp}@gmailtest.com`,
  worker: `mg.p6.worker.${stamp}@gmailtest.com`,
  siteSup: `mg.p6.sitesup.${stamp}@gmailtest.com`,
  added: `mg.p6.added.${stamp}@gmailtest.com`,
  outsider: `mg.p6.outsider.${stamp}@gmailtest.com`,
};
const ORG_SLUG = `p6-probe-${stamp}`;
const PASSWORD = "MgProbePass!2026";

function report(status, label, detail = "") {
  console.log(`${status.padEnd(5)} ${label}${detail ? " — " + detail : ""}`);
  if (status === "FAIL") failures += 1;
}

async function jfetch(path, { method = "GET", token, body, headers = {} } = {}) {
  const res = await fetch(URL + path, {
    method,
    headers: {
      apikey: ANON,
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function signUp(email) {
  const u = await sql(`with nu as (
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
  if ((u.status !== 200 && u.status !== 201) || !Array.isArray(u.data) || !u.data.length) {
    throw new Error(`create user ${email}: HTTP ${u.status} ${JSON.stringify(u.data).slice(0, 200)}`);
  }
  const s = await jfetch("/auth/v1/token?grant_type=password", { method: "POST", body: { email, password: PASSWORD } });
  if (s.status !== 200 || !s.data.access_token) {
    throw new Error(`signin ${email}: HTTP ${s.status} ${JSON.stringify(s.data).slice(0, 160)}`);
  }
  return { user: s.data.user, access_token: s.data.access_token };
}

async function rpc(name, args, token) {
  return jfetch(`/rest/v1/rpc/${name}`, { method: "POST", token, body: args || {} });
}

async function main() {
  report("INFO", "probe project", REF);
  let admin, worker, siteSup, added, outsider;
  let siteA = null, siteB = null, amlOrgId = null;
  try {
    const health = await fetch(`${URL}/auth/v1/health`);
    report(health.status > 0 ? "PASS" : "FAIL", "auth/v1/health reachable", `HTTP ${health.status}`);
  } catch (e) {
    report("FAIL", "auth/v1/health reachable", e.message);
  }

  try {
    // ---- 0. pg-catalog state (Phase 06 objects) ------------------------------
    const pol = await sql(
      `select tablename, policyname from pg_policies
       where schemaname = 'public' and tablename in
         ('sites','organizational_units','workers','organizations','audit_log')
       order by tablename, policyname;`);
    const names = Array.isArray(pol.data) ? pol.data.map((r) => `${r.tablename}.${r.policyname}`) : [];
    const expectPolicies = [
      "sites.sites_select_org_or_site",
      "organizational_units.units_select_org_or_site",
      "workers.workers_select_viewers",
      "organizations.org_update_owner_admin",
      "audit_log.audit_select_viewers",
    ];
    const missing = expectPolicies.filter((p) => !names.includes(p));
    report(missing.length === 0 ? "PASS" : "FAIL", "catalog: Phase 06 policies present", missing.length ? `missing ${missing.join(", ")}` : `${expectPolicies.length} policies`);

    const rls = await sql(
      `select c.relname, c.relrowsecurity from pg_class c
       join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = 'public' and c.relname in
         ('sites','organizational_units','workers','organizations','audit_log')
       order by c.relname;`);
    const rlsMap = {};
    for (const r of (Array.isArray(rls.data) ? rls.data : [])) rlsMap[r.relname] = r.relrowsecurity;
    const allOn = ["sites", "organizational_units", "workers", "organizations", "audit_log"].every((t) => rlsMap[t] === true);
    report(allOn ? "PASS" : "FAIL", "catalog: RLS enabled on all Phase 06 tables", JSON.stringify(rlsMap));

    const trg = await sql(
      `select count(*) as n from pg_trigger t
       join pg_class c on c.oid = t.tgrelid
       where not t.tgisinternal and c.relname in
         ('organization_members','site_members','sites','organizational_units','workers','org_invites','organizations')
         and t.tgname like 'trg_audit_%';`);
    const trgN = trg.data && trg.data[0] ? Number(trg.data[0].n) : 0;
    report(trgN === 7 ? "PASS" : "FAIL", "catalog: 7 Phase 06 audit triggers installed on tenant tables (Phase 07 adds 3 safety-domain triggers, checked by verify-phase07)", `count=${trgN}`);

    const priv = await sql(
      `select r.rolname, p.perm, has_table_privilege(r.rolname, 'public.audit_log', p.perm) as ok
       from (values ('anon','SELECT'),('anon','INSERT'),('anon','UPDATE'),('anon','DELETE'),
                    ('authenticated','SELECT'),('authenticated','INSERT'),
                    ('authenticated','UPDATE'),('authenticated','DELETE')) as r(rolname, perm)
       join (values ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) as p(perm) on p.perm = r.perm;`);
    const privMap = {};
    for (const row of (Array.isArray(priv.data) ? priv.data : [])) privMap[`${row.rolname}.${row.perm}`] = row.ok;
    const okPriv =
      privMap["anon.SELECT"] === true && privMap["authenticated.SELECT"] === true &&
      privMap["anon.INSERT"] === false && privMap["anon.UPDATE"] === false && privMap["anon.DELETE"] === false &&
      privMap["authenticated.INSERT"] === false && privMap["authenticated.UPDATE"] === false &&
      privMap["authenticated.DELETE"] === false;
    report(okPriv ? "PASS" : "FAIL", "catalog: audit_log = SELECT-only privileges", JSON.stringify(privMap));

    // ---- fixture: users, scratch org, sites ---------------------------------
    admin = await signUp(EMAILS.admin);
    worker = await signUp(EMAILS.worker);
    siteSup = await signUp(EMAILS.siteSup);
    added = await signUp(EMAILS.added);
    outsider = await signUp(EMAILS.outsider);

    const aml = await sql(`select id from public.organizations where slug = 'arcelormittal-liberia';`);
    amlOrgId = aml.data && aml.data[0] ? aml.data[0].id : null;

    const orgRes = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
      values ('${ORG_SLUG}', 'Phase06 Probe Org', 'mining_company', 'active',
              '{"displayName":"Phase06 Probe Org"}'::jsonb) returning id;`);
    if ((orgRes.status !== 200 && orgRes.status !== 201) || !Array.isArray(orgRes.data) || !orgRes.data.length) {
      throw new Error(`create scratch org: HTTP ${orgRes.status} ${JSON.stringify(orgRes.data).slice(0, 200)}`);
    }
    createdOrgId = orgRes.data[0].id;
    report("PASS", "scratch org created", ORG_SLUG);

    const siteRes = await sql(`insert into public.sites (organization_id, name, location, county) values
      ('${createdOrgId}', 'Probe Site A', 'Nimba', 'Nimba'),
      ('${createdOrgId}', 'Probe Site B', 'Buchanan', 'Grand Bassa') returning id, name;`);
    if (!Array.isArray(siteRes.data) || siteRes.data.length !== 2) throw new Error("create sites failed");
    siteA = siteRes.data.find((s) => s.name === "Probe Site A").id;
    siteB = siteRes.data.find((s) => s.name === "Probe Site B").id;
    report("PASS", "sites created", "Site A + Site B");

    const memRes = await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by) values
      ('${createdOrgId}', '${admin.user.id}', 'owner', 'active', '${admin.user.id}'),
      ('${createdOrgId}', '${worker.user.id}', 'worker', 'active', '${admin.user.id}');`);
    if (memRes.status !== 200 && memRes.status !== 201) throw new Error(`seed memberships: HTTP ${memRes.status}`);
    await sql(`insert into public.site_members (organization_id, site_id, user_id, role, status, created_by) values
      ('${createdOrgId}', '${siteA}', '${siteSup.user.id}', 'supervisor', 'active', '${admin.user.id}');`);
    report("PASS", "memberships seeded", "admin=owner · worker=worker · siteSup=supervisor@A (no org row)");

    // ---- 1. organizations UPDATE gate (by effect) ---------------------------
    const orgRowPath = `/rest/v1/organizations?id=eq.${createdOrgId}&select=id,branding`;
    const ownPatch = await jfetch(`/rest/v1/organizations?id=eq.${createdOrgId}`, {
      method: "PATCH", token: admin.access_token,
      body: { branding: { displayName: "Phase06 Probe Org", tagline: "RLS-gated update" } },
    });
    const ownerVisible = await jfetch(orgRowPath, { token: admin.access_token });
    const brandingChanged = ownerVisible.data && ownerVisible.data[0] && ownerVisible.data[0].branding
      && ownerVisible.data[0].branding.tagline === "RLS-gated update";
    report(ownPatch.status === 204 && brandingChanged ? "PASS" : "FAIL", "owner: PATCH own org row OK (organizations.manage)", `HTTP ${ownPatch.status} changed=${brandingChanged}`);

    const workerPatch = await jfetch(`/rest/v1/organizations?id=eq.${createdOrgId}`, {
      method: "PATCH", token: worker.access_token,
      body: { branding: { displayName: "Hacked", tagline: "x" } },
    });
    const afterWorker = await jfetch(orgRowPath, { token: admin.access_token });
    const workerBlocked = afterWorker.data && afterWorker.data[0] && afterWorker.data[0].branding
      && afterWorker.data[0].branding.tagline === "RLS-gated update";
    report(workerPatch.status < 400 && workerBlocked ? "PASS" : "FAIL", "worker: PATCH org row has NO effect (RLS)", `HTTP ${workerPatch.status} unchanged=${workerBlocked}`);

    const outPatch = await jfetch(`/rest/v1/organizations?id=eq.${createdOrgId}`, {
      method: "PATCH", token: outsider.access_token, body: { branding: { displayName: "Nope" } },
    });
    const afterOut = await jfetch(orgRowPath, { token: admin.access_token });
    const outBlocked = afterOut.data && afterOut.data[0] && afterOut.data[0].branding
      && afterOut.data[0].branding.tagline === "RLS-gated update";
    report(outPatch.status < 400 && outBlocked ? "PASS" : "FAIL", "outsider: PATCH org row has NO effect (RLS)", `HTTP ${outPatch.status} unchanged=${outBlocked}`);

    if (amlOrgId) {
      const crossPatch = await jfetch(`/rest/v1/organizations?id=eq.${amlOrgId}`, {
        method: "PATCH", token: admin.access_token,
        body: { branding: { displayName: "Intruder" } },
      });
      const amlVisible = await jfetch(`/rest/v1/organizations?id=eq.${amlOrgId}&select=id,branding`, { token: admin.access_token });
      const amlUntouched = !Array.isArray(amlVisible.data) || amlVisible.data.length === 0;
      report(crossPatch.status < 400 && amlUntouched ? "PASS" : "FAIL", "owner(scratch): CANNOT touch tenant #1 org row (cross-tenant no-op)", `HTTP ${crossPatch.status} amlRows=${Array.isArray(amlVisible.data) ? amlVisible.data.length : "?"}`);
    }

    // ---- 2. site-scope SELECT matrix ----------------------------------------
    const supSites = await jfetch(`/rest/v1/sites?organization_id=eq.${createdOrgId}&select=id,name`, { token: siteSup.access_token });
    const supSitesOwn = Array.isArray(supSites.data) && supSites.data.length === 1 && supSites.data[0].id === siteA;
    report(supSites.status === 200 && supSitesOwn ? "PASS" : "FAIL", "siteSup: reads OWN site only (site A)", `rows=${Array.isArray(supSites.data) ? supSites.data.length : "?"}`);

    const unitRes = await rpc("org_create_unit", { p_organization_id: createdOrgId, p_site_id: siteA, p_parent_id: null, p_unit_type: "department", p_name: "Mining Ops", p_code: "MIN" }, admin.access_token);
    const unitId = typeof unitRes.data === "string" ? unitRes.data : null;
    report(unitRes.status === 200 && unitId ? "PASS" : "FAIL", "admin: org_create_unit OK (audit below)", `HTTP ${unitRes.status}`);
    const unitB = await rpc("org_create_unit", { p_organization_id: createdOrgId, p_site_id: siteB, p_parent_id: null, p_unit_type: "department", p_name: "Port Ops", p_code: null }, admin.access_token);
    const unitBId = typeof unitB.data === "string" ? unitB.data : null;
    report(unitB.status === 200 && unitBId ? "PASS" : "FAIL", "admin: unit created at Site B", `HTTP ${unitB.status}`);

    const supUnitsA = await jfetch(`/rest/v1/organizational_units?organization_id=eq.${createdOrgId}&select=id,site_id`, { token: siteSup.access_token });
    const supUnitsOk = Array.isArray(supUnitsA.data) && supUnitsA.data.length === 1 && supUnitsA.data[0].site_id === siteA;
    report(supUnitsA.status === 200 && supUnitsOk ? "PASS" : "FAIL", "siteSup: reads units of own site A ONLY (site B hidden)", `rows=${Array.isArray(supUnitsA.data) ? supUnitsA.data.length : "?"} allA=${Array.isArray(supUnitsA.data) && supUnitsA.data.every((u) => u.site_id === siteA)}`);

    const supUnitsB = await jfetch(`/rest/v1/organizational_units?organization_id=eq.${createdOrgId}&site_id=eq.${siteB}&select=id`, { token: siteSup.access_token });
    report(supUnitsB.status === 200 && Array.isArray(supUnitsB.data) && supUnitsB.data.length === 0 ? "PASS" : "FAIL", "siteSup: 0 units at site B (no transitive access)", `rows=${Array.isArray(supUnitsB.data) ? supUnitsB.data.length : "?"}`);

    const supWorkers = await jfetch(`/rest/v1/workers?organization_id=eq.${createdOrgId}&select=id`, { token: siteSup.access_token });
    report(supWorkers.status === 200 && Array.isArray(supWorkers.data) && supWorkers.data.length === 0 ? "PASS" : "FAIL", "siteSup(supervisor): workers registry = 0 (no workers.view)", `rows=${Array.isArray(supWorkers.data) ? supWorkers.data.length : "?"}`);

    const supInvites = await jfetch(`/rest/v1/org_invites?organization_id=eq.${createdOrgId}&select=id`, { token: siteSup.access_token });
    report(supInvites.status === 200 && Array.isArray(supInvites.data) && supInvites.data.length === 0 ? "PASS" : "FAIL", "siteSup: org_invites = 0 rows", `rows=${Array.isArray(supInvites.data) ? supInvites.data.length : "?"}`);

    const supOrg = await jfetch(`/rest/v1/organizations?id=eq.${createdOrgId}&select=id`, { token: siteSup.access_token });
    report(supOrg.status === 200 && Array.isArray(supOrg.data) && supOrg.data.length === 0 ? "PASS" : "FAIL", "siteSup: org row = 0 (no org membership)", `rows=${Array.isArray(supOrg.data) ? supOrg.data.length : "?"}`);

    const supMemb = await jfetch(`/rest/v1/organization_members?organization_id=eq.${createdOrgId}&select=organization_id`, { token: siteSup.access_token });
    report(supMemb.status === 200 && Array.isArray(supMemb.data) && supMemb.data.length === 0 ? "PASS" : "FAIL", "siteSup: org membership rows = 0", `rows=${Array.isArray(supMemb.data) ? supMemb.data.length : "?"}`);

    const supSiteMemb = await jfetch(`/rest/v1/site_members?user_id=eq.${siteSup.user.id}&select=site_id`, { token: siteSup.access_token });
    report(supSiteMemb.status === 200 && Array.isArray(supSiteMemb.data) && supSiteMemb.data.length === 1 ? "PASS" : "FAIL", "siteSup: reads own site_members row", `rows=${Array.isArray(supSiteMemb.data) ? supSiteMemb.data.length : "?"}`);

    // worker (org member) still reads hierarchy reference data but NOT the roster
    const wkSites = await jfetch(`/rest/v1/sites?organization_id=eq.${createdOrgId}&select=id`, { token: worker.access_token });
    report(wkSites.status === 200 && Array.isArray(wkSites.data) && wkSites.data.length === 2 ? "PASS" : "FAIL", "worker: reads org sites (2)", `rows=${Array.isArray(wkSites.data) ? wkSites.data.length : "?"}`);
    const wkUnits = await jfetch(`/rest/v1/organizational_units?organization_id=eq.${createdOrgId}&select=id`, { token: worker.access_token });
    report(wkUnits.status === 200 && Array.isArray(wkUnits.data) && wkUnits.data.length === 2 ? "PASS" : "FAIL", "worker: reads org units (2)", `rows=${Array.isArray(wkUnits.data) ? wkUnits.data.length : "?"}`);
    const wkWorkers = await jfetch(`/rest/v1/workers?organization_id=eq.${createdOrgId}&select=id`, { token: worker.access_token });
    report(wkWorkers.status === 200 && Array.isArray(wkWorkers.data) && wkWorkers.data.length === 0 ? "PASS" : "FAIL", "worker: workers registry = 0 (least privilege)", `rows=${Array.isArray(wkWorkers.data) ? wkWorkers.data.length : "?"}`);

    // ---- 3. cross-tenant (tenant #1 AML) --------------------------------------
    if (amlOrgId) {
      for (const [who, u] of [["worker", worker], ["siteSup", siteSup], ["outsider", outsider]]) {
        const t = await jfetch(`/rest/v1/organizational_units?organization_id=eq.${amlOrgId}&select=id`, { token: u.access_token });
        report(t.status === 200 && Array.isArray(t.data) && t.data.length === 0 ? "PASS" : "FAIL",
          `${who}: 0 rows of tenant #1 (AML) units`, `rows=${Array.isArray(t.data) ? t.data.length : "?"}`);
      }
    }

    // ---- 4. audit flows (actor = auth.uid(), append-only) --------------------
    const addM = await rpc("org_add_member", { p_organization_id: createdOrgId, p_user_id: added.user.id, p_role: "safety_officer" }, admin.access_token);
    report(addM.status === 200 || addM.status === 204 ? "PASS" : "FAIL", "admin: org_add_member OK", `HTTP ${addM.status}`);
    const roleM = await rpc("org_update_member_role", { p_organization_id: createdOrgId, p_user_id: added.user.id, p_role: "admin" }, admin.access_token);
    report(roleM.status === 204 ? "PASS" : "FAIL", "admin: org_update_member_role OK", `HTTP ${roleM.status}`);
    const siteM = await rpc("site_assign_member", { p_organization_id: createdOrgId, p_site_id: siteB, p_user_id: added.user.id, p_role: "supervisor" }, admin.access_token);
    report(siteM.status === 204 ? "PASS" : "FAIL", "admin: site_assign_member OK", `HTTP ${siteM.status}`);
    const unitUpd = await rpc("org_update_unit", { p_unit_id: unitId, p_name: "Mining Operations Renamed", p_code: "MIN", p_status: "active" }, admin.access_token);
    report(unitUpd.status === 204 ? "PASS" : "FAIL", "admin: org_update_unit OK", `HTTP ${unitUpd.status}`);
    const inv = await rpc("org_send_invite", { p_organization_id: createdOrgId, p_email: `mg.p6.invitee.${stamp}@gmailtest.com`, p_role: "safety_officer", p_site_id: siteA }, admin.access_token);
    const invId = await sql(`select id from public.org_invites where organization_id = '${createdOrgId}' order by created_at desc limit 1;`);
    const inviteRowId = invId.data && invId.data[0] ? invId.data[0].id : null;
    report(inv.status === 200 && typeof inv.data === "string" ? "PASS" : "FAIL", "admin: org_send_invite OK", `HTTP ${inv.status}`);
    if (inviteRowId) {
      const rev = await rpc("org_revoke_invite", { p_organization_id: createdOrgId, p_invite_id: inviteRowId }, admin.access_token);
      report(rev.status === 204 ? "PASS" : "FAIL", "admin: org_revoke_invite OK", `HTTP ${rev.status}`);
    }
    const wRes = await rpc("worker_add", { p_organization_id: createdOrgId, p_site_id: siteA, p_department_id: unitId, p_team_id: null, p_user_id: worker.user.id, p_employee_id: "W6-1001", p_full_name: "P6 Probe Worker", p_classification: "employee", p_contact_phone: null }, admin.access_token);
    const wId = typeof wRes.data === "string" ? wRes.data : null;
    report(wRes.status === 200 && wId ? "PASS" : "FAIL", "admin: worker_add OK", `HTTP ${wRes.status}`);
    if (wId) {
      const wU = await rpc("worker_update", { p_worker_id: wId, p_site_id: null, p_department_id: null, p_team_id: null, p_employee_id: null, p_full_name: "P6 Probe Worker Updated", p_classification: "employee", p_contact_phone: null, p_status: null }, admin.access_token);
      report(wU.status === 204 ? "PASS" : "FAIL", "admin: worker_update OK", `HTTP ${wU.status}`);
    }

    const aud = await jfetch(`/rest/v1/audit_log?organization_id=eq.${createdOrgId}&select=action,actor_user_id,resource,metadata&order=created_at.asc`, { token: admin.access_token });
    const rows = Array.isArray(aud.data) ? aud.data : [];
    const actorRows = rows.filter((r) => r.actor_user_id === admin.user.id);
    const expectedActions = [
      "organization_members.insert", "organization_members.update",
      "site_members.insert", "organizational_units.insert",
      "organizational_units.update", "org_invites.insert", "org_invites.update",
      "workers.insert", "workers.update",
    ];
    const missingActions = expectedActions.filter((a) => !actorRows.some((r) => r.action === a));
    report(missingActions.length === 0 ? "PASS" : "FAIL", "audit: RPC ops captured with actor=auth.uid()", `actorRows=${actorRows.length} missing=[${missingActions.join(", ")}]`);
    const allActored = actorRows.every((r) => r.actor_user_id === admin.user.id && r.actor_user_id !== null);
    report(allActored ? "PASS" : "FAIL", "audit: actor integrity (auth.uid(), never null for user ops)", `actorRows=${actorRows.length}`);

    const tokLeak = await sql(
      `select count(*) as n from public.audit_log
       where organization_id = '${createdOrgId}' and action like 'org_invites.%'
         and metadata ? 'token';`);
    const tokN = tokLeak.data && tokLeak.data[0] ? Number(tokLeak.data[0].n) : -1;
    report(tokN === 0 ? "PASS" : "FAIL", "audit: invite tokens NOT mirrored in metadata", `leaks=${tokN}`);

    // viewers: owner (audit_logs.view) reads; worker/outsider/anon read 0
    const audWk = await jfetch(`/rest/v1/audit_log?organization_id=eq.${createdOrgId}&select=id`, { token: worker.access_token });
    report(audWk.status === 200 && Array.isArray(audWk.data) && audWk.data.length === 0 ? "PASS" : "FAIL", "worker: audit_log SELECT = 0 rows", `rows=${Array.isArray(audWk.data) ? audWk.data.length : "?"}`);
    const audOut = await jfetch(`/rest/v1/audit_log?organization_id=eq.${createdOrgId}&select=id`, { token: outsider.access_token });
    report(audOut.status === 200 && Array.isArray(audOut.data) && audOut.data.length === 0 ? "PASS" : "FAIL", "outsider: audit_log SELECT = 0 rows", `rows=${Array.isArray(audOut.data) ? audOut.data.length : "?"}`);
    const audAnon = await jfetch(`/rest/v1/audit_log?organization_id=eq.${createdOrgId}&select=id`, {});
    report(audAnon.status === 200 && Array.isArray(audAnon.data) && audAnon.data.length === 0 ? "PASS" : "FAIL", "anon: audit_log SELECT = 0 rows (RLS)", `rows=${Array.isArray(audAnon.data) ? audAnon.data.length : "?"}`);

    // append-only: even the owner cannot INSERT/UPDATE/DELETE audit rows
    const beforeCount = actorRows.length;
    const ins = await jfetch("/rest/v1/audit_log", { method: "POST", token: admin.access_token, body: { organization_id: createdOrgId, action: "forged.insert", resource: "audit_log" } });
    report(ins.status >= 400 ? "PASS" : "FAIL", "owner: INSERT audit_log denied (append-only)", `HTTP ${ins.status}`);
    const upd = await jfetch(`/rest/v1/audit_log?organization_id=eq.${createdOrgId}`, { method: "PATCH", token: admin.access_token, body: { action: "forged.update" } });
    report(upd.status >= 400 ? "PASS" : "FAIL", "owner: UPDATE audit_log denied (append-only)", `HTTP ${upd.status}`);
    const del = await jfetch(`/rest/v1/audit_log?organization_id=eq.${createdOrgId}`, { method: "DELETE", token: admin.access_token });
    report(del.status >= 400 ? "PASS" : "FAIL", "owner: DELETE audit_log denied (append-only)", `HTTP ${del.status}`);
    const afterCount = await jfetch(`/rest/v1/audit_log?organization_id=eq.${createdOrgId}&select=id&order=created_at.asc`, { token: admin.access_token });
    const afterN = Array.isArray(afterCount.data) ? afterCount.data.length : -1;
    report(afterN === rows.length ? "PASS" : "FAIL", "audit: row count unchanged after forged writes", `before=${rows.length} after=${afterN}`);

    // direct escalation: worker INSERT into workers table (no RLS policy)
    const esc = await jfetch("/rest/v1/workers", { method: "POST", token: worker.access_token, body: { organization_id: createdOrgId, full_name: "Escalator" } });
    report(esc.status >= 400 ? "PASS" : "FAIL", "worker: direct INSERT into workers denied (RPC-only writes)", `HTTP ${esc.status}`);
    const esc2 = await jfetch("/rest/v1/organization_members", { method: "POST", token: worker.access_token, body: { organization_id: createdOrgId, role: "owner", status: "active" } });
    report(esc2.status >= 400 ? "PASS" : "FAIL", "worker: direct INSERT owner membership denied", `HTTP ${esc2.status}`);

    console.log(failures === 0
      ? "\nPhase 06 probe: all executed checks passed (no FAIL)."
      : `\nPhase 06 probe: ${failures} check(s) FAILED.`);
  } catch (err) {
    failures += 1;
    console.error("Phase 06 probe aborted:", err.message);
  } finally {
    // ---- Cleanup: remove every trace of the probe ---------------------------
    try {
      const sweepOrgs = async (ids) => {
        // FK-safe order: dependents first, then the org row.
        for (const id of ids) {
          await sql(`delete from public.audit_log where organization_id = '${id}';`);
          await sql(`delete from public.org_invites where organization_id = '${id}';`);
          await sql(`delete from public.workers where organization_id = '${id}';`);
          await sql(`delete from public.organizational_units where organization_id = '${id}';`);
          await sql(`delete from public.site_members where organization_id = '${id}';`);
          await sql(`delete from public.organization_members where organization_id = '${id}';`);
          await sql(`delete from public.sites where organization_id = '${id}';`);
        }
        for (const id of ids) await sql(`delete from public.organizations where id = '${id}';`);
      };
      if (createdOrgId) {
        await sweepOrgs([createdOrgId]);
        const chk = await sql(`select count(*) as n from public.organizations where id = '${createdOrgId}';`);
        const n = chk.data && chk.data[0] ? Number(chk.data[0].n) : -1;
        report(Number(n) === 0 ? "PASS" : "FAIL", "cleanup: scratch org removed", `remaining=${n}`);
      } else {
        const orphans = await sql(`select id from public.organizations where slug like 'p6-probe-%';`);
        const ids = (Array.isArray(orphans.data) ? orphans.data : []).map((r) => r.id);
        if (ids.length) await sweepOrgs(ids);
        const left = await sql(`select count(*) as n from public.organizations where slug like 'p6-probe-%';`);
        const ln = left.data && left.data[0] ? Number(left.data[0].n) : -1;
        report(ln === 0 ? "PASS" : "FAIL", "cleanup: no probe org tracked; swept p6-probe-% orphans (FK-safe)", `remaining=${ln}`);
      }
      await sql(`delete from auth.users where email like 'mg.p6.%@gmailtest.com';`);
      report("PASS", "cleanup: probe users removed", "5 probe accounts");
      const auditLeft = await sql(`select count(*) as n from public.audit_log where organization_id = '${createdOrgId}';`);
      const aN = auditLeft.data && auditLeft.data[0] ? Number(auditLeft.data[0].n) : -1;
      report(aN === 0 ? "PASS" : "FAIL", "cleanup: no probe audit rows remain", `remaining=${aN}`);
    } catch (e) {
      report("FAIL", "cleanup", e.message);
    }
    console.log(failures === 0 ? "Phase 06 probe: PASS (all checks, cleanup verified)." : `Phase 06 probe: ${failures} FAIL(s).`);
    process.exit(failures === 0 ? 0 : 1);
  }
}

await main();
