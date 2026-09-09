// ============================================================
// Phase 12 verification probe — SaaS + enterprise administration
// Live end-to-end against the linked Supabase project.
//   1. catalog: plans/subscriptions tables, Phase 12 RPCs, audit triggers
//   2. SaaS modeling: plan catalog visible; subscription read (RLS)
//   3. site lifecycle: site_create/update/remove as org admin
//   4. org settings + branding via org_update_settings
//   5. org subscription switch via org_update_subscription
//   6. grant expiry: issue with p_expires_at; regulator_extend_grant
//   7. platform layer: bootstrap one-shot, list orgs, status update gated
//   8. gov_national_overview: aggregate matches row counts, gated by grants
//   9. isolation: non-privileged users cannot invoke admin RPCs
//  10. self-cleanup of all probe artifacts
// Usage: SUPABASE_ACCESS_TOKEN=... node scripts/verify-phase12.mjs
// ============================================================
import { readFileSync } from "node:fs";

const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
if (!TOKEN) { console.error("SUPABASE_ACCESS_TOKEN required"); process.exit(1); }
const REF = JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;

// URL + anon key are PUBLIC (config.js convention used by all prior probes).
const APP = "https://" + REF + ".supabase.co";
let ANON_SYNC = null;
try {
  const cfg = readFileSync("config.js", "utf8");
  ANON_SYNC = (cfg.match(/supabaseAnonKey:\s*"([^"]+)"/) || [])[1] || "";
} catch { /* config.js missing */ }
if (!ANON_SYNC) { console.error("Cannot read public anon key from config.js"); process.exit(1); }

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log("PASS", name); }
  else { fail++; console.log("FAIL", name, detail ? "— " + detail : ""); }
}

async function sql(query, params) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query, parameters: params || [] })
  });
  const body = await res.text();
  if (!res.ok) throw new Error(`mgmt SQL ${res.status}: ${body}`);
  return JSON.parse(body);
}
async function sqlOne(query, params) { const r = await sql(query, params); return r[0] || null; }

const scratchSuffix = Math.random().toString(36).slice(2, 8);


function parseBody(b) { try { return JSON.parse(b); } catch { return b; } }

async function signup(email, password) {
  const res = await fetch(APP + "/auth/v1/signup", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: await anonKey(),
      Authorization: "Bearer " + await anonKey()
    },
    body: JSON.stringify({ email, password })
  });
  const body = await res.json();
  if (!res.ok) throw new Error("signup " + res.status + ": " + JSON.stringify(body));
  if (body.access_token) return body.access_token;
  // email confirmation enabled — sign in instead
  return signin(email, password);
}
async function signin(email, password) {
  const res = await fetch(APP + "/auth/v1/token?grant_type=password", {
    method: "POST",
    headers: { "Content-Type": "application/json", apikey: await anonKey() },
    body: JSON.stringify({ email, password })
  });
  const body = await res.json();
  if (!res.ok) throw new Error("signin " + res.status + ": " + JSON.stringify(body));
  return body.access_token;
}
async function anonKey() { return ANON_SYNC; }

function pg(path, method, token, bodyObj) {
  return fetch(APP + "/rest/v1/" + path, {
    method: method || "GET",
    headers: {
      apikey: ANON_SYNC, Authorization: "Bearer " + token,
      "Content-Type": "application/json",
      Accept: method === "GET" ? "application/json" : "application/json",
      Prefer: method && method !== "GET" && method !== "PATCH" ? "return=representation" : "return=representation"
    },
    body: bodyObj === undefined ? undefined : JSON.stringify(bodyObj)
  }).then(async r => ({ status: r.status, body: await r.text() }));
}

// ---------- main ----------
const artifacts = { orgIds: [], userIds: [], grantIds: [], siteIds: [], extraOrgIds: [] };
try {
  // ============ 1. catalog ============
  const planTable = await sqlOne(
    "select count(*)::int as n from information_schema.tables where table_schema='public' and table_name in ('plans','subscriptions')");
  ok("catalog: plans + subscriptions tables exist", planTable && planTable.n === 2, JSON.stringify(planTable));

  const planCols = await sqlOne(
    "select count(*)::int as n from information_schema.columns where table_schema='public' and table_name='plans' and column_name in ('code','name','max_sites','max_users','features','sort_order')");
  ok("catalog: plans columns", planCols && planCols.n === 6, JSON.stringify(planCols));

  const rpcs = await sqlOne(
    "select count(*)::int as n from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname in ('site_create','site_update','site_remove','org_update_settings','org_update_subscription','regulator_extend_grant','bootstrap_first_platform_admin','platform_list_organizations','platform_update_organization_status','gov_national_overview')");
  ok("catalog: 10 Phase 12 RPCs", rpcs && rpcs.n === 10, "found " + (rpcs && rpcs.n));

  const plansSeeded = await sqlOne("select count(*)::int as n from public.plans");
  ok("catalog: plans seeded (>=3 tiers)", plansSeeded && plansSeeded.n >= 3, "found " + (plansSeeded && plansSeeded.n));

  const grantIssueSig = await sqlOne(
    "select count(*)::int as n from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname='regulator_issue_grant'");
  const issueArgs = await sql(
    "select pg_get_function_arguments(p.oid) as args from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname='regulator_issue_grant'");
  const hasExpires = issueArgs.some(r => String(r.args).includes("p_expires_at"));
  ok("catalog: regulator_issue_grant accepts p_expires_at", grantIssueSig && grantIssueSig.n >= 1 && hasExpires, JSON.stringify(issueArgs));

  // ============ create probe actors ============
  // Seed org: reuse a benign existing org? NO — create scratch orgs; never touch AML/seed data.
  const mkOrg = async (name, slug) => {
    const row = await sqlOne(
      "insert into public.organizations (name, slug) values ($1,$2) returning id", [name, slug]);
    artifacts.orgIds.push(row.id);
    return row.id;
  };
  const targetOrg = await mkOrg("P12 Target " + scratchSuffix, "p12-target-" + scratchSuffix);
  const regOrg = await mkOrg("P12 Reg " + scratchSuffix, "p12-reg-" + scratchSuffix);

  const mkUser = async (local) => {
    const email = local + "-" + scratchSuffix + "@p12probe.test";
    const tok = await signup(email, "Probe-Passw0rd!23");
    const u = await sqlOne("select id from auth.users where email = $1", [email]);
    artifacts.userIds.push(u.id);
    return { id: u.id, email, token: tok };
  };

  const admin = await mkUser("p12admin");
  const worker = await mkUser("p12worker");
  const regAdmin = await mkUser("p12regadmin");

  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'owner','active')",
    [targetOrg, admin.id]);
  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'worker','active')",
    [targetOrg, worker.id]);
  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'national_regulatory_admin','active')",
    [regOrg, regAdmin.id]);

  // ============ 2. SaaS modeling ============
  const plansGet = await pg("plans?select=code,name,max_sites,max_users&order=sort_order.asc", "GET", admin.token);
  ok("SaaS: plan catalog readable by authenticated user", plansGet.status === 200 && (parseBody(plansGet.body) || []).length >= 3, plansGet.status + " " + plansGet.body.slice(0, 120));

  const anonPlans = await pg("plans?select=code", "GET", ANON_SYNC);
  ok("SaaS: plan catalog readable by anon (public pricing)", anonPlans.status === 200, anonPlans.status + " " + anonPlans.body.slice(0, 120));

  const subsAnon = await pg("subscriptions?select=id", "GET", ANON_SYNC);
  ok("SaaS: subscriptions NOT readable by anon", subsAnon.status >= 400 || (parseBody(subsAnon.body) || []).length === 0, subsAnon.status + " " + subsAnon.body.slice(0, 120));

  // ============ 3. site lifecycle ============
  const siteCreated = await pg("rpc/site_create", "POST", admin.token,
    { p_organization_id: targetOrg, p_name: "P12 Site A " + scratchSuffix, p_location: "Liberia", p_county: "Nimba" });
  // scalar uuid RPC → PostgREST returns a bare JSON string
  const siteId = typeof parseBody(siteCreated.body) === "string" ? parseBody(siteCreated.body)
    : (Array.isArray(parseBody(siteCreated.body)) ? parseBody(siteCreated.body)[0]?.id : parseBody(siteCreated.body)?.id);
  ok("sites: org_admin can site_create", siteCreated.status === 200 && !!siteId, siteCreated.status + " " + siteCreated.body.slice(0, 200));
  if (siteId) artifacts.siteIds.push(siteId);

  const siteUpdated = await pg("rpc/site_update", "POST", admin.token,
    { p_site_id: siteId, p_name: "P12 Site A Renamed " + scratchSuffix, p_location: null, p_county: null });
  ok("sites: org_admin can site_update", siteUpdated.status === 200 || siteUpdated.status === 204, siteUpdated.status + " " + siteUpdated.body.slice(0, 200));

  const siteByWorker = await pg("rpc/site_create", "POST", worker.token,
    { p_organization_id: targetOrg, p_name: "should fail", p_location: null, p_county: null });
  ok("sites: worker CANNOT site_create", siteByWorker.status >= 400, siteByWorker.status + " " + siteByWorker.body.slice(0, 160));

  // ============ 4. org settings ============
  const settings = await pg("rpc/org_update_settings", "POST", admin.token,
    { p_organization_id: targetOrg, p_settings: { timezone: "Africa/Monrovia", report_prefix: "P12" }, p_branding: { primary_color: "#006B3F" } });
  ok("settings: org_admin can org_update_settings", settings.status === 200 || settings.status === 204, settings.status + " " + settings.body.slice(0, 200));
  const orgAfter = await sqlOne("select settings->>'timezone' as tz, branding->>'primary_color' as color from public.organizations where id=$1", [targetOrg]);
  ok("settings: persisted to organizations row", orgAfter && orgAfter.tz === "Africa/Monrovia" && orgAfter.color === "#006B3F", JSON.stringify(orgAfter));

  const settingsByWorker = await pg("rpc/org_update_settings", "POST", worker.token,
    { p_organization_id: targetOrg, p_settings: { timezone: "UTC" }, p_branding: null });
  ok("settings: worker CANNOT org_update_settings", settingsByWorker.status >= 400, settingsByWorker.status + " " + settingsByWorker.body.slice(0, 160));

  // ============ 5. subscription ============
  const subSet = await pg("rpc/org_update_subscription", "POST", admin.token,
    { p_organization_id: targetOrg, p_plan_code: "enterprise" });
  ok("subscription: org_admin can switch plan", subSet.status === 200 || subSet.status === 204, subSet.status + " " + subSet.body.slice(0, 200));
  const subRow = await sqlOne("select plan_code, status from public.subscriptions where organization_id=$1 and status in ('active','trialing') order by created_at desc limit 1", [targetOrg]);
  ok("subscription: row persisted with plan_code", subRow && subRow.plan_code === "enterprise", JSON.stringify(subRow));

  const subByWorker = await pg("rpc/org_update_subscription", "POST", worker.token,
    { p_organization_id: targetOrg, p_plan_code: "starter" });
  ok("subscription: worker CANNOT switch plan", subByWorker.status >= 400, subByWorker.status + " " + subByWorker.body.slice(0, 160));

  // ============ 6. grant expiry ============
  // Issue an expiring grant as regulator admin (needs gov bootstrap first for regAdmin? regAdmin already gov_admin member — issue directly).
  const issued = await pg("rpc/regulator_issue_grant", "POST", regAdmin.token,
    { p_target_org_id: targetOrg, p_site_id: siteId, p_scope: "p12 probe", p_regulator_user_id: regAdmin.id, p_expires_at: new Date(Date.now() + 7 * 864e5).toISOString() });
  const issuedBody = parseBody(issued.body);
  const grantId = Array.isArray(issuedBody) ? issuedBody[0] : (typeof issuedBody === "string" ? issuedBody : (issuedBody && issuedBody.id));
  ok("grants: issue with p_expires_at succeeds", issued.status === 200 && !!grantId, issued.status + " " + issued.body.slice(0, 200));
  if (grantId) artifacts.grantIds.push(grantId);
  const grantRow = grantId ? await sqlOne("select expires_at, status from public.government_grants where id=$1", [grantId]) : null;
  ok("grants: expires_at persisted", grantRow && !!grantRow.expires_at, JSON.stringify(grantRow));

  const extended = await pg("rpc/regulator_extend_grant", "POST", regAdmin.token,
    { p_grant_id: grantId, p_expires_at: new Date(Date.now() + 30 * 864e5).toISOString() });
  ok("grants: regulator_extend_grant updates expiry", extended.status === 200 || extended.status === 204, extended.status + " " + extended.body.slice(0, 200));
  const grantRow2 = grantId ? await sqlOne("select expires_at from public.government_grants where id=$1", [grantId]) : null;
  ok("grants: new expiry persisted", grantRow2 && new Date(grantRow2.expires_at) > new Date(Date.now() + 20 * 864e5), JSON.stringify(grantRow2));

  const extendByOther = await pg("rpc/regulator_extend_grant", "POST", admin.token,
    { p_grant_id: grantId, p_expires_at: new Date(Date.now() + 365 * 864e5).toISOString() });
  ok("grants: non-regulator CANNOT extend grant", extendByOther.status >= 400, extendByOther.status + " " + extendByOther.body.slice(0, 160));

  // ============ 7. platform layer ============
  const boot = await pg("rpc/bootstrap_first_platform_admin", "POST", admin.token, {});
  // First platform admin bootstrap: succeeds only if no platform admin exists yet; here we
  // expect it NOT to be claimable (seeded platform admin exists) OR to fail for the non-platform user.
  ok("platform: bootstrap is one-shot/gated for regular org admin", boot.status >= 400 || parseBody(boot.body) === null || parseBody(boot.body) === false, boot.status + " " + boot.body.slice(0, 200));

  const listByWorker = await pg("rpc/platform_list_organizations", "POST", worker.token, {});
  ok("platform: org worker CANNOT platform_list_organizations", listByWorker.status >= 400 || (parseBody(listByWorker.body) || { error: 1 }).error, listByWorker.status + " " + listByWorker.body.slice(0, 160));

  const statusByWorker = await pg("rpc/platform_update_organization_status", "POST", worker.token,
    { p_organization_id: targetOrg, p_new_status: "suspended" });
  ok("platform: non-platform user CANNOT change org status", statusByWorker.status >= 400, statusByWorker.status + " " + statusByWorker.body.slice(0, 160));

  // ============ 8. national overview ============
  // regAdmin holds the grant → national overview should be callable for grant holders.
  // overview columns: granted_orgs, incidents_total, incidents_open,
  // inspections_total, capas_open, emergency_total, emergency_active, sites_total
  const natForReg = await pg("rpc/gov_national_overview", "POST", regAdmin.token, {});
  const natRow = Array.isArray(parseBody(natForReg.body)) ? parseBody(natForReg.body)[0] : parseBody(natForReg.body);
  ok("national: callable by granted regulator", natForReg.status === 200 && natRow && typeof natRow.granted_orgs === "number", natForReg.status + " " + natForReg.body.slice(0, 200));
  ok("national: counts reflect the probe grant", natRow && natRow.granted_orgs >= 1 && natRow.sites_total >= 1, JSON.stringify(natRow));

  const natForWorker = await pg("rpc/gov_national_overview", "POST", worker.token, {});
  const natW = Array.isArray(parseBody(natForWorker.body)) ? parseBody(natForWorker.body)[0] : parseBody(natForWorker.body);
  ok("national: non-granted user sees zeros (no blanket stats)", natForWorker.status >= 400 || (natW && natW.granted_orgs === 0 && natW.incidents_total === 0), natForWorker.status + " " + natForWorker.body.slice(0, 200));

  // Revoke → overview no longer counts it
  const revoked = await pg("rpc/regulator_revoke_grant", "POST", regAdmin.token, { p_grant_id: grantId });
  ok("grants: revoke still works (Phase 11 preserved)", revoked.status === 200 || revoked.status === 204, revoked.status);
  const natAfter = await pg("rpc/gov_national_overview", "POST", regAdmin.token, {});
  const natAfterRow = Array.isArray(parseBody(natAfter.body)) ? parseBody(natAfter.body)[0] : parseBody(natAfter.body);
  ok("national: revoked grant excluded from roll-up", natAfterRow && natAfterRow.granted_orgs === 0, JSON.stringify(natAfterRow));

  // ============ 9. audit coverage ============
  const auditRows = await sqlOne(
    "select count(*)::int as n from public.audit_log where resource in ('sites','subscriptions','government_grants') and created_at > now() - interval '10 minutes'");
  ok("audit: Phase 12 actions land in audit_log", auditRows && auditRows.n >= 1, JSON.stringify(auditRows));

} catch (e) {
  fail++;
  console.log("FAIL probe-abort —", e.message);
} finally {
  // ============ 10. self-cleanup ============
  try {
    if (artifacts.grantIds.length) {
      await sql("delete from public.government_grants where id = any($1::uuid[])", [artifacts.grantIds]);
    }
    // users last (memberships/grants FK)
    if (artifacts.userIds.length) {
      await sql("delete from public.organization_members where user_id = any($1::uuid[])", [artifacts.userIds]);
      await sql("delete from auth.users where id = any($1::uuid[])", [artifacts.userIds]);
    }
    if (artifacts.siteIds.length) {
      await sql("delete from public.sites where id = any($1::uuid[])", [artifacts.siteIds]);
    }
    if (artifacts.orgIds.length) {
      await sql("delete from public.subscriptions where organization_id = any($1::uuid[])", [artifacts.orgIds]);
      await sql("delete from public.audit_log where organization_id = any($1::uuid[])", [artifacts.orgIds]);
      await sql("delete from public.organizations where id = any($1::uuid[])", [artifacts.orgIds]);
    }
    console.log(`cleanup: removed ${artifacts.orgIds.length} orgs, ${artifacts.userIds.length} users, ${artifacts.grantIds.length} grants, ${artifacts.siteIds.length} sites`);
  } catch (e) {
    console.log("cleanup-error:", e.message);
  }
}

console.log(`\nverify-phase12: ${pass} PASS, ${fail} FAIL`);
process.exit(fail ? 1 : 0);
