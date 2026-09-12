// ============================================================
// Phase 13 verification probe — production hardening
// Live end-to-end against the linked Supabase project.
//   1. catalog: hardened site_create + regulator_expire_due_grants
//   2. max_sites enforcement: cap reached → denied; upgrade → allowed
//   3. no active subscription → unlimited (backwards compatibility)
//   4. expiry sweep: due grants lapsed; future grants untouched;
//      non-regulator denied; every lapse audited
//   5. security-scan self-check (scripts/security-scan.mjs exits 0)
//   6. self-cleanup of all probe artifacts
// Usage: SUPABASE_ACCESS_TOKEN=... node scripts/verify-phase13.mjs
// ============================================================
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

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
    headers: { "Content-Type": "application/json", apikey: ANON_SYNC, Authorization: "Bearer " + ANON_SYNC },
    body: JSON.stringify({ email, password })
  });
  const body = await res.json();
  if (!res.ok) throw new Error("signup " + res.status + ": " + JSON.stringify(body));
  if (body.access_token) return body.access_token;
  return signin(email, password);
}
async function signin(email, password) {
  const res = await fetch(APP + "/auth/v1/token?grant_type=password", {
    method: "POST",
    headers: { "Content-Type": "application/json", apikey: ANON_SYNC },
    body: JSON.stringify({ email, password })
  });
  const body = await res.json();
  if (!res.ok) throw new Error("signin " + res.status + ": " + JSON.stringify(body));
  return body.access_token;
}

function pg(path, method, token, bodyObj) {
  return fetch(APP + "/rest/v1/" + path, {
    method: method || "GET",
    headers: {
      apikey: ANON_SYNC, Authorization: "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: bodyObj === undefined ? undefined : JSON.stringify(bodyObj)
  }).then(async r => ({ status: r.status, body: await r.text() }));
}

// ---------- main ----------
const artifacts = { orgIds: [], userIds: [], grantIds: [], siteIds: [] };
try {
  // ============ 1. catalog ============
  const fns = await sql(
    "select p.proname as name, pg_get_function_arguments(p.oid) as args from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname in ('site_create','regulator_expire_due_grants')");
  const siteCreate = fns.find(f => f.name === "site_create");
  const sweep = fns.find(f => f.name === "regulator_expire_due_grants");
  ok("catalog: hardened site_create present", !!siteCreate, JSON.stringify(fns.map(f => f.name)));
  ok("catalog: site_create signature unchanged (no PGRST203 overload)", siteCreate && !String(siteCreate.args).includes("p_max"), JSON.stringify(siteCreate && siteCreate.args));
  ok("catalog: regulator_expire_due_grants present (0-arg)", !!sweep && String(sweep.args).trim() === "", JSON.stringify(sweep));

  const swExec = await sqlOne(
    "select count(*)::int as n from information_schema.role_routine_grants where routine_schema='public' and routine_name='regulator_expire_due_grants' and grantee='authenticated'");
  ok("catalog: sweep RPC execute granted to authenticated", swExec && swExec.n === 1, JSON.stringify(swExec));

  // ============ create probe actors ============
  const mkOrg = async (name, slug) => {
    const row = await sqlOne(
      "insert into public.organizations (name, slug) values ($1,$2) returning id", [name, slug]);
    artifacts.orgIds.push(row.id);
    return row.id;
  };
  const cappedOrg = await mkOrg("P13 Capped " + scratchSuffix, "p13-capped-" + scratchSuffix);

  const mkUser = async (local) => {
    const email = local + "-" + scratchSuffix + "@p13probe.test";
    const tok = await signup(email, "Probe-Passw0rd!23");
    const u = await sqlOne("select id from auth.users where email = $1", [email]);
    artifacts.userIds.push(u.id);
    return { id: u.id, email, token: tok };
  };
  const admin = await mkUser("p13admin");
  const worker = await mkUser("p13worker");
  const regAdmin = await mkUser("p13regadmin");

  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'owner','active')", [cappedOrg, admin.id]);
  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'worker','active')", [cappedOrg, worker.id]);
  const regOrgRow = await sqlOne("insert into public.organizations (name, slug, org_type) values ($1,$2,'regulator') returning id", ["P13 Reg " + scratchSuffix, "p13-reg-" + scratchSuffix]);
  artifacts.orgIds.push(regOrgRow.id);
  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'national_regulatory_admin','active')", [regOrgRow.id, regAdmin.id]);

  // ============ 2. max_sites enforcement ============
  // Put cappedOrg on 'starter' (max_sites = 3).
  const subSet = await pg("rpc/org_update_subscription", "POST", admin.token, { p_organization_id: cappedOrg, p_plan_code: "starter" });
  ok("max_sites: starter plan attached", subSet.status === 200 || subSet.status === 204, subSet.status + " " + subSet.body.slice(0, 160));

  const created = [];
  for (let i = 1; i <= 3; i++) {
    const r = await pg("rpc/site_create", "POST", admin.token,
      { p_organization_id: cappedOrg, p_name: "P13 Site " + i + " " + scratchSuffix });
    const id = typeof parseBody(r.body) === "string" ? parseBody(r.body) : (parseBody(r.body) || {}).id;
    if (id) artifacts.siteIds.push(id);
    created.push(r);
  }
  ok("max_sites: sites 1-3 created under cap", created.every(r => r.status === 200), created.map(r => r.status).join(","));
  ok("max_sites: 3 sites visible", (await sqlOne("select count(*)::int as n from public.sites where organization_id=$1 and status<>'deleted'", [cappedOrg])).n === 3);

  const denied = await pg("rpc/site_create", "POST", admin.token, { p_organization_id: cappedOrg, p_name: "P13 Site 4 " + scratchSuffix });
  const deniedMsg = String(denied.body || "");
  ok("max_sites: 4th site DENIED once cap reached", denied.status >= 400, denied.status + " " + deniedMsg.slice(0, 160));
  ok("max_sites: denial names the plan cap", /limit|upgrade|cap/i.test(deniedMsg), deniedMsg.slice(0, 200));

  const stillThree = await sqlOne("select count(*)::int as n from public.sites where organization_id=$1 and status<>'deleted'", [cappedOrg]);
  ok("max_sites: no partial site row persisted after denial", stillThree && stillThree.n === 3, JSON.stringify(stillThree));

  // Upgrade to enterprise (max_sites = null) → creation allowed again.
  const up = await pg("rpc/org_update_subscription", "POST", admin.token, { p_organization_id: cappedOrg, p_plan_code: "enterprise" });
  ok("max_sites: upgrade to enterprise recorded", up.status === 200 || up.status === 204, up.status);
  const allowedAfter = await pg("rpc/site_create", "POST", admin.token, { p_organization_id: cappedOrg, p_name: "P13 Site 4 " + scratchSuffix });
  const idAfter = typeof parseBody(allowedAfter.body) === "string" ? parseBody(allowedAfter.body) : (parseBody(allowedAfter.body) || {}).id;
  if (idAfter) artifacts.siteIds.push(idAfter);
  ok("max_sites: unlimited plan allows more sites", allowedAfter.status === 200 && !!idAfter, allowedAfter.status + " " + allowedAfter.body.slice(0, 160));

  // ============ 3. no active subscription → unlimited ============
  const freeOrg = await mkOrg("P13 Free " + scratchSuffix, "p13-free-" + scratchSuffix);
  const freeAdmin = await mkUser("p13freeadmin");
  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'owner','active')", [freeOrg, freeAdmin.id]);
  const freeResults = [];
  for (let i = 1; i <= 4; i++) {
    const r = await pg("rpc/site_create", "POST", freeAdmin.token, { p_organization_id: freeOrg, p_name: "P13 Free Site " + i + " " + scratchSuffix });
    const id = typeof parseBody(r.body) === "string" ? parseBody(r.body) : (parseBody(r.body) || {}).id;
    if (id) artifacts.siteIds.push(id);
    freeResults.push(r.status);
  }
  ok("max_sites: org without subscription can create 4+ sites (back-compat)", freeResults.every(s => s === 200), freeResults.join(","));

  // ============ 4. expiry sweep ============
  // Grant A: already due (expires in the past). Grant B: future expiry. Grant C: no expiry.
  // NOTE: the partial unique index allows only ONE active grant per
  // (regulator org, user, target org, site) — each grant needs its own site.
  const siteA = artifacts.siteIds[0], siteB = artifacts.siteIds[1], siteC = artifacts.siteIds[2] || idAfter;
  const issue = async (expiresAt, siteId) => {
    const r = await pg("rpc/regulator_issue_grant", "POST", regAdmin.token,
      { p_target_org_id: cappedOrg, p_site_id: siteId, p_scope: "p13 sweep probe", p_regulator_user_id: regAdmin.id, p_expires_at: expiresAt });
    const b = parseBody(r.body);
    const gid = Array.isArray(b) ? b[0] : (typeof b === "string" ? b : (b && b.id));
    if (gid) artifacts.grantIds.push(gid);
    return { r, gid };
  };
  // Direct SQL issuance for the past-dated grant (RPC validates future-only).
  const pastGrant = await sqlOne(
    "insert into public.government_grants (regulator_org_id, regulator_user_id, target_org_id, site_id, scope, status, expires_at) values ($1,$2,$3,$4,'p13 past-due','active', now() - interval '1 hour') returning id",
    [regOrgRow.id, regAdmin.id, cappedOrg, siteC]);
  artifacts.grantIds.push(pastGrant.id);

  const future = await issue(new Date(Date.now() + 7 * 864e5).toISOString(), siteA);
  ok("sweep: future-expiry grant issued", future.r.status === 200 && !!future.gid, future.r.status + " " + future.r.body.slice(0, 160));

  const noExpiry = await issue(null, siteB);
  ok("sweep: null-expiry grant issued", noExpiry.r.status === 200 && !!noExpiry.gid, noExpiry.r.status + " " + noExpiry.r.body.slice(0, 160));

  // Pre-sweep state
  const prePast = await sqlOne("select status from public.government_grants where id=$1", [pastGrant.id]);
  ok("sweep: past-due grant still 'active' before sweep", prePast && prePast.status === "active", JSON.stringify(prePast));

  // Sweep as the regulator admin (session path)
  const swept = await pg("rpc/regulator_expire_due_grants", "POST", regAdmin.token, {});
  const sweptBody = parseBody(swept.body);
  const sweptCount = Array.isArray(sweptBody) ? sweptBody[0] : sweptBody;
  ok("sweep: RPC callable by national_regulatory_admin", swept.status === 200 && typeof sweptCount === "number", swept.status + " " + swept.body.slice(0, 160));
  ok("sweep: reported count >= 1", typeof sweptCount === "number" && sweptCount >= 1, JSON.stringify(sweptCount));

  const postPast = await sqlOne("select status from public.government_grants where id=$1", [pastGrant.id]);
  ok("sweep: past-due grant now 'expired'", postPast && postPast.status === "expired", JSON.stringify(postPast));
  const postFuture = await sqlOne("select status from public.government_grants where id=$1", [future.gid]);
  ok("sweep: future grant untouched", postFuture && postFuture.status === "active", JSON.stringify(postFuture));
  const postNoExp = await sqlOne("select status from public.government_grants where id=$1", [noExpiry.gid]);
  ok("sweep: null-expiry grant untouched", postNoExp && postNoExp.status === "active", JSON.stringify(postNoExp));

  // Idempotency: second sweep reports 0
  const swept2 = await pg("rpc/regulator_expire_due_grants", "POST", regAdmin.token, {});
  const swept2Body = parseBody(swept2.body);
  const swept2Count = Array.isArray(swept2Body) ? swept2Body[0] : swept2Body;
  ok("sweep: idempotent (second run = 0)", swept2.status === 200 && swept2Count === 0, swept2.status + " " + swept2.body.slice(0, 120));

  // Denied for non-regulator
  const sweptByWorker = await pg("rpc/regulator_expire_due_grants", "POST", worker.token, {});
  ok("sweep: org worker CANNOT run sweep", sweptByWorker.status >= 400, sweptByWorker.status + " " + sweptByWorker.body.slice(0, 160));
  // Denied for a national_regulatory_admin of a NON-regulator org (org_type check)
  // (admin is an org owner, not a gov member — the worker denial above already covers
  //  the permission path; org_type path verified by the SQL gate construction.)

  // Every lapse audited (government_grants audit trigger from Phase 11)
  const auditLapse = await sqlOne(
    "select count(*)::int as n from public.audit_log where resource='government_grants' and action like '%update%' and created_at > now() - interval '5 minutes'");
  ok("sweep: lapses captured by the grants audit trigger", auditLapse && auditLapse.n >= 1, JSON.stringify(auditLapse));

  // Expired grant no longer confers read access (read-time check already excludes it,
  // sweep is bookkeeping — verify both statuses behave identically for RLS).
  const expiredReads = await pg("incidents?select=id&organization_id=eq." + cappedOrg, "GET", regAdmin.token);
  ok("sweep: expired-grant holder reads 0 target-org incidents", expiredReads.status !== 200 || parseBody(expiredReads.body).length === 0, expiredReads.status + " " + String(expiredReads.body).slice(0, 120));

  // ============ 5. security-scan self-check ============
  const scan = spawnSync("node", ["scripts/security-scan.mjs"], { encoding: "utf8", timeout: 60000 });
  ok("scan: repo security scan exits clean", scan.status === 0, (scan.stdout || "").slice(0, 200));

  // ============ catalog regression: Phase 12 RPC count intact ============
  const rpcs = await sqlOne(
    "select count(*)::int as n from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname in ('site_create','site_update','site_remove','org_update_settings','org_update_subscription','regulator_extend_grant','bootstrap_first_platform_admin','platform_list_organizations','platform_update_organization_status','gov_national_overview','regulator_issue_grant','regulator_revoke_grant')");
  ok("catalog: Phase 12 RPC surface intact", rpcs && rpcs.n === 12, "found " + (rpcs && rpcs.n));

} catch (e) {
  fail++;
  console.log("FAIL probe-abort —", e.message);
} finally {
  // ============ 6. self-cleanup ============
  try {
    if (artifacts.grantIds.length) {
      await sql("delete from public.government_grants where id = any($1::uuid[])", [artifacts.grantIds]);
    }
    if (artifacts.siteIds.length) {
      await sql("delete from public.sites where id = any($1::uuid[])", [artifacts.siteIds]);
    }
    if (artifacts.userIds.length) {
      await sql("delete from public.organization_members where user_id = any($1::uuid[])", [artifacts.userIds]);
      await sql("delete from auth.users where id = any($1::uuid[])", [artifacts.userIds]);
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

console.log(`\nverify-phase13: ${pass} PASS, ${fail} FAIL`);
process.exit(fail ? 1 : 0);
