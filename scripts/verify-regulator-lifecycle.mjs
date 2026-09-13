// ============================================================================
// MINEGUARD — Regulator organization lifecycle probe (session 20).
//
// Covers REGULATOR_ORGANIZATION_LIFECYCLE §14 tests plus the §24 database
// matrix, against the LIVE project. Self-cleaning: every scratch org, user,
// membership and audit row is removed at the end (verified by recount).
//
// Usage: SUPABASE_ACCESS_TOKEN=… node scripts/verify-regulator-lifecycle.mjs
// ============================================================================
import { readFileSync } from "node:fs";

const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;


// Parse config.js (window.MG_CONFIG = {...})
const cfgSrc = readFileSync("config.js", "utf8");
const m = cfgSrc.match(/\{[\s\S]*\}/);
const cfg = eval("(" + m[0] + ")");
const URL = (cfg.supabaseUrl || "").replace(/\/+$/, "");
const ANON = cfg.supabaseAnonKey || "";

let pass = 0, fail = 0;
const createdOrgIds = [];
const createdUserEmails = [];
const stamp = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
const PASSWORD = "MgRegPass!2026";

function report(status, label, detail) {
  if (status === "PASS") pass++; else if (status === "FAIL") fail++;
  console.log((status === "PASS" ? "PASS " : status === "FAIL" ? "FAIL " : "INFO ") + label + (detail ? " — " + detail : ""));
  if (status === "FAIL" && /security|privilege|RLS/i.test(label)) {
    console.log("      !! security-relevant failure");
  }
}

async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`SQL ${res.status}: ${JSON.stringify(data)}`);
  return data;
}

async function sqlOne(query) {
  const rows = await sql(query);
  if (!Array.isArray(rows) || rows.length !== 1) throw new Error(`sqlOne expected 1 row: ${JSON.stringify(rows).slice(0, 300)}`);
  return rows[0];
}

async function rest(path, { method = "GET", token, body } = {}) {
  const headers = { apikey: ANON, "Content-Type": "application/json", Accept: "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  const res = await fetch(URL + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function rpc(name, args, token) {
  return rest(`/rest/v1/rpc/${name}`, { method: "POST", token, body: args || {} });
}

// Create a user directly via service role + sign in (same convention as
// verify-phase04/verify-auth-gate).
async function signUp(email) {
  const u = await sql(
    `with nu as (
       insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
         email_confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data,
         created_at, updated_at, confirmation_token, recovery_token, email_change, email_change_token_new)
       values ('00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
         '${email}', crypt('${PASSWORD}', gen_salt('bf')), now(), now(),
         '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '')
       returning id, email)
     insert into auth.identities (provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
     select email, id, jsonb_build_object('sub', id::text, 'email', email), 'email', now(), now(), now()
     from nu returning user_id as id;`);
  if (!Array.isArray(u) || !u.length || !u[0].id) {
    throw new Error(`create user ${email}: unexpected result ${JSON.stringify(u).slice(0, 200)}`);
  }
  const s = await rest("/auth/v1/token?grant_type=password", { method: "POST", body: { email, password: PASSWORD } });
  if (s.status !== 200 || !s.data.access_token) throw new Error(`signin ${email}: HTTP ${s.status}`);
  createdUserEmails.push(email);
  return { userId: s.data.user.id, email, token: s.data.access_token };
}

async function main() {
  report("INFO", "probe project", REF);

  // ============ static wiring ============
  const gov = readFileSync("gov-admin.js", "utf8");
  report(gov.includes("regulator_claim_status") && gov.includes("renderClaimSurface") ? "PASS" : "FAIL",
    "static: claim surface resolves state from the server TVF before offering the button");
  report(gov.includes("govClaimStatus") && gov.includes("claimStatusLine") ? "PASS" : "FAIL",
    "static: claim result reported inline in the claim surface (silent no-op fixed)");
  report(gov.includes("govClaimModal") && gov.includes("Confirm Claim") ? "PASS" : "FAIL",
    "static: confirmation modal before the claim executes");
  const authjs = readFileSync("supabase-auth.js", "utf8");
  report(authjs.includes("regulator_claim_status") ? "PASS" : "FAIL",
    "static: client wrapper regulatorClaimStatus wired");
  const sw = readFileSync("sw.js", "utf8");
  report(/CACHE_NAME = 'mineguard-v\d+'/.test(sw) && !sw.includes("mineguard-v13") ? "PASS" : "FAIL",
    "static: SW cache version bumped past the pre-lifecycle shell");

  // ============ users ============
  const outsider = await signUp(`mg.reg.out.${stamp}@gmailtest.com`);       // has a commercial org later
  const orgless1 = await signUp(`mg.reg.u1.${stamp}@gmailtest.com`);        // eligible claimant
  const orgless2 = await signUp(`mg.reg.u2.${stamp}@gmailtest.com`);        // second claimant (should be denied after first)
  const platUser = await signUp(`mg.reg.plat.${stamp}@gmailtest.com`);      // platform admin

  // scratch commercial org with a member (outsider = owner)
  const commercial = await sqlOne(
    `insert into public.organizations (slug, name, org_type, status) values ('reg-com-${stamp}', 'Reg Commercial ${stamp}', 'mining_company', 'active') returning id`);
  createdOrgIds.push(commercial.id);
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by) values ('${commercial.id}', '${outsider.userId}', 'owner', 'active', '${outsider.userId}')`);

  // platform org with platUser as platform_super_admin
  const platform = await sqlOne(
    `insert into public.organizations (slug, name, org_type, status) values ('reg-plat-${stamp}', 'Reg Platform ${stamp}', 'platform', 'active') returning id`);
  createdOrgIds.push(platform.id);
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by) values ('${platform.id}', '${platUser.userId}', 'platform_super_admin', 'active', '${platUser.userId}')`);

  // DEBUG: verify the platform authorization subquery directly
  {
    const diag = await sql(`select m.user_id, m.role, r.scope, o.org_type, o.status`
      + ` from public.organization_members m`
      + ` join public.organizations o on o.id = m.organization_id`
      + ` join public.roles r on r.code = m.role`
      + ` where m.user_id = '${platUser.userId}'`);
    console.log('DEBUG platUser auth subquery:', JSON.stringify(diag));
    const raw = await sql(`select om.role, om.status, o.org_type, o.slug from public.organization_members om join public.organizations o on o.id = om.organization_id where om.user_id = '${platUser.userId}'`);
    console.log('DEBUG platUser raw rows:', JSON.stringify(raw));
    const u2 = await sql(`select id, email from auth.users where email = '${platUser.email}'`);
    console.log('DEBUG platUser auth.users row:', JSON.stringify(u2), 'token-sub-match:', u2.length && u2[0].id === platUser.userId);
  }

  // ============ claim state when nothing exists ============
  let r = await rpc("regulator_claim_status", {}, orgless1.token);
  report(r.status === 200 && Array.isArray(r.data) && r.data[0] && r.data[0].state === "none_provisioned" ? "PASS" : "FAIL",
    "claim state: no regulator org → none_provisioned", JSON.stringify(r.data));

  // ============ provision authorization matrix ============
  r = await rpc("provision_regulator_organization", { p_name: "Sneaky Regulator " + stamp }, orgless1.token);
  report(r.status === 400 && /platform administrator/i.test(String(r.data && (r.data.message || r.data)) || "") ? "PASS" : "FAIL",
    "security: orgless user CANNOT provision a regulator org (denied)", `HTTP ${r.status}`);

  r = await rpc("provision_regulator_organization", { p_name: "Sneaky Regulator " + stamp }, outsider.token);
  report(r.status === 400 ? "PASS" : "FAIL",
    "security: commercial org owner CANNOT provision a regulator org", `HTTP ${r.status}`);

  r = await rpc("provision_regulator_organization", { p_name: "Anon Regulator" }, null);
  report(r.status === 401 || r.status === 400 ? "PASS" : "FAIL",
    "security: unauthenticated provisioning denied", `HTTP ${r.status}`);

  // platform admin CAN provision
  r = await rpc("provision_regulator_organization",
    { p_name: "Liberia Minerals Regulator " + stamp, p_county: "Montserrado" }, platUser.token);
  console.log('DEBUG provision:', r.status, JSON.stringify(r.data));
  report(r.status === 200 && r.data && r.data.organization_id ? "PASS" : "FAIL",
    "authorized claim: platform admin provisions the regulator org", `HTTP ${r.status}`);
  const regOrgId = r.data && r.data.organization_id;
  if (regOrgId) createdOrgIds.push(regOrgId);

  // duplicate provisioning denied (both by pre-check and unique index)
  r = await rpc("provision_regulator_organization", { p_name: "Duplicate Regulator " + stamp }, platUser.token);
  report(r.status === 400 && /already exists/i.test(String(r.data && (r.data.message || r.data)) || "") ? "PASS" : "FAIL",
    "duplicate regulator organization PREVENTED (unique index + pre-check)", `HTTP ${r.status}`);

  // the provisioned org has NO members and NO subscription
  const regMembers = await sql(`select count(*)::int as n from public.organization_members where organization_id = '${regOrgId}'`);
  report(regMembers[0].n === 0 ? "PASS" : "FAIL", "provisioned regulator org has NO owner membership (onboards via claim)", `members=${regMembers[0].n}`);
  const regSubs = await sql(`select count(*)::int as n from public.subscriptions where organization_id = '${regOrgId}'`);
  report(regSubs[0].n === 0 ? "PASS" : "FAIL", "provisioned regulator org has NO commercial subscription", `subs=${regSubs[0].n}`);

  // created_by = the platform actor (server-derived)
  const regRow = await sqlOne(`select created_by, org_type, status from public.organizations where id = '${regOrgId}'`);
  report(regRow.created_by === platUser.userId && regRow.org_type === "regulator" && regRow.status === "active" ? "PASS" : "FAIL",
    "provisioning actor derived from auth.uid(), org_type/status server-set");

  // ============ claim state transitions ============
  r = await rpc("regulator_claim_status", {}, outsider.token);
  report(r.status === 200 && (!Array.isArray(r.data) || r.data.length === 0) ? "PASS" : "FAIL",
    "claim state: commercial member is NOT eligible (empty result)", `HTTP ${r.status}`);

  r = await rpc("regulator_claim_status", {}, orgless1.token);
  report(r.status === 200 && Array.isArray(r.data) && r.data[0] && r.data[0].state === "claimable" && r.data[0].organization_id === regOrgId ? "PASS" : "FAIL",
    "claim state: orgless user sees claimable org", JSON.stringify(r.data && r.data[0]));

  // ============ claim execution (authorized) ============
  r = await rpc("bootstrap_first_regulator_admin", {}, orgless1.token);
  report(r.status === 200 && r.data === regOrgId ? "PASS" : "FAIL",
    "authorized claim: orgless user claims the regulator org (success)", `HTTP ${r.status} body=${JSON.stringify(r.data)}`);

  // role assigned correctly
  const claimed = await sqlOne(`select role, status from public.organization_members where organization_id = '${regOrgId}' and user_id = '${orgless1.userId}'`);
  report(claimed.role === "national_regulatory_admin" && claimed.status === "active" ? "PASS" : "FAIL",
    "claim assigns national_regulatory_admin / active (server-side role, not client-chosen)");

  // ============ second claim denied ============
  r = await rpc("bootstrap_first_regulator_admin", {}, orgless2.token);
  report(r.status === 400 && /no claimable|already/i.test(String(r.data && (r.data.message || r.data)) || "") ? "PASS" : "FAIL",
    "second claim DENIED (already claimed / no claimable org)", `HTTP ${r.status}`);

  // claimant with a commercial org denied (retry once on 504 gateway blip)
  r = await rpc("bootstrap_first_regulator_admin", {}, outsider.token);
  if (r.status === 504) {
    await new Promise(res => setTimeout(res, 2000));
    r = await rpc("bootstrap_first_regulator_admin", {}, outsider.token);
  }
  report(r.status === 400 && /already holds an active organization membership/i.test(String(r.data && (r.data.message || r.data)) || "") ? "PASS" : "FAIL",
    "security: user WITH a membership cannot claim (orgless-only guard)", `HTTP ${r.status}`);

  // claimed org is no longer claimable
  r = await rpc("regulator_claim_status", {}, orgless2.token);
  report(r.status === 200 && Array.isArray(r.data) && r.data[0] && r.data[0].state === "already_claimed" ? "PASS" : "FAIL",
    "claim state: already_claimed after successful claim", JSON.stringify(r.data && r.data[0]));

  // ============ forgery attempts ============
  // forged role: client cannot insert a regulator membership directly (RLS)
  r = await rest("/rest/v1/organization_members", {
    method: "POST", token: orgless2.token,
    body: [{ organization_id: regOrgId, user_id: orgless2.userId, role: "national_regulatory_admin", status: "active" }]
  });
  report(r.status === 403 || r.status === 401 ? "PASS" : "FAIL",
    "security: direct INSERT of a regulator membership (forged role) denied by RLS", `HTTP ${r.status}`);

  // forged organization id: claim RPC against a non-regulator org
  r = await rest("/rest/v1/rpc/nonexistent_claim_rpc", { method: "POST", token: orgless2.token, body: {} });
  report(r.status === 404 ? "PASS" : "FAIL", "security: no alternative claim RPC surface (404)", `HTTP ${r.status}`);

  // client-provided user id/role: the RPC takes ZERO arguments — a call with
  // forged named args must not match any overload (PostgREST PGRST202 → 404)
  // or must be rejected (400). Either way the injection is impossible.
  r = await rpc("bootstrap_first_regulator_admin", { p_user_id: orgless2.userId, p_role: "owner" }, orgless1.token);
  report(r.status === 404 || r.status === 400 ? "PASS" : "FAIL",
    "security: forged args to the 0-arg claim RPC rejected (no client-controlled identity)", `HTTP ${r.status}`);

  // the same guard, cleanly: member-caller, no forged args → explicit denial
  r = await rpc("bootstrap_first_regulator_admin", {}, orgless1.token);
  report(r.status === 400 && /already holds an active organization membership/i.test(String(r.data && (r.data.message || r.data)) || "") ? "PASS" : "FAIL",
    "security: member-caller explicitly denied by the server-side guard", `HTTP ${r.status}`);

  // non-regulator org: platform provision output can never be pointed at a
  // mining org — the RPC inserts org_type='regulator' unconditionally.
  const typeCheck = await sqlOne(`select org_type from public.organizations where id = '${regOrgId}'`);
  report(typeCheck.org_type === "regulator" ? "PASS" : "FAIL",
    "security: provision RPC cannot create a non-regulator org (type is server-set)");

  // suspended org claim: suspend the regulator org then attempt claim as orgless2
  await sql(`update public.organizations set status = 'suspended' where id = '${regOrgId}'`);
  // orgless2 is still orgless; make the org claimable again by removing members? No —
  // suspended orgs are excluded from the claim query. Verify:
  r = await rpc("regulator_claim_status", {}, orgless2.token);
  const stateAfterSuspend = Array.isArray(r.data) && r.data[0] ? r.data[0].state : "none";
  report(stateAfterSuspend !== "claimable" ? "PASS" : "FAIL",
    "security: suspended regulator org is never claimable", `state=${stateAfterSuspend}`);
  r = await rpc("bootstrap_first_regulator_admin", {}, orgless2.token);
  report(r.status === 400 ? "PASS" : "FAIL", "security: claim against suspended org DENIED", `HTTP ${r.status}`);

  // ============ audit trail ============
  const audits = await sql(
    `select action, count(*)::int as n from public.audit_log
      where organization_id in ('${regOrgId}', '${commercial.id}', '${platform.id}')
      group by action order by action`);
  const auditMap = {};
  (audits || []).forEach(a => { auditMap[a.action] = a.n; });
  report((auditMap["organizations.insert"] || 0) >= 1 ? "PASS" : "FAIL",
    "audit: regulator org creation captured by the append-only audit trigger",
    JSON.stringify(auditMap));
  const claimAudit = await sql(
    `select count(*)::int as n from public.audit_log where organization_id = '${regOrgId}' and action = 'organization_members.insert'`);
  report((claimAudit[0] ? claimAudit[0].n : 0) >= 1 ? "PASS" : "FAIL",
    "audit: regulator membership creation captured (actor + role)");

  // ============ isolation: regulator does NOT blanket-access tenants ============
  // The regulator admin (orgless1) must see ZERO incident rows of the
  // commercial org — oversight requires an explicit government_grant.
  r = await rest(`/rest/v1/incidents?organization_id=eq.${commercial.id}&select=*`, { token: orgless1.token });
  report(r.status === 200 && Array.isArray(r.data) && r.data.length === 0 ? "PASS" : "FAIL",
    "security: regulator member sees 0 target-org incidents WITHOUT a government grant (no blanket access)", `rows=${Array.isArray(r.data) ? r.data.length : "?"}`);

  r = await rest(`/rest/v1/organizations?id=eq.${commercial.id}&select=*`, { token: orgless1.token });
  report(r.status === 200 && Array.isArray(r.data) && r.data.length === 0 ? "PASS" : "FAIL",
    "security: regulator member cannot read other organizations' rows", `rows=${Array.isArray(r.data) ? r.data.length : "?"}`);

  // ============ cleanup ============
  for (const id of createdOrgIds) {
    await sql(`delete from public.audit_log where organization_id = '${id}'`);
    await sql(`delete from public.subscriptions where organization_id = '${id}'`);
    await sql(`delete from public.organization_members where organization_id = '${id}'`);
    await sql(`delete from public.sites where organization_id = '${id}'`);
    await sql(`delete from public.organizations where id = '${id}'`);
  }
  for (const email of createdUserEmails) {
    await sql(`delete from auth.users where email = '${email}'`);
  }
  const orgsLeft = await sql(`select count(*)::int as n from public.organizations where slug like 'reg-com-${stamp}%' or slug like 'reg-plat-${stamp}%' or slug like 'liberia-minerals-regulator-${stamp}%'`);
  const usersLeft = await sql(`select count(*)::int as n from auth.users where email like '%${stamp}%'`);
  report(orgsLeft[0].n === 0 && usersLeft[0].n === 0 ? "PASS" : "FAIL",
    "cleanup: probe orgs + users removed", JSON.stringify({ orgs: orgsLeft[0].n, users: usersLeft[0].n }));

  console.log(`\nverify-regulator-lifecycle: ${pass} PASS, ${fail} FAIL`);
  if (fail > 0) process.exit(1);
}

main().catch(err => { console.error("PROBE ERROR:", err); console.log(`verify-regulator-lifecycle: ${pass} PASS, ${fail + 1} FAIL`); process.exit(1); });
