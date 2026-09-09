// ============================================================
// MINEGUARD — Phase 04 site hierarchy live probe (dev verification)
//
// Verifies the Phase 04 layer END-TO-END on the live Supabase project:
//   * org-admin member management RPCs (add / re-role / remove; owner
//     protected; non-admins denied)
//   * invite flow (send -> token -> accept by matching email -> join;
//     duplicate/expired/revoked paths; re-invite while pending upserts)
//   * site-scoped permission resolution (max(org role, site role)):
//       - an ORG MEMBER is widened by a site role inside the org
//       - a SITE-ONLY user (no org membership) gets site scope through
//         auth_user_has_site_permission but NEVER org scope
//       - no transitive access to a second site
//   * hierarchy + worker registry RPCs (units, workers) with denial paths
//   * RLS: outsiders and anon see zero rows on the four new tables.
//     Phase 06 note: site-scope SELECT expectations below were updated to the
//     RLS_MATRIX semantics (site-only members read OWN-site sites/units but
//     never other sites/org rows or invite rows; the worker registry is
//     least-privilege — workers.view/users.view required).
//
// Self-cleaning: creates a scratch org + probe users, then removes every
// trace in a finally block. Requires Management API access
// (SUPABASE_ACCESS_TOKEN, sbp_...) exactly like scripts/verify-rbac.mjs.
//
// Usage:
//   NEXT_PUBLIC_SUPABASE_URL=... NEXT_PUBLIC_SUPABASE_ANON_KEY=... \
//   SUPABASE_ACCESS_TOKEN=... node scripts/verify-phase04.mjs
// ============================================================

import { readFileSync } from "node:fs";

// Public config.js fallbacks (URL + anon key are PUBLIC by design; the
// service-role key and access token are NEVER derived from the repo).
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
  admin: `mg.p4.admin.${stamp}@gmailtest.com`,
  worker: `mg.p4.worker.${stamp}@gmailtest.com`,
  siteMgr: `mg.p4.sitemgr.${stamp}@gmailtest.com`,
  siteOnly: `mg.p4.siteonly.${stamp}@gmailtest.com`,
  invitee: `mg.p4.invitee.${stamp}@gmailtest.com`,
  outsider: `mg.p4.outsider.${stamp}@gmailtest.com`,
};
const ORG_SLUG = `p4-probe-${stamp}`;
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

// Phase 04 RPC helper: named args; void RPCs return 204.
async function rpc(name, args, token) {
  return jfetch(`/rest/v1/rpc/${name}`, { method: "POST", token, body: args || {} });
}

async function main() {
  report("INFO", "probe project", REF);
  try {
    const health = await fetch(`${URL}/auth/v1/health`);
    report(health.status > 0 ? "PASS" : "FAIL", "auth/v1/health reachable", `HTTP ${health.status}`);
  } catch (e) {
    report("FAIL", "auth/v1/health reachable", e.message);
  }

  try {
    // ---- fixture: users, scratch org, sites --------------------------------
    const admin = await signUp(EMAILS.admin);
    const worker = await signUp(EMAILS.worker);
    const siteMgr = await signUp(EMAILS.siteMgr);
    const siteOnly = await signUp(EMAILS.siteOnly);
    const invitee = await signUp(EMAILS.invitee);
    const outsider = await signUp(EMAILS.outsider);

    const orgRes = await sql(`insert into public.organizations (slug, name, org_type, status)
      values ('${ORG_SLUG}', 'Phase04 Probe Org', 'mining_company', 'active') returning id;`);
    if ((orgRes.status !== 200 && orgRes.status !== 201) || !Array.isArray(orgRes.data) || !orgRes.data.length) {
      throw new Error(`create scratch org: HTTP ${orgRes.status} ${JSON.stringify(orgRes.data).slice(0, 200)}`);
    }
    createdOrgId = orgRes.data[0].id;
    report("PASS", "scratch org created", ORG_SLUG);

    const siteRes = await sql(`insert into public.sites (organization_id, name, location, county) values
      ('${createdOrgId}', 'Probe Site A', 'Nimba', 'Nimba'),
      ('${createdOrgId}', 'Probe Site B', 'Buchanan', 'Grand Bassa') returning id, name;`);
    if (!Array.isArray(siteRes.data) || siteRes.data.length !== 2) throw new Error("create sites failed");
    const siteA = siteRes.data.find(s => s.name === "Probe Site A").id;
    const siteB = siteRes.data.find(s => s.name === "Probe Site B").id;
    report("PASS", "sites created", "Site A + Site B");

    const memRes = await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by) values
      ('${createdOrgId}', '${admin.user.id}', 'owner', 'active', '${admin.user.id}'),
      ('${createdOrgId}', '${worker.user.id}', 'worker', 'active', '${admin.user.id}'),
      ('${createdOrgId}', '${siteMgr.user.id}', 'member', 'active', '${admin.user.id}');`);
    if (memRes.status !== 200 && memRes.status !== 201) throw new Error(`seed memberships: HTTP ${memRes.status}`);
    report("PASS", "memberships seeded (owner, worker, siteMgr-as-member)");

    // siteMgr gets a site_manager role at Site A; siteOnly gets supervisor at
    // Site A with NO org membership at all.
    const smRes = await sql(`insert into public.site_members (organization_id, site_id, user_id, role, status, created_by) values
      ('${createdOrgId}', '${siteA}', '${siteMgr.user.id}', 'site_manager', 'active', '${admin.user.id}'),
      ('${createdOrgId}', '${siteA}', '${siteOnly.user.id}', 'supervisor', 'active', '${admin.user.id}');`);
    if (smRes.status !== 200 && smRes.status !== 201) throw new Error(`seed site memberships: HTTP ${smRes.status}`);
    report("PASS", "site memberships seeded", "siteMgr(site_manager A), siteOnly(supervisor A, no org row)");

    // ---- 1. Site-scoped permission resolution (max(org role, site role)) ---
    // siteMgr is an ORG MEMBER (member role) widened by site_manager at Site A.
    for (const [perm, expect] of [["sites.update", true], ["organizational_units.update", true], ["users.suspend", false]]) {
      const r = await rpc("auth_user_has_permission", { p_organization_id: createdOrgId, p_permission: perm }, siteMgr.access_token);
      report(r.status === 200 && r.data === expect ? "PASS" : "FAIL",
        `siteMgr(org member + site_manager A): has_permission(${perm}) = ${expect}`, `got ${JSON.stringify(r.data)}`);
    }
    const siteAOk = await rpc("auth_user_has_site_permission", { p_organization_id: createdOrgId, p_site_id: siteA, p_permission: "sites.update" }, siteMgr.access_token);
    report(siteAOk.status === 200 && siteAOk.data === true ? "PASS" : "FAIL", "siteMgr: has_site_permission(A, sites.update) = true", `got ${JSON.stringify(siteAOk.data)}`);
    const siteBOk = await rpc("auth_user_has_site_permission", { p_organization_id: createdOrgId, p_site_id: siteB, p_permission: "sites.update" }, siteMgr.access_token);
    report(siteBOk.status === 200 && siteBOk.data === false ? "PASS" : "FAIL", "siteMgr: has_site_permission(B, sites.update) = false (no transitive site access)", `got ${JSON.stringify(siteBOk.data)}`);

    // siteOnly: supervisor at Site A but NO org membership => site scope only.
    const soOrgPerm = await rpc("auth_user_has_permission", { p_organization_id: createdOrgId, p_permission: "sites.update" }, siteOnly.access_token);
    report(soOrgPerm.status === 200 && soOrgPerm.data === false ? "PASS" : "FAIL", "siteOnly: has_permission(org, sites.update) = false (site role never grants org scope)", `got ${JSON.stringify(soOrgPerm.data)}`);
    const soSiteApprove = await rpc("auth_user_has_site_permission", { p_organization_id: createdOrgId, p_site_id: siteA, p_permission: "jsas.approve" }, siteOnly.access_token);
    report(soSiteApprove.status === 200 && soSiteApprove.data === true ? "PASS" : "FAIL", "siteOnly: has_site_permission(A, jsas.approve) = true (supervisor)", `got ${JSON.stringify(soSiteApprove.data)}`);
    const soSiteB = await rpc("auth_user_has_site_permission", { p_organization_id: createdOrgId, p_site_id: siteB, p_permission: "jsas.approve" }, siteOnly.access_token);
    report(soSiteB.status === 200 && soSiteB.data === false ? "PASS" : "FAIL", "siteOnly: has_site_permission(B, jsas.approve) = false", `got ${JSON.stringify(soSiteB.data)}`);
    const soRoleA = await rpc("auth_user_site_effective_role", { p_organization_id: createdOrgId, p_site_id: siteA }, siteOnly.access_token);
    report(soRoleA.status === 200 && soRoleA.data === "supervisor" ? "PASS" : "FAIL", "siteOnly: site_effective_role(A) = supervisor", `got ${JSON.stringify(soRoleA.data)}`);
    const soRoleB = await rpc("auth_user_site_effective_role", { p_organization_id: createdOrgId, p_site_id: siteB }, siteOnly.access_token);
    report(soRoleB.status === 200 && soRoleB.data == null ? "PASS" : "FAIL", "siteOnly: site_effective_role(B) = null", `got ${JSON.stringify(soRoleB.data)}`);

    // plain worker: no site scope anywhere
    const wkSite = await rpc("auth_user_has_site_permission", { p_organization_id: createdOrgId, p_site_id: siteA, p_permission: "sites.update" }, worker.access_token);
    report(wkSite.status === 200 && wkSite.data === false ? "PASS" : "FAIL", "worker: has_site_permission(A, sites.update) = false", `got ${JSON.stringify(wkSite.data)}`);

    // ---- 2. Org-admin member management (authorization gates) --------------
    const outsiderAdd = await rpc("org_add_member", { p_organization_id: createdOrgId, p_user_id: outsider.user.id, p_role: "worker" }, outsider.access_token);
    report(outsiderAdd.status !== 200 ? "PASS" : "FAIL", "outsider: org_add_member denied", `HTTP ${outsiderAdd.status} ${JSON.stringify(outsiderAdd.data).slice(0, 120)}`);
    const siteOnlyAdd = await rpc("org_add_member", { p_organization_id: createdOrgId, p_user_id: worker.user.id, p_role: "worker" }, siteOnly.access_token);
    report(siteOnlyAdd.status !== 200 ? "PASS" : "FAIL", "siteOnly (no org membership): org_add_member denied", `HTTP ${siteOnlyAdd.status}`);
    const workerInvite = await rpc("org_send_invite", { p_organization_id: createdOrgId, p_email: EMAILS.outsider, p_role: "worker", p_site_id: null }, worker.access_token);
    report(workerInvite.status !== 200 ? "PASS" : "FAIL", "worker: org_send_invite denied (not admin)", `HTTP ${workerInvite.status}`);

    const ownerProtect = await rpc("org_remove_member", { p_organization_id: createdOrgId, p_user_id: admin.user.id }, admin.access_token);
    report(ownerProtect.status !== 200 ? "PASS" : "FAIL", "admin: org_remove_member(owner) denied", `HTTP ${ownerProtect.status} ${JSON.stringify(ownerProtect.data).slice(0, 120)}`);
    const ownerRerole = await rpc("org_update_member_role", { p_organization_id: createdOrgId, p_user_id: admin.user.id, p_role: "admin" }, admin.access_token);
    report(ownerRerole.status !== 200 ? "PASS" : "FAIL", "admin: org_update_member_role(owner) denied", `HTTP ${ownerRerole.status}`);
    const ownerGrant = await rpc("org_add_member", { p_organization_id: createdOrgId, p_user_id: outsider.user.id, p_role: "owner" }, admin.access_token);
    report(ownerGrant.status !== 200 ? "PASS" : "FAIL", "admin: org_add_member(owner) denied (owner already exists)", `HTTP ${ownerGrant.status}`);

    // admin: re-role worker -> supervisor, then back to worker
    const r1 = await rpc("org_update_member_role", { p_organization_id: createdOrgId, p_user_id: worker.user.id, p_role: "supervisor" }, admin.access_token);
    report(r1.status === 204 ? "PASS" : "FAIL", "admin: org_update_member_role(worker -> supervisor) OK", `HTTP ${r1.status}`);
    const r2 = await rpc("org_update_member_role", { p_organization_id: createdOrgId, p_user_id: worker.user.id, p_role: "worker" }, admin.access_token);
    report(r2.status === 204 ? "PASS" : "FAIL", "admin: org_update_member_role(worker) OK", `HTTP ${r2.status}`);

    // admin: remove siteMgr's org membership, verify site memberships withdrawn
    const r3 = await rpc("org_remove_member", { p_organization_id: createdOrgId, p_user_id: siteMgr.user.id }, admin.access_token);
    report(r3.status === 204 ? "PASS" : "FAIL", "admin: org_remove_member(siteMgr) OK", `HTTP ${r3.status}`);
    const smAfter = await jfetch(`/rest/v1/site_members?organization_id=eq.${createdOrgId}&user_id=eq.${siteMgr.user.id}&select=status`, { token: admin.access_token });
    const smStatuses = Array.isArray(smAfter.data) ? smAfter.data.map(x => x.status) : [];
    report(smStatuses.length === 1 && smStatuses[0] === "removed" ? "PASS" : "FAIL", "org_remove_member also withdraws site memberships", JSON.stringify(smStatuses));
    const r4 = await rpc("org_add_member", { p_organization_id: createdOrgId, p_user_id: siteMgr.user.id, p_role: "member" }, admin.access_token);
    report(r4.status === 204 ? "PASS" : "FAIL", "admin: re-add removed member OK (upsert reactivates)", `HTTP ${r4.status}`);

    // org_list_members visibility (emails)
    const list = await rpc("org_list_members", { p_organization_id: createdOrgId }, admin.access_token);
    const emails = Array.isArray(list.data) ? list.data.map(m => m.email) : [];
    report(list.status === 200 && emails.includes(EMAILS.worker) ? "PASS" : "FAIL", "admin: org_list_members includes member emails", `${Array.isArray(list.data) ? list.data.length : "?"} rows`);
    const outsiderList = await rpc("org_list_members", { p_organization_id: createdOrgId }, outsider.access_token);
    report(outsiderList.status !== 200 ? "PASS" : "FAIL", "outsider: org_list_members denied", `HTTP ${outsiderList.status}`);

    // ---- 3. Invite flow -----------------------------------------------------
    const inv = await rpc("org_send_invite", { p_organization_id: createdOrgId, p_email: EMAILS.invitee, p_role: "safety_officer", p_site_id: siteA }, admin.access_token);
    const token = typeof inv.data === "string" && inv.data.length > 10 ? inv.data : null;
    report(inv.status === 200 && token ? "PASS" : "FAIL", "admin: org_send_invite returns token", token ? "token ok" : JSON.stringify(inv.data).slice(0, 120));

    // re-invite while still pending must UPSERT (new token), not error
    const inv2 = await rpc("org_send_invite", { p_organization_id: createdOrgId, p_email: EMAILS.invitee, p_role: "safety_officer", p_site_id: siteA }, admin.access_token);
    const token2 = typeof inv2.data === "string" && inv2.data.length > 10 ? inv2.data : null;
    report(inv2.status === 200 && token2 && token2 !== token ? "PASS" : "FAIL", "re-invite while pending upserts with a fresh token", token2 && token2 !== token ? "new token" : JSON.stringify(inv2.data).slice(0, 120));

    // wrong-user accept must fail (email match)
    const wrongAccept = await rpc("org_accept_invite", { p_token: token2 }, outsider.access_token);
    report(wrongAccept.status !== 200 ? "PASS" : "FAIL", "outsider: org_accept_invite denied (email mismatch)", `HTTP ${wrongAccept.status}`);
    // correct user accepts -> membership + site membership created
    const accept = await rpc("org_accept_invite", { p_token: token2 }, invitee.access_token);
    report(accept.status === 204 ? "PASS" : "FAIL", "invitee: org_accept_invite OK", `HTTP ${accept.status}`);
    const invMember = await rpc("auth_user_effective_role", { p_organization_id: createdOrgId }, invitee.access_token);
    report(invMember.status === 200 && invMember.data === "safety_officer" ? "PASS" : "FAIL", "invitee: effective_role = safety_officer after accept", `got ${JSON.stringify(invMember.data)}`);
    const invSite = await rpc("auth_user_site_effective_role", { p_organization_id: createdOrgId, p_site_id: siteA }, invitee.access_token);
    report(invSite.status === 200 && invSite.data === "safety_officer" ? "PASS" : "FAIL", "invitee: site_effective_role(A) = safety_officer (site invite)", `got ${JSON.stringify(invSite.data)}`);
    const accept2 = await rpc("org_accept_invite", { p_token: token2 }, invitee.access_token);
    report(accept2.status !== 200 ? "PASS" : "FAIL", "invitee: second accept denied (no longer pending)", `HTTP ${accept2.status}`);
    const dupInvite = await rpc("org_send_invite", { p_organization_id: createdOrgId, p_email: EMAILS.invitee, p_role: "worker", p_site_id: null }, admin.access_token);
    report(dupInvite.status !== 200 ? "PASS" : "FAIL", "admin: invite for existing member denied", `HTTP ${dupInvite.status}`);

    // revoke flow
    const inv3 = await rpc("org_send_invite", { p_organization_id: createdOrgId, p_email: EMAILS.outsider, p_role: "worker", p_site_id: null }, admin.access_token);
    const invId = await sql(`select id from public.org_invites where organization_id = '${createdOrgId}' and email = '${EMAILS.outsider}' and status = 'pending' limit 1;`);
    const inviteRowId = invId.data && invId.data[0] && invId.data[0].id;
    const rev = await rpc("org_revoke_invite", { p_organization_id: createdOrgId, p_invite_id: inviteRowId }, admin.access_token);
    report(rev.status === 204 ? "PASS" : "FAIL", "admin: org_revoke_invite OK", `HTTP ${rev.status}`);
    const revokedAccept = await rpc("org_accept_invite", { p_token: inv3.data }, outsider.access_token);
    report(revokedAccept.status !== 200 ? "PASS" : "FAIL", "accepted revoked invite denied", `HTTP ${revokedAccept.status}`);

    // ---- 4. Hierarchy (units) + worker registry ----------------------------
    const dept = await rpc("org_create_unit", { p_organization_id: createdOrgId, p_site_id: siteA, p_parent_id: null, p_unit_type: "department", p_name: "Mining Operations", p_code: "MIN" }, admin.access_token);
    report(dept.status === 200 && typeof dept.data === "string" ? "PASS" : "FAIL", "admin: org_create_unit(department) OK", JSON.stringify(dept.data).slice(0, 80));
    const deptId = typeof dept.data === "string" ? dept.data : null;
    const team = await rpc("org_create_unit", { p_organization_id: createdOrgId, p_site_id: siteA, p_parent_id: deptId, p_unit_type: "team", p_name: "Pit 3 Crew", p_code: null }, admin.access_token);
    report(team.status === 200 && typeof team.data === "string" ? "PASS" : "FAIL", "admin: org_create_unit(team under dept) OK", JSON.stringify(team.data).slice(0, 80));
    const wZone = await rpc("org_create_unit", { p_organization_id: createdOrgId, p_site_id: siteA, p_parent_id: deptId, p_unit_type: "work_zone", p_name: "Bench 12", p_code: null }, admin.access_token);
    report(wZone.status === 200 ? "PASS" : "FAIL", "admin: org_create_unit(work_zone) OK", `HTTP ${wZone.status}`);
    const crossSite = await rpc("org_create_unit", { p_organization_id: createdOrgId, p_site_id: siteB, p_parent_id: deptId, p_unit_type: "team", p_name: "Wrong Parent", p_code: null }, admin.access_token);
    report(crossSite.status !== 200 ? "PASS" : "FAIL", "unit with parent from another site rejected (trigger)", `HTTP ${crossSite.status} ${JSON.stringify(crossSite.data).slice(0, 120)}`);
    const workerUnit = await rpc("org_create_unit", { p_organization_id: createdOrgId, p_site_id: siteA, p_parent_id: null, p_unit_type: "department", p_name: "Nope", p_code: null }, worker.access_token);
    report(workerUnit.status !== 200 ? "PASS" : "FAIL", "worker: org_create_unit denied", `HTTP ${workerUnit.status}`);
    // siteOnly has no organizational_units.create/update (supervisor) -> denied
    const siteOnlyUnit = await rpc("org_create_unit", { p_organization_id: createdOrgId, p_site_id: siteA, p_parent_id: null, p_unit_type: "department", p_name: "Nope2", p_code: null }, siteOnly.access_token);
    report(siteOnlyUnit.status !== 200 ? "PASS" : "FAIL", "siteOnly(supervisor): org_create_unit denied", `HTTP ${siteOnlyUnit.status}`);

    const workerRow = await rpc("worker_add", { p_organization_id: createdOrgId, p_site_id: siteA, p_department_id: deptId, p_team_id: null, p_user_id: worker.user.id, p_employee_id: "W-1001", p_full_name: "Probe Worker One", p_classification: "employee", p_contact_phone: "+231000000000" }, admin.access_token);
    report(workerRow.status === 200 && typeof workerRow.data === "string" ? "PASS" : "FAIL", "admin: worker_add OK", JSON.stringify(workerRow.data).slice(0, 80));
    const workerId = typeof workerRow.data === "string" ? workerRow.data : null;
    const wUpd = await rpc("worker_update", { p_worker_id: workerId, p_site_id: null, p_department_id: null, p_team_id: null, p_employee_id: null, p_full_name: "Probe Worker One Updated", p_classification: "contractor", p_contact_phone: null, p_status: null }, admin.access_token);
    report(wUpd.status === 204 ? "PASS" : "FAIL", "admin: worker_update OK", `HTTP ${wUpd.status}`);
    const workerDenied = await rpc("worker_add", { p_organization_id: createdOrgId, p_site_id: siteA, p_department_id: null, p_team_id: null, p_user_id: null, p_employee_id: "W-9999", p_full_name: "Nope", p_classification: "employee", p_contact_phone: null }, worker.access_token);
    report(workerDenied.status !== 200 ? "PASS" : "FAIL", "worker: worker_add denied (needs workers.manage)", `HTTP ${workerDenied.status}`);

    // ---- 5. RLS visibility --------------------------------------------------
    const outUnits = await jfetch(`/rest/v1/organizational_units?organization_id=eq.${createdOrgId}&select=id`, { token: outsider.access_token });
    report(outUnits.status === 200 && Array.isArray(outUnits.data) && outUnits.data.length === 0 ? "PASS" : "FAIL", "outsider: organizational_units SELECT = 0 rows", `rows=${Array.isArray(outUnits.data) ? outUnits.data.length : "?"}`);
    const outWorkers = await jfetch(`/rest/v1/workers?organization_id=eq.${createdOrgId}&select=id`, { token: outsider.access_token });
    report(outWorkers.status === 200 && Array.isArray(outWorkers.data) && outWorkers.data.length === 0 ? "PASS" : "FAIL", "outsider: workers SELECT = 0 rows", `rows=${Array.isArray(outWorkers.data) ? outWorkers.data.length : "?"}`);
    const outInvites = await jfetch(`/rest/v1/org_invites?organization_id=eq.${createdOrgId}&select=id`, { token: outsider.access_token });
    report(outInvites.status === 200 && Array.isArray(outInvites.data) && outInvites.data.length === 0 ? "PASS" : "FAIL", "outsider: org_invites SELECT = 0 rows", `rows=${Array.isArray(outInvites.data) ? outInvites.data.length : "?"}`);
    const anonUnits = await jfetch(`/rest/v1/organizational_units?organization_id=eq.${createdOrgId}&select=id`, {});
    report(anonUnits.status === 200 && Array.isArray(anonUnits.data) && anonUnits.data.length === 0 ? "PASS" : "FAIL", "anon: organizational_units SELECT = 0 rows (RLS)", `rows=${Array.isArray(anonUnits.data) ? anonUnits.data.length : "?"}`);
    // siteOnly can read their OWN site_members row (policy user_id = auth.uid())
    const soOwn = await jfetch(`/rest/v1/site_members?user_id=eq.${siteOnly.user.id}&select=site_id,role`, { token: siteOnly.access_token });
    report(soOwn.status === 200 && Array.isArray(soOwn.data) && soOwn.data.length === 1 ? "PASS" : "FAIL", "siteOnly: reads own site_members row", `rows=${Array.isArray(soOwn.data) ? soOwn.data.length : "?"}`);
    // Phase 06 site-scope matrix (supersedes the Phase 04 org-scope-only read):
    // siteOnly (site-only supervisor at Site A) now reads hierarchy rows of
    // THEIR OWN site only — never Site B rows, never org/membership/invite
    // rows, and never the worker roster (supervisor has no workers.view).
    const soUnits = await jfetch(`/rest/v1/organizational_units?organization_id=eq.${createdOrgId}&select=id,site_id`, { token: siteOnly.access_token });
    const soUnitsAllA = Array.isArray(soUnits.data) && soUnits.data.length >= 3 && soUnits.data.every((u) => u.site_id === siteA);
    report(soUnits.status === 200 && soUnitsAllA ? "PASS" : "FAIL", "siteOnly: reads organizational_units of own site A (Phase 06 site scope)", `rows=${Array.isArray(soUnits.data) ? soUnits.data.length : "?"} allAtSiteA=${soUnitsAllA}`);
    const soUnitsB = await jfetch(`/rest/v1/organizational_units?organization_id=eq.${createdOrgId}&site_id=eq.${siteB}&select=id`, { token: siteOnly.access_token });
    report(soUnitsB.status === 200 && Array.isArray(soUnitsB.data) && soUnitsB.data.length === 0 ? "PASS" : "FAIL", "siteOnly: NO units of site B (no transitive site access)", `rows=${Array.isArray(soUnitsB.data) ? soUnitsB.data.length : "?"}`);
    const soSites = await jfetch(`/rest/v1/sites?organization_id=eq.${createdOrgId}&select=id,name`, { token: siteOnly.access_token });
    const soSitesOwn = Array.isArray(soSites.data) && soSites.data.length === 1 && soSites.data[0].id === siteA;
    report(soSites.status === 200 && soSitesOwn ? "PASS" : "FAIL", "siteOnly: reads own site row only (site A)", `rows=${Array.isArray(soSites.data) ? soSites.data.length : "?"}`);
    const soWorkers = await jfetch(`/rest/v1/workers?organization_id=eq.${createdOrgId}&select=id`, { token: siteOnly.access_token });
    report(soWorkers.status === 200 && Array.isArray(soWorkers.data) && soWorkers.data.length === 0 ? "PASS" : "FAIL", "siteOnly(supervisor): workers registry SELECT = 0 (no workers.view)", `rows=${Array.isArray(soWorkers.data) ? soWorkers.data.length : "?"}`);
    const soInvites = await jfetch(`/rest/v1/org_invites?organization_id=eq.${createdOrgId}&select=id`, { token: siteOnly.access_token });
    report(soInvites.status === 200 && Array.isArray(soInvites.data) && soInvites.data.length === 0 ? "PASS" : "FAIL", "siteOnly: org_invites SELECT = 0 rows (tokens are org-members-only)", `rows=${Array.isArray(soInvites.data) ? soInvites.data.length : "?"}`);
    // worker (org member) CAN read the hierarchy
    const wkUnits = await jfetch(`/rest/v1/organizational_units?organization_id=eq.${createdOrgId}&select=id&limit=10`, { token: worker.access_token });
    report(wkUnits.status === 200 && Array.isArray(wkUnits.data) && wkUnits.data.length >= 3 ? "PASS" : "FAIL", "worker: reads org hierarchy (3 units)", `rows=${Array.isArray(wkUnits.data) ? wkUnits.data.length : "?"}`);
    // Phase 06 least privilege (RLS_MATRIX §1.1 "WRK: –"): a plain worker has
    // no workers.view/users.view, so the worker registry is NOT readable.
    const wkWorkers = await jfetch(`/rest/v1/workers?organization_id=eq.${createdOrgId}&select=id`, { token: worker.access_token });
    report(wkWorkers.status === 200 && Array.isArray(wkWorkers.data) && wkWorkers.data.length === 0 ? "PASS" : "FAIL", "worker: workers registry SELECT denied (least privilege, Phase 06)", `rows=${Array.isArray(wkWorkers.data) ? wkWorkers.data.length : "?"}`);
    // siteMgr (org member 'member' widened by site_manager@A) holds workers.view → reads the registry
    const smWorkers = await jfetch(`/rest/v1/workers?organization_id=eq.${createdOrgId}&select=id`, { token: siteMgr.access_token });
    report(smWorkers.status === 200 && Array.isArray(smWorkers.data) && smWorkers.data.length >= 1 ? "PASS" : "FAIL", "siteMgr: reads worker registry (workers.view via site_manager@A)", `rows=${Array.isArray(smWorkers.data) ? smWorkers.data.length : "?"}`);

    // soft-delete the worker via RPC (registry management path)
    const wDel = await rpc("worker_remove", { p_worker_id: workerId }, admin.access_token);
    report(wDel.status === 204 ? "PASS" : "FAIL", "admin: worker_remove OK (soft delete)", `HTTP ${wDel.status}`);

    console.log(failures === 0
      ? "\nPhase 04 probe: all executed checks passed (no FAIL)."
      : `\nPhase 04 probe: ${failures} check(s) FAILED.`);
  } catch (err) {
    failures += 1;
    console.error("Phase 04 probe aborted:", err.message);
  } finally {
    // ---- Cleanup: remove every trace of the probe --------------------------
    try {
      if (createdOrgId) {
        await sql(`delete from public.organizations where id = '${createdOrgId}';`);
        const chk = await sql(`select count(*) as n from public.organizations where id = '${createdOrgId}';`);
        const n = chk.data && chk.data[0] && chk.data[0].n;
        report(Number(n) === 0 ? "PASS" : "FAIL", "cleanup: scratch org removed", `remaining=${n}`);
      } else {
        await sql(`delete from public.organizations where slug like 'p4-probe-%';`);
        report("PASS", "cleanup: no probe org tracked; swept p4-probe-% orphans");
      }
      await sql(`delete from auth.users where email like 'mg.p4.%@gmailtest.com';`);
      report("PASS", "cleanup: probe users removed", "6 probe accounts");
    } catch (e) {
      report("FAIL", "cleanup", e.message);
    }
  }
}

await main();
process.exit(failures === 0 ? 0 : 1);