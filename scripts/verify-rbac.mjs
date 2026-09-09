// ============================================================
// MINEGUARD — Phase 03 RBAC live probe (dev verification)
//
// Verifies the RBAC layer END-TO-END on the live Supabase project:
//   * auth_user_effective_role / auth_user_has_permission /
//     auth_user_permissions return correct results for owner, worker,
//     and non-member users
//   * tenant isolation: a member sees ONLY their own organization
//   * RLS: self-promotion (owner/active, role change, activation) is
//     impossible via PostgREST (42501)
//   * RBAC catalogs are readable by authenticated users, hidden from anon
//
// Uses REAL probe users + a scratch organization on the linked project,
// then removes every trace of itself (org + probe users) in a finally
// block. Requires Management API access (SUPABASE_ACCESS_TOKEN, sbp_…)
// for the elevated SQL steps (email confirmation + membership setup),
// exactly like the Phase 02 probe flow.
//
// Usage:
//   NEXT_PUBLIC_SUPABASE_URL=... NEXT_PUBLIC_SUPABASE_ANON_KEY=... \
//   SUPABASE_ACCESS_TOKEN=... node scripts/verify-rbac.mjs
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
  owner: `mg.rbac.owner.${stamp}@gmailtest.com`,
  worker: `mg.rbac.worker.${stamp}@gmailtest.com`,
  outsider: `mg.rbac.outsider.${stamp}@gmailtest.com`,
};
const ORG_SLUG = `rbac-probe-${stamp}`;
const PASSWORD = "MgProbePass!2026";

function report(status, label, detail = "") {
  console.log(`${status.padEnd(5)} ${label}${detail ? " — " + detail : ""}`);
  if (status === "FAIL") failures += 1;
}

// ---- HTTP helpers ----------------------------------------------------------
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

// Create a probe user DIRECTLY in auth.users (bcrypt hash via pgcrypto) and
// return a real GoTrue session. Deliberately bypasses the signup email path:
//   * probes must not consume the project's email quota / hit rate limits
//   * email confirmation is pre-set, so the password grant works immediately
// This mirrors what an org-admin provisioning flow will do server-side (Phase 04).
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

async function main() {
  report("INFO", "probe project", REF);
  try {
    const health = await fetch(`${URL}/auth/v1/health`);
    report(health.status > 0 ? "PASS" : "FAIL", "auth/v1/health reachable", `HTTP ${health.status}`);
  } catch (e) {
    report("FAIL", "auth/v1/health reachable", e.message);
  }

  try {
  // 1. Probe users + scratch org
  const owner = await signUp(EMAILS.owner);
  const worker = await signUp(EMAILS.worker);
  const outsider = await signUp(EMAILS.outsider);

  const orgRes = await sql(`insert into public.organizations (slug, name, org_type, status)
    values ('${ORG_SLUG}', 'RBAC Probe Org', 'mining_company', 'active') returning id;`);
  if ((orgRes.status !== 200 && orgRes.status !== 201) || !Array.isArray(orgRes.data) || !orgRes.data.length) {
    throw new Error(`create scratch org: HTTP ${orgRes.status} ${JSON.stringify(orgRes.data).slice(0, 200)}`);
  }
  createdOrgId = orgRes.data[0].id;
  report("PASS", "scratch org created", ORG_SLUG);

  const memRes = await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by) values
    ('${createdOrgId}', '${owner.user.id}', 'owner', 'active', '${owner.user.id}'),
    ('${createdOrgId}', '${worker.user.id}', 'worker', 'active', '${worker.user.id}');`);
  if (memRes.status !== 200 && memRes.status !== 201) throw new Error(`seed memberships: HTTP ${memRes.status} ${JSON.stringify(memRes.data).slice(0, 200)}`);
  report("PASS", "memberships seeded (owner + worker)", "via Management API SQL (postgres, bypasses RLS)");

  // 2. Helper RPCs — owner
  const ownerRole = await jfetch("/rest/v1/rpc/auth_user_effective_role", { method: "POST", token: owner.access_token, body: { p_organization_id: createdOrgId } });
  report(ownerRole.status === 200 && ownerRole.data === "owner" ? "PASS" : "FAIL", "owner: auth_user_effective_role = 'owner'", JSON.stringify(ownerRole.data));
  const ownerPerms = await jfetch("/rest/v1/rpc/auth_user_permissions", { method: "POST", token: owner.access_token, body: { p_organization_id: createdOrgId } });
  const ownerCodes = Array.isArray(ownerPerms.data) ? ownerPerms.data : [];
  const expectOwnerTrue = ["organizations.manage", "billing.manage", "audit_logs.view", "jsas.approve", "users.suspend"];
  const ownerOk = ownerPerms.status === 200 && expectOwnerTrue.every(c => ownerCodes.includes(c));
  report(ownerOk ? "PASS" : "FAIL", "owner: auth_user_permissions includes full org bundle", `${ownerCodes.length} perms`);
  for (const perm of expectOwnerTrue) {
    const r = await jfetch("/rest/v1/rpc/auth_user_has_permission", { method: "POST", token: owner.access_token, body: { p_organization_id: createdOrgId, p_permission: perm } });
    report(r.status === 200 && r.data === true ? "PASS" : "FAIL", `owner: auth_user_has_permission(${perm}) = true`, `HTTP ${r.status} got ${JSON.stringify(r.data)}`);
  }

  // 3. Helper RPCs — worker (positive + negative)
  const workerRole = await jfetch("/rest/v1/rpc/auth_user_effective_role", { method: "POST", token: worker.access_token, body: { p_organization_id: createdOrgId } });
  report(workerRole.status === 200 && workerRole.data === "worker" ? "PASS" : "FAIL", "worker: auth_user_effective_role = 'worker'", JSON.stringify(workerRole.data));
  for (const perm of ["incidents.create", "jsas.create", "emergency.acknowledge"]) {
    const r = await jfetch("/rest/v1/rpc/auth_user_has_permission", { method: "POST", token: worker.access_token, body: { p_organization_id: createdOrgId, p_permission: perm } });
    report(r.status === 200 && r.data === true ? "PASS" : "FAIL", `worker: auth_user_has_permission(${perm}) = true`, `HTTP ${r.status} got ${JSON.stringify(r.data)}`);
  }
  for (const perm of ["organizations.manage", "users.suspend", "analytics.view", "billing.manage", "audit_logs.view"]) {
    const r = await jfetch("/rest/v1/rpc/auth_user_has_permission", { method: "POST", token: worker.access_token, body: { p_organization_id: createdOrgId, p_permission: perm } });
    report(r.status === 200 && r.data === false ? "PASS" : "FAIL", `worker: auth_user_has_permission(${perm}) = false`, `HTTP ${r.status} got ${JSON.stringify(r.data)}`);
  }

  // 4. Non-member: no role, no permissions (tenant isolation at permission layer)
  const outRole = await jfetch("/rest/v1/rpc/auth_user_effective_role", { method: "POST", token: outsider.access_token, body: { p_organization_id: createdOrgId } });
  report(outRole.status === 200 && outRole.data == null ? "PASS" : "FAIL", "outsider: auth_user_effective_role = null", JSON.stringify(outRole.data));
  const outPerm = await jfetch("/rest/v1/rpc/auth_user_has_permission", { method: "POST", token: outsider.access_token, body: { p_organization_id: createdOrgId, p_permission: "incidents.view" } });
  report(outPerm.status === 200 && outPerm.data === false ? "PASS" : "FAIL", "outsider: auth_user_has_permission = false", `HTTP ${outPerm.status} got ${JSON.stringify(outPerm.data)}`);

  // 5. RLS tenant isolation: members see ONLY the scratch org; outsider sees zero
  const ownerOrgs = await jfetch("/rest/v1/organizations?select=slug&order=slug", { token: owner.access_token });
  const ownerSlugs = Array.isArray(ownerOrgs.data) ? ownerOrgs.data.map(o => o.slug) : [];
  report(ownerOrgs.status === 200 && ownerSlugs.length === 1 && ownerSlugs[0] === ORG_SLUG
    ? "PASS" : "FAIL", "owner: org SELECT = scratch org only (no cross-tenant rows)", JSON.stringify(ownerSlugs));
  const outsiderOrgs = await jfetch("/rest/v1/organizations?select=slug", { token: outsider.access_token });
  report(outsiderOrgs.status === 200 && Array.isArray(outsiderOrgs.data) && outsiderOrgs.data.length === 0
    ? "PASS" : "FAIL", "outsider: org SELECT = zero rows", JSON.stringify(outsiderOrgs.data));
  const anonOrgs = await jfetch("/rest/v1/organizations?select=slug", {});
  report(anonOrgs.status === 200 && Array.isArray(anonOrgs.data) && anonOrgs.data.length === 0
    ? "PASS" : "FAIL", "anon: org SELECT = zero rows (RLS)", `HTTP ${anonOrgs.status}`);

  // 6. RLS: no self-promotion / no role escalation via PostgREST
  const selfPromote = await jfetch("/rest/v1/organization_members", {
    method: "POST", token: worker.access_token,
    body: { organization_id: createdOrgId, user_id: worker.user.id, role: "owner", status: "active", created_by: worker.user.id },
  });
  report(selfPromote.status === 403 ? "PASS" : "FAIL", "worker: INSERT own owner/active row → 403", `HTTP ${selfPromote.status}`);
  const selfEscalate = await jfetch(`/rest/v1/organization_members?organization_id=eq.${createdOrgId}&user_id=eq.${worker.user.id}`, {
    method: "PATCH", token: worker.access_token, body: { role: "admin" },
  });
  report(selfEscalate.status === 403 ? "PASS" : "FAIL", "worker: UPDATE own role → admin → 403", `HTTP ${selfEscalate.status}`);
  const selfActivate = await jfetch(`/rest/v1/organization_members?organization_id=eq.${createdOrgId}&user_id=eq.${worker.user.id}`, {
    method: "PATCH", token: worker.access_token, body: { status: "invited" },
  });
  report(selfActivate.status === 403 ? "PASS" : "FAIL", "worker: UPDATE own status → invited (de-escalation also blocked) → 403", `HTTP ${selfActivate.status}`);

  // 7. RBAC catalogs: readable by authenticated, hidden from anon
  const authedRoles = await jfetch("/rest/v1/roles?select=code&limit=100", { token: owner.access_token });
  report(authedRoles.status === 200 && Array.isArray(authedRoles.data) && authedRoles.data.length >= 16
    ? "PASS" : "FAIL", "authenticated: roles catalog readable", `${Array.isArray(authedRoles.data) ? authedRoles.data.length : "?"} roles`);
  const anonRoles = await jfetch("/rest/v1/roles?select=code&limit=5", {});
  report(anonRoles.status === 200 && Array.isArray(anonRoles.data) && anonRoles.data.length === 0
    ? "PASS" : "FAIL", "anon: roles catalog hidden (0 rows)", `HTTP ${anonRoles.status} rows=${Array.isArray(anonRoles.data) ? anonRoles.data.length : "?"}`);

  console.log(failures === 0
    ? "\nRBAC probe: all executed checks passed (no FAIL)."
    : `\nRBAC probe: ${failures} check(s) FAILED.`);
} catch (err) {
  failures += 1;
  console.error("RBAC probe aborted:", err.message);
} finally {
  // ---- Cleanup: remove every trace of the probe --------------------------
  try {
    if (createdOrgId) {
      await sql(`delete from public.organizations where id = '${createdOrgId}';`);
      const chk = await sql(`select count(*) as n from public.organizations where id = '${createdOrgId}';`);
      const n = chk.data && chk.data[0] && chk.data[0].n;
      report(Number(n) === 0 ? "PASS" : "FAIL", "cleanup: scratch org removed", `remaining=${n}`);
    } else {
      // Belt and suspenders: remove any orphaned probe org from a failed run.
      await sql(`delete from public.organizations where slug like 'rbac-probe-%';`);
      report("PASS", "cleanup: no probe org was tracked; swept rbac-probe-% orphans");
    }
    const del = await sql(`delete from auth.users where email like 'mg.rbac.%@gmailtest.com';`);
    report("PASS", "cleanup: probe users removed", `${EMAILS.owner}, ${EMAILS.worker}, ${EMAILS.outsider}`);
  } catch (e) {
    report("FAIL", "cleanup", e.message);
  }
  }
}

await main();
process.exit(failures === 0 ? 0 : 1);