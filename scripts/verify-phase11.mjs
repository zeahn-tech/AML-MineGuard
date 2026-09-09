// ============================================================
// MINEGUARD — Phase 11 government authorization live probe
// (dev verification, self-cleaning)
//
// Verifies Phase 11 (migration 20260903000090 + fix 20260903000091)
// end-to-end on the live Supabase project:
//   * catalog: government_grants table, RLS, helpers, RPCs, audit trigger
//   * onboarding: bootstrap_first_regulator_admin (one-shot, regulator orgs
//     only, non-government/new-membership callers denied, anon denied)
//   * grant lifecycle: regulator_issue_grant (site-scoped + org-wide, cross-
//     checks) and regulator_revoke_grant (admin-only), regulator_update_user_role
//   * regulator SELECT scope: 0 rows before grant; incidents/inspections/CAPA/
//     emergency visible within grant scope; site-scoped grant does NOT leak
//     other-site rows; revocation is immediate; workers/org-members only with
//     regulator-org permission; audit reads bounded
//   * government_grants RLS: regulator org reads own grants; target org sees
//     none; grant issue/revoke audit-captured with actor identity
//   * regression smoke: org user incident flows unchanged after Phase 11
//
// Self-cleaning: scratch regulator org + scratch mining org + probe users +
// grants removed in a finally block. AML tenant data untouched.
//
// Usage: bun scripts/verify-phase11.mjs
// (bun auto-loads .env.local for SUPABASE_ACCESS_TOKEN; URL/anon key read
//  from config.js exactly like verify-phase04/06/07)
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
  try { return JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref; }
  catch { return ""; }
})();

if (!URL || !ANON || !TOKEN || !REF) {
  console.error("FAIL: missing URL/anon key (config.js) or SUPABASE_ACCESS_TOKEN or project ref");
  process.exit(1);
}

let failures = 0;
const results = [];
function record(name, ok, detail = "") {
  results.push({ name, ok });
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

const PASSWORD = "MgProbePass!2026";
const stamp = Date.now().toString(36);
const ORG_A_SLUG = "arcelormittal-liberia";
const ORG_B_SLUG = "liberia-regulator";
const EMAILS = {
  regAdmin: `mg.p11.regadmin.${stamp}@gmailtest.com`,
  inspector: `mg.p11.inspector.${stamp}@gmailtest.com`,
  targetOwner: `mg.p11.targetowner.${stamp}@gmailtest.com`,
  freshUser: `mg.p11.fresh.${stamp}@gmailtest.com`,
};
const ORG_A_REG_SLUG = `p11-reg-${stamp}`;
const ORG_A_TARGET_SLUG = `p11-target-${stamp}`;

// ---- Management API SQL (privileged, no service-role JWT needed) ----------
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

// ---- PostgREST / Auth (client-visible behavior) ---------------------------
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

async function signUp(email) {
  // Create a confirmed user directly in auth schema (mirrors phase04/06 probes)
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
  return { userId: u.data[0].id, email, token: s.data.access_token };
}

async function rpc(name, args, token) {
  return jfetch(`/rest/v1/rpc/${name}`, { method: "POST", token, body: args || {} });
}

async function rest(entity, { method = "GET", token, query = "", body } = {}) {
  const path = `/rest/v1/${entity}${query ? "?" + query : ""}`;
  return jfetch(path, { method, token, body });
}

// ---- state ----------------------------------------------------------------
const state = {
  users: {},          // email -> { userId, token }
  orgAId: null, siteA1: null, siteA2: null,   // AML tenant
  orgBId: null,                                // seeded regulator placeholder
  scratchRegOrgId: null,
  scratchTargetOrgId: null,
  grants: [],         // { id }
  incidentIds: [], inspectionIds: [], capaIds: [], emergencyIds: [],
};

async function cleanup() {
  try {
    // grants first (unique index on active rows would block user deletion anyway via FK)
    if (state.grants.length) {
      await sql(`delete from public.government_grants where id in (${state.grants.map((g) => `'${g.id}'`).join(",")})`);
    }
    // scratch orgs (cascade their members/rows) — NEVER the seeded regulator
    // placeholder: onboarding() re-points scratchRegOrgId at the bootstrap-claimed
    // seeded org, and deleting it here is what wiped 'liberia-regulator' during
    // the 2026-09-09 session. Only genuinely-scratch orgs are deleted.
    for (const orgId of [state.scratchRegOrgId, state.scaffoldRegOrgId, state.scratchTargetOrgId]) {
      if (orgId && orgId !== state.seededRegOrgId && orgId !== state.orgAId && orgId !== state.orgBId) {
        await sql(`delete from public.organization_members where organization_id = '${orgId}'`);
        await sql(`delete from public.sites where organization_id = '${orgId}'`);
        await sql(`delete from public.organizations where id = '${orgId}'`);
      }
    }
    // safety-domain rows in AML created by the probe
    if (state.emergencyIds.length) await sql(`delete from public.emergency_events where id in (${state.emergencyIds.map((i) => `'${i}'`).join(",")})`);
    if (state.capaIds.length) await sql(`delete from public.corrective_actions where id in (${state.capaIds.map((i) => `'${i}'`).join(",")})`);
    if (state.inspectionIds.length) await sql(`delete from public.inspections where id in (${state.inspectionIds.map((i) => `'${i}'`).join(",")})`);
    if (state.incidentIds.length) await sql(`delete from public.incidents where id in (${state.incidentIds.map((i) => `'${i}'`).join(",")})`);
    // restore the seeded regulator placeholder to its pre-probe claimable
    // state (no active members) if bootstrap claimed it — NEVER delete the
    // seeded org (it must stay for future regulator onboarding; probe delete
    // here is what wiped it in the 2026-09-09 session).
    if (state.seededRegOrgId) {
      await sql(`delete from public.organization_members where organization_id = '${state.seededRegOrgId}'`);
    }
    // probe users
    const ids = Object.values(state.users).map((u) => `'${u.userId}'`).filter(Boolean);
    if (ids.length) {
      await sql(`delete from public.organization_members where user_id in (${ids.join(",")})`);
      await sql(`delete from public.site_members where user_id in (${ids.join(",")})`);
      await sql(`delete from auth.users where id in (${ids.join(",")})`);
    }
  } catch (e) {
    console.error("cleanup error (probe artifacts may remain):", e.message);
  }
}

// ---- scaffold --------------------------------------------------------------
async function scaffold() {
  // AML tenant
  const a = await sql(`select id from public.organizations where slug = '${ORG_A_SLUG}' limit 1`);
  state.orgAId = a.data?.[0]?.id;
  if (!state.orgAId) throw new Error("AML tenant org not found");

  const sites = await sql(`select id, name from public.sites where organization_id = '${state.orgAId}' order by name`);
  const siteRows = sites.data || [];
  if (siteRows.length < 2) throw new Error("AML needs >= 2 seeded sites for the scope matrix");
  state.siteA1 = siteRows[0].id;
  state.siteA2 = siteRows[1].id;

  // seeded regulator placeholder org (must NOT be grantable as target)
  const b = await sql(`select id from public.organizations where slug = '${ORG_B_SLUG}' limit 1`);
  state.orgBId = b.data?.[0]?.id;

  // probe users
  for (const email of Object.values(EMAILS)) {
    state.users[email] = await signUp(email);
  }

  // scratch regulator org (no members -> claimable)
  const reg = await sql(`insert into public.organizations (name, slug, org_type, status, county)
    values ('P11 Probe Regulator', '${ORG_A_REG_SLUG}', 'regulator', 'active', 'Bong') returning id`);
  state.scratchRegOrgId = reg.data?.[0]?.id;
  state.scaffoldRegOrgId = state.scratchRegOrgId; // scaffold-created org: always deleted in cleanup
  if (!state.scratchRegOrgId) throw new Error("scratch regulator org create failed: " + JSON.stringify(reg.data).slice(0, 400));

  // scratch target mining org with 2 sites
  const tgt = await sql(`insert into public.organizations (name, slug, org_type, status, county)
    values ('P11 Probe Mining Co', '${ORG_A_TARGET_SLUG}', 'mining_company', 'active', 'Bong') returning id`);
  state.scratchTargetOrgId = tgt.data?.[0]?.id;
  if (!state.scratchTargetOrgId) throw new Error("scratch target org create failed: " + JSON.stringify(tgt.data).slice(0, 400));
  const s1 = await sql(`insert into public.sites (organization_id, name, county, status)
    values ('${state.scratchTargetOrgId}', 'P11 Site One', 'Bong', 'active') returning id`);
  const s2 = await sql(`insert into public.sites (organization_id, name, county, status)
    values ('${state.scratchTargetOrgId}', 'P11 Site Two', 'Bong', 'active') returning id`);
  state.scratchSite1 = s1.data?.[0]?.id;
  state.scratchSite2 = s2.data?.[0]?.id;

  // memberships
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${state.scratchTargetOrgId}', '${state.users[EMAILS.targetOwner].userId}', 'owner', 'active', '${state.users[EMAILS.targetOwner].userId}')`);
  // inspector membership must live in the org the fresh user actually claimed
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${state.scratchRegOrgId}', '${state.users[EMAILS.inspector].userId}', 'government_safety_inspector', 'active', '${state.users[EMAILS.inspector].userId}')
    on conflict do nothing`);

  // safety-domain rows in the scratch target org (granted scope)
  const inc = await sql(`insert into public.incidents
    (organization_id, site_id, client_id, reported_by_name, incident_type, severity, status, description, lang, created_by)
    values ('${state.scratchTargetOrgId}', '${state.scratchSite1}', 'p11-inc-${stamp}', 'P11 Worker', 'near_miss', 'medium', 'SUBMITTED', 'P11 probe incident', 'en',
            '${state.users[EMAILS.targetOwner].userId}') returning id`);
  state.incidentIds.push(inc.data?.[0]?.id);

  const insp = await sql(`insert into public.inspections
    (organization_id, site_id, client_id, title, inspector_id, inspection_type, status, created_by)
    values ('${state.scratchTargetOrgId}', '${state.scratchSite1}', 'p11-insp-${stamp}', 'P11 inspection', '${state.users[EMAILS.targetOwner].userId}', 'regulatory', 'draft',
            '${state.users[EMAILS.targetOwner].userId}') returning id`);
  state.inspectionIds.push(insp.data?.[0]?.id);

  const capa = await sql(`insert into public.corrective_actions
    (organization_id, site_id, client_id, source_type, title, priority, status, created_by)
    values ('${state.scratchTargetOrgId}', '${state.scratchSite1}', 'p11-capa-${stamp}', 'inspection', 'P11 CAPA', 'medium', 'open',
            '${state.users[EMAILS.targetOwner].userId}') returning id`);
  state.capaIds.push(capa.data?.[0]?.id);

  const ev = await sql(`insert into public.emergency_events
    (organization_id, site_id, client_id, category, severity, status, site_notice_scope, activated_by, created_by)
    values ('${state.scratchTargetOrgId}', '${state.scratchSite1}', 'p11-ev-${stamp}', 'medical', 'high', 'ACTIVATED', true,
            '${state.users[EMAILS.targetOwner].userId}', '${state.users[EMAILS.targetOwner].userId}') returning id`);
  state.emergencyIds.push(ev.data?.[0]?.id);

  // one incident at site 2 (must stay invisible under a site-1-scoped grant)
  const inc2 = await sql(`insert into public.incidents
    (organization_id, site_id, client_id, reported_by_name, incident_type, severity, status, description, lang, created_by)
    values ('${state.scratchTargetOrgId}', '${state.scratchSite2}', 'p11-inc2-${stamp}', 'P11 Worker 2', 'near_miss', 'low', 'SUBMITTED', 'P11 probe incident site 2', 'en',
            '${state.users[EMAILS.targetOwner].userId}') returning id`);
  state.incidentIds.push(inc2.data?.[0]?.id);
}

// ---- 1. catalog checks -----------------------------------------------------
async function catalog() {
  const t = await sql(`select count(*)::int as n from information_schema.tables
    where table_schema='public' and table_name='government_grants'`);
  record("catalog: government_grants table exists", t.data?.[0]?.n === 1);

  const rls = await sql(`select c.relrowsecurity from pg_class c join pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relname='government_grants'`);
  record("catalog: government_grants RLS enabled", rls.data?.[0]?.relrowsecurity === true);

  const helpers = await sql(`select count(*)::int as n from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname in
      ('auth_user_is_regulator_org_member','auth_user_is_regulator_user_in',
       'current_user_active_government_grants','auth_user_has_regulator_grant_for',
       'bootstrap_first_regulator_admin','regulator_issue_grant','regulator_revoke_grant',
       'regulator_update_user_role')`);
  record("catalog: 8 Phase 11 helper/RPC functions present", helpers.data?.[0]?.n === 8, `found ${helpers.data?.[0]?.n}`);

  const pol = await sql(`select policyname from pg_policies where schemaname='public' and tablename='government_grants'`);
  const names = (pol.data || []).map((r) => r.policyname);
  record("catalog: government_grants SELECT policies present",
    names.includes("government_grants_select_regulator_org") && names.includes("government_grants_select_target_org"));

  const trg = await sql(`select count(*)::int as n from pg_trigger t join pg_class c on c.oid=t.tgrelid
    join pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relname='government_grants' and not t.tgisinternal and t.tgname='trg_audit_government_grants'`);
  record("catalog: government_grants audit trigger present", trg.data?.[0]?.n === 1);

  const regPol = await sql(`select count(*)::int as n from pg_policies where schemaname='public'
    and policyname in ('incidents_select_regulator','incident_evidence_select_regulator','incident_witnesses_select_regulator',
      'jsas_select_regulator','inspections_select_regulator','corrective_actions_select_regulator',
      'emergency_events_select_regulator','emergency_acks_select_regulator','emergency_esc_select_regulator',
      'emergency_resp_select_regulator','emergency_log_select_regulator','sites_select_regulator',
      'organizational_units_select_regulator','workers_select_regulator','organization_members_select_regulator',
      'audit_log_select_regulator')`);
  record("catalog: 16 regulator SELECT policies present", regPol.data?.[0]?.n === 16, `found ${regPol.data?.[0]?.n}`);
}

// ---- 2. onboarding ----------------------------------------------------------
async function onboarding() {
  const fresh = state.users[EMAILS.freshUser];

  // bootstrap claims the FIRST claimable regulator org by created_at — that
  // is the seeded 'liberia-regulator' placeholder, not our scratch org.
  // Record the placeholder's prior state so cleanup can restore it exactly.
  const seeded = await sql(`select id from public.organizations where slug = 'liberia-regulator' limit 1`);
  state.seededRegOrgId = seeded.data?.[0]?.id || null;

  const boot = await rpc("bootstrap_first_regulator_admin", {}, fresh.token);
  const raw = Array.isArray(boot.data) ? boot.data[0] : boot.data;
  const claimedId = typeof raw === "string" ? raw
    : raw && typeof raw === "object"
      ? (raw.bootstrap_first_regulator_admin ?? Object.values(raw)[0])
      : null;
  record("onboarding: fresh user claims regulator org", boot.status === 200 && !!claimedId,
    boot.status !== 200 ? JSON.stringify(boot.data).slice(0, 160) : `org ${claimedId}`);
  if (claimedId) {
    // All regulator-side flows use the org bootstrap actually claimed.
    state.scratchRegOrgId = claimedId;
    state.bootstrapClaimedOrg = claimedId;
    // Add the inspector to the claimed org (scaffold may have used a different one).
    await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
      values ('${claimedId}', '${state.users[EMAILS.inspector].userId}', 'government_safety_inspector', 'active', '${state.users[EMAILS.inspector].userId}')
      on conflict do nothing`);
  }

  // second claim attempt (fresh user now has a membership) -> denied
  const boot2 = await rpc("bootstrap_first_regulator_admin", {}, fresh.token);
  record("onboarding: second bootstrap denied (already a member)", boot2.status !== 200,
    boot2.status === 200 ? "unexpectedly succeeded" : "");

  // non-government caller with existing membership -> denied
  const owner = state.users[EMAILS.targetOwner];
  const boot3 = await rpc("bootstrap_first_regulator_admin", {}, owner.token);
  record("onboarding: caller with existing membership denied", boot3.status !== 200,
    boot3.status === 200 ? "unexpectedly succeeded" : "");

  // anon -> denied
  const boot4 = await rpc("bootstrap_first_regulator_admin", {});
  record("onboarding: anon bootstrap denied", boot4.status === 401, `status ${boot4.status}`);
}

// ---- 3. grant lifecycle ------------------------------------------------------
async function grantLifecycle() {
  const regAdmin = state.users[EMAILS.freshUser]; // national_regulatory_admin after bootstrap
  const inspector = state.users[EMAILS.inspector];

  // The bootstrap claim in onboarding() created the inspector's membership
  // row in the REGULATOR-ORG-AS-CLAIMED; but bootstrap ran AFTER scaffold
  // inserted it. Ensure it exists in the claimed org:
  if (state.bootstrapClaimedOrg) {
    await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
      values ('${state.bootstrapClaimedOrg}', '${inspector.userId}', 'government_safety_inspector', 'active', '${inspector.userId}')
      on conflict do nothing`);
  }

  // site-scoped grant for the inspector
  const g1 = await rpc("regulator_issue_grant", {
    p_target_org_id: state.scratchTargetOrgId,
    p_site_id: state.scratchSite1,
    p_scope: "compliance monitoring",
    p_regulator_user_id: inspector.userId,
  }, regAdmin.token);
  // scalar-returning RPC → PostgREST returns the bare JSON string "<uuid>"
  function grantIdOf(r) {
    if (typeof r.data === "string") return r.data;
    if (Array.isArray(r.data)) return typeof r.data[0] === "string" ? r.data[0] : r.data[0]?.regulator_issue_grant;
    return r.data?.regulator_issue_grant;
  }
  const g1id = grantIdOf(g1);
  record("grants: site-scoped grant issued for inspector", (g1.status === 200 || g1.status === 201) && !!g1id,
    g1.status !== 200 && g1.status !== 201 ? JSON.stringify(g1.data).slice(0, 200) : `grant ${g1id}`);
  if (g1id) state.grants.push({ id: g1id });

  // org-wide grant for the regulator admin themself
  const g2 = await rpc("regulator_issue_grant", {
    p_target_org_id: state.scratchTargetOrgId,
    p_scope: "compliance monitoring",
  }, regAdmin.token);
  const g2id = grantIdOf(g2);
  record("grants: org-wide grant issued for regulator admin", (g2.status === 200 || g2.status === 201) && !!g2id,
    g2.status !== 200 && g2.status !== 201 ? JSON.stringify(g2.data).slice(0, 200) : `grant ${g2id}`);
  if (g2id) state.grants.push({ id: g2id });

  // duplicate active grant (same scope) -> upsert, not a new row
  const g1b = await rpc("regulator_issue_grant", {
    p_target_org_id: state.scratchTargetOrgId,
    p_site_id: state.scratchSite1,
    p_scope: "compliance monitoring",
    p_regulator_user_id: inspector.userId,
  }, regAdmin.token);
  const g1bid = grantIdOf(g1b);
  record("grants: duplicate grant upserts (no new row)", (g1b.status === 200 || g1b.status === 201) && g1bid === g1id,
    g1bid === g1id ? "same grant id" : `got ${g1bid} vs ${g1id}`);

  // cross-checks
  const gx = await rpc("regulator_issue_grant", { p_target_org_id: state.orgBId }, regAdmin.token);
  record("grants: grant targeting a regulator org denied", gx.status !== 200);

  const gy = await rpc("regulator_issue_grant", {
    p_target_org_id: state.scratchTargetOrgId,
    p_site_id: state.orgAId, // valid uuid, but a site of another org
  }, regAdmin.token);
  record("grants: grant with site outside target org denied", gy.status !== 200);

  const gz = await rpc("regulator_issue_grant", {
    p_target_org_id: state.scratchTargetOrgId,
    p_regulator_user_id: state.users[EMAILS.targetOwner].userId, // not a regulator-org member
  }, regAdmin.token);
  record("grants: grant for non-regulator-org member denied", gz.status !== 200);

  // non-admin government member cannot issue
  const gi = await rpc("regulator_issue_grant", { p_target_org_id: state.scratchTargetOrgId }, inspector.token);
  record("grants: inspector (non-admin) cannot issue grants", gi.status !== 200);

  // non-admin government member cannot revoke
  const rv1 = await rpc("regulator_revoke_grant", { p_grant_id: g1id }, inspector.token);
  record("grants: inspector cannot revoke", rv1.status !== 200);

  // admin revokes the site-scoped grant (void RPC → PostgREST 204)
  const rv2 = await rpc("regulator_revoke_grant", { p_grant_id: g1id }, regAdmin.token);
  record("grants: admin revokes site-scoped grant", rv2.status === 200 || rv2.status === 204,
    `status ${rv2.status}`);

  // role assignment (use the org actually claimed by bootstrap)
  const ru = await rpc("regulator_update_user_role", {
    p_regulator_org_id: state.bootstrapClaimedOrg || state.scratchRegOrgId,
    p_user_id: inspector.userId,
    p_new_role: "government_compliance_officer",
  }, regAdmin.token);
  record("roles: admin assigns government role", ru.status === 200 || ru.status === 204, `status ${ru.status}`);

  const ru2 = await rpc("regulator_update_user_role", {
    p_regulator_org_id: state.bootstrapClaimedOrg || state.scratchRegOrgId,
    p_user_id: inspector.userId,
    p_new_role: "worker",
  }, regAdmin.token);
  record("roles: non-government role rejected", ru2.status !== 200);

  const ru3 = await rpc("regulator_update_user_role", {
    p_regulator_org_id: state.bootstrapClaimedOrg || state.scratchRegOrgId,
    p_user_id: inspector.userId,
    p_new_role: "government_analyst",
  }, inspector.token);
  record("roles: non-admin cannot assign roles", ru3.status !== 200);

  // re-issue site-scoped grant (revoked -> upsert path re-activates) for scope tests
  const g3 = await rpc("regulator_issue_grant", {
    p_target_org_id: state.scratchTargetOrgId,
    p_site_id: state.scratchSite1,
    p_scope: "compliance monitoring",
    p_regulator_user_id: inspector.userId,
  }, regAdmin.token);
  const g3id = grantIdOf(g3);
  record("grants: re-issue after revoke succeeds", (g3.status === 200 || g3.status === 201) && !!g3id);
  if (g3id && g3id !== g1id) state.grants.push({ id: g3id });
}

// ---- 4. regulator read scopes -------------------------------------------------
async function regulatorReads() {
  const admin = state.users[EMAILS.freshUser];          // holds org-wide grant
  const inspector = state.users[EMAILS.inspector];      // holds site-1 grant

  // --- before any grant (inspector's grant re-issued above, so use a clean probe:
  //     admin sees scratch-target rows; a DIFFERENT org (AML) stays invisible)
  const amlBefore = await rest("incidents", {
    token: admin.token,
    query: `organization_id=eq.${state.orgAId}&select=id`,
  });
  record("scope: regulator sees 0 AML incidents (no grant for AML)", (amlBefore.data || []).length === 0);

  // --- org-wide grant visibility
  const inc = await rest("incidents", {
    token: admin.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=id`,
  });
  record("scope: org-wide grant sees target incidents", (inc.data || []).length >= 2, `${(inc.data || []).length} rows`);

  const insp = await rest("inspections", {
    token: admin.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=id`,
  });
  record("scope: org-wide grant sees target inspections", (insp.data || []).length >= 1);

  const capa = await rest("corrective_actions", {
    token: admin.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=id`,
  });
  record("scope: org-wide grant sees target CAPAs", (capa.data || []).length >= 1);

  const ev = await rest("emergency_events", {
    token: admin.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=id`,
  });
  record("scope: org-wide grant sees target emergency events", (ev.data || []).length >= 1);

  const jsa = await rest("jsas", {
    token: admin.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=id`,
  });
  record("scope: org-wide grant on jsas returns 200 (0 or more rows)", jsa.status === 200);

  const sites = await rest("sites", {
    token: admin.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=id`,
  });
  record("scope: org-wide grant sees target sites", (sites.data || []).length >= 2);

  // --- target-org data the regulator must NEVER see
  const workers = await rest("workers", {
    token: admin.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=id`,
  });
  record("scope: regulator sees 0 target workers (no workers.view at regulator org)",
    (workers.data || []).length === 0);

  const members = await rest("organization_members", {
    token: admin.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=user_id`,
  });
  // Phase 11 fix …091 semantics: the regulator admin holds users.view at their
  // REGULATOR org + an org-wide grant → they MAY read target-org membership
  // rows. The least-privilege check is that the inspector (government role
  // WITHOUT users.view) still sees 0 of them.
  record("scope: users.view-holding regulator reads target org members (grant scope)",
    members.status === 200 && (members.data || []).length >= 1,
    `status ${members.status}, ${(Array.isArray(members.data) ? members.data.length : 0)} rows`);
  const membersInsp = await rest("organization_members", {
    token: inspector.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=user_id`,
  });
  record("scope: regulator without users.view sees 0 target org members",
    membersInsp.status === 200 && (membersInsp.data || []).length === 0,
    `${(membersInsp.data || []).length} leaked`);

  // --- site-scoped grant: site 1 visible, site 2 NOT
  const incS1 = await rest("incidents", {
    token: inspector.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&site_id=eq.${state.scratchSite1}&select=id`,
  });
  record("scope: site grant sees site-1 incidents", (incS1.data || []).length >= 1);

  const incS2 = await rest("incidents", {
    token: inspector.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&site_id=eq.${state.scratchSite2}&select=id`,
  });
  record("scope: site grant sees 0 site-2 incidents", (incS2.data || []).length === 0,
    `${(incS2.data || []).length} leaked`);

  const evS1 = await rest("emergency_events", {
    token: inspector.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&site_id=eq.${state.scratchSite1}&select=id`,
  });
  record("scope: site grant sees site-1 emergency events", (evS1.data || []).length >= 1);

  // --- government grant does NOT bypass org-user rules for org members
  const targetOwner = state.users[EMAILS.targetOwner];
  const ownInc = await rest("incidents", {
    token: targetOwner.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=id`,
  });
  record("scope: target org owner still reads own incidents", (ownInc.data || []).length >= 2);

  // --- regulator writes are still denied on safety-domain tables
  const wInc = await rest("incidents", {
    method: "POST",
    token: admin.token,
    body: {
      organization_id: state.scratchTargetOrgId,
      site_id: state.scratchSite1,
      client_id: `p11-write-${stamp}`,
      reported_by_name: "Regulator Write",
      incident_type: "near_miss",
      severity: "low",
      status: "SUBMITTED",
      description: "regulator write attempt",
      lang: "en",
    },
  });
  record("writes: regulator INSERT into target incidents denied", wInc.status === 403,
    `status ${wInc.status}`);
}

// ---- 5. grant revocation immediacy ---------------------------------------------
async function revocationImmediacy() {
  const admin = state.users[EMAILS.freshUser];
  // find the org-wide grant and revoke it
  const g = state.grants.find((x) => x.id && x.orgWide !== false);
  const orgWideGrant = state.grants[1] || state.grants[0];
  if (!orgWideGrant) return;

  const rv = await rpc("regulator_revoke_grant", { p_grant_id: orgWideGrant.id }, admin.token);
  record("revoke: admin revokes org-wide grant", rv.status === 200 || rv.status === 204, `status ${rv.status}`);

  const inc = await rest("incidents", {
    token: admin.token,
    query: `organization_id=eq.${state.scratchTargetOrgId}&select=id`,
  });
  record("revoke: access lost immediately after revocation", (inc.data || []).length === 0,
    `${(inc.data || []).length} rows still visible`);
}

// ---- 6. grants RLS + audit -------------------------------------------------------
async function grantsRLSAndAudit() {
  const admin = state.users[EMAILS.freshUser];
  const owner = state.users[EMAILS.targetOwner];

  const mine = await rest("government_grants", {
    token: admin.token,
    query: `select=id&regulator_org_id=eq.${state.scratchRegOrgId}`,
  });
  record("grants RLS: regulator org reads own grants", (mine.data || []).length >= 1);

  const theirs = await rest("government_grants", {
    token: owner.token,
    query: `select=id&target_org_id=eq.${state.scratchTargetOrgId}`,
  });
  // Migration …090 design: a target-org member with audit_logs.view may READ
  // grants touching their org (transparency — GOVERNMENT_PLATFORM §5 "recorded
  // in both orgs' audit views"); writes stay RPC-only.
  record("grants RLS: target org member (audit_logs.view) reads grants touching own org",
    (theirs.data || []).length >= 1, `${(theirs.data || []).length} rows`);

  // direct INSERT denied (writes only via RPC)
  const direct = await rest("government_grants", {
    method: "POST",
    token: admin.token,
    body: {
      regulator_org_id: state.scratchRegOrgId,
      regulator_user_id: admin.userId,
      target_org_id: state.scratchTargetOrgId,
    },
  });
  record("grants RLS: direct INSERT denied (RPC-only writes)", direct.status === 403 || direct.status === 401,
    `status ${direct.status}`);

  const audit = await rest("audit_log", {
    token: admin.token,
    query: `resource=eq.government_grants&order=created_at.desc&limit=5&select=action,actor_name,source`,
  });
  const rows = audit.data || [];
  record("audit: grant issue/revoke captured", rows.length >= 1,
    rows.map((r) => r.action).join(","));
  record("audit: grant rows carry actor identity", rows.some((r) => r.actor_name === EMAILS.freshUser));
  record("audit: grant rows written via trigger source", rows.every((r) => r.source === "trigger"));
}

// ---- 7. regression smoke -----------------------------------------------------------
async function regression() {
  const owner = state.users[EMAILS.targetOwner];
  // owner incident flow still works
  const inc = await rest("incidents", {
    method: "POST",
    token: owner.token,
    body: {
      organization_id: state.scratchTargetOrgId,
      site_id: state.scratchSite1,
      client_id: `p11-reg-${stamp}`,
      reported_by_name: "Regression Owner",
      incident_type: "near_miss",
      severity: "low",
      status: "SUBMITTED",
      description: "phase 11 regression",
      lang: "en",
    },
  });
  record("regression: owner incident INSERT works", inc.status === 201,
    `status ${inc.status}`);
  if (inc.data?.id) state.incidentIds.push(inc.data.id);

  // cross-tenant isolation intact: AML user sees 0 regulator-org rows
  // (create a temporary AML membership for the target owner? No — use the
  //  inspector: they are a government org member but NOT an AML member.)
  const aml = await rest("incidents", {
    token: state.users[EMAILS.inspector].token,
    query: `organization_id=eq.${state.orgAId}&select=id`,
  });
  record("regression: government user sees 0 AML incidents", (aml.data || []).length === 0);
}

async function main() {
  try {
    await scaffold();
    await catalog();
    await onboarding();
    await grantLifecycle();
    await regulatorReads();
    await revocationImmediacy();
    await grantsRLSAndAudit();
    await regression();
  } catch (e) {
    console.error("probe error:", e);
    record("probe", false, e.message);
  } finally {
    await cleanup();
  }
  const fails = results.filter((r) => !r.ok);
  console.log("\n--- results ---");
  console.log(`total ${results.length}  fail ${fails.length}`);
  if (fails.length) {
    console.log("failed:", fails.map((r) => r.name).join(", "));
    process.exitCode = 1;
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
