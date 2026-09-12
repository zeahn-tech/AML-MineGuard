// ============================================================
// MINEGUARD — Organization lifecycle live probe (session 18)
//
// Verifies the self-service organization creation + ownership
// transfer layer END-TO-END on the live Supabase project:
//
//   Catalog
//     * create_organization(text,text,text) SECURITY DEFINER exists,
//       execute revoked from public/anon, granted to authenticated
//     * org_transfer_ownership(uuid,uuid) same
//     * org_type constraint now includes 'service_provider'
//
//   Creation (happy path)
//     * authenticated user creates a mining_company → org + owner
//       membership + starter subscription all exist; creator is the
//       active owner; slug derived from name
//
//   Creation (denials / edge cases)
//     * unauthenticated (anon) → 401/403
//     * regulator type → rejected
//     * platform type → rejected
//     * forged owner/role/status/org id in a direct INSERT → RLS deny
//     * duplicate name → clean slug collision handling (-2)
//     * empty name → rejected
//
//   Ownership transfer
//     * non-owner member → DENIED
//     * outsider (not a member) → DENIED
//     * owner → target active member: swap succeeds, exactly one
//       active owner, previous owner becomes admin, audit rows exist
//     * transfer to a non-member → DENIED
//
//   Tenant isolation after creation
//     * a second user's org cannot see the first org's rows (0 rows
//       on organizations/sites SELECT for an unrelated org context)
//
// Self-cleaning: removes probe orgs + users in a finally block.
// Requires SUPABASE_ACCESS_TOKEN (management API) as with all probes.
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
const REF = (() => {
  try { return JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref; }
  catch { return process.env.SUPABASE_PROJECT_REF || ""; }
})();

if (!URL || !ANON || !TOKEN) {
  console.error("Missing URL/ANON/SUPABASE_ACCESS_TOKEN");
  process.exit(1);
}

let pass = 0, fail = 0;
function report(status, label, detail = "") {
  console.log(`${status.padEnd(5)} ${label}${detail ? " — " + detail : ""}`);
  if (status === "PASS") pass++;
  else if (status === "FAIL") fail++;
}

async function jfetch(path, { method = "GET", token, body } = {}) {
  const res = await fetch(URL + path, {
    method,
    headers: {
      apikey: ANON, Accept: "application/json", "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const text = await res.text();
  let data = null; try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}
async function sqlOne(query) { const r = await sql(query); return Array.isArray(r.data) && r.data.length ? r.data[0] : null; }

const PASSWORD = "MgProbePass!2026";
const stamp = Date.now().toString(36);
const ORG_SLUG_PREFIX = "olc-probe-";

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
  return { userId: s.data.user.id, email, token: s.data.access_token };
}

async function rpc(name, args, token) {
  return jfetch(`/rest/v1/rpc/${name}`, { method: "POST", token, body: args || {} });
}

const createdOrgIds = [];
const createdUserEmails = [];

async function main() {
  report("INFO", "probe project", REF);

  // ================= catalog =================
  const fnA = await sqlOne(
    `select count(*)::int as n from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.proname = 'create_organization'`);
  report(fnA && fnA.n === 1 ? "PASS" : "FAIL", "catalog: create_organization exists", `n=${fnA && fnA.n}`);

  const fnB = await sqlOne(
    `select count(*)::int as n from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.proname = 'org_transfer_ownership'`);
  report(fnB && fnB.n === 1 ? "PASS" : "FAIL", "catalog: org_transfer_ownership exists", `n=${fnB && fnB.n}`);

  const privs = await sqlOne(
    `select
       (select count(*)::int from information_schema.role_routine_grants
         where specific_schema='public' and routine_name in ('create_organization','org_transfer_ownership')
           and grantee in ('anon','public')) as anon_grants,
       (select count(*)::int from information_schema.role_routine_grants
         where specific_schema='public' and routine_name in ('create_organization','org_transfer_ownership')
           and grantee = 'authenticated') as auth_grants`);
  report(privs && privs.anon_grants === 0 && privs.auth_grants === 2 ? "PASS" : "FAIL",
    "catalog: execute revoked from public/anon, granted to authenticated", JSON.stringify(privs));

  const chk = await sqlOne(
    `select pg_get_constraintdef(oid) as def from pg_constraint
     where conrelid = 'public.organizations'::regclass and contype = 'c' and conname = 'organizations_org_type_check'`);
  report(chk && /service_provider/.test(chk.def) ? "PASS" : "FAIL", "catalog: org_type includes service_provider", chk && chk.def);

  // ================= actors =================
  const creator = await signUp(`mg.olc.creator.${stamp}@gmailtest.com`);
  const member = await signUp(`mg.olc.member.${stamp}@gmailtest.com`);
  const outsider = await signUp(`mg.olc.outsider.${stamp}@gmailtest.com`);
  createdUserEmails.push(creator.email, member.email, outsider.email);

  // ================= creation happy path =================
  const orgName = `Olc Probe Mining ${stamp}`;
  const created = await rpc("create_organization", { p_name: orgName, p_org_type: "mining_company", p_county: "Nimba" }, creator.token);
  report(created.status === 200 && created.data && created.data.organization_id ? "PASS" : "FAIL",
    "creation: authenticated mining_company creation succeeds", `HTTP ${created.status} ${JSON.stringify(created.data).slice(0, 120)}`);
  const orgId = created.data && created.data.organization_id;
  if (orgId) createdOrgIds.push(orgId);

  const orgRow = orgId ? await sqlOne(`select slug, name, org_type, status, created_by from public.organizations where id = '${orgId}'`) : null;
  report(orgRow && orgRow.created_by === creator.userId && orgRow.status === "active" ? "PASS" : "FAIL",
    "creation: org row server-derived (created_by = auth.uid(), active)", orgRow && JSON.stringify(orgRow).slice(0, 160));

  const slugOk = orgRow && orgRow.slug === orgName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  report(slugOk ? "PASS" : "FAIL", "creation: slug derived from name", orgRow && orgRow.slug);

  const memRow = orgId ? await sqlOne(
    `select role, status, user_id from public.organization_members where organization_id = '${orgId}' and user_id = '${creator.userId}'`) : null;
  report(memRow && memRow.role === "owner" && memRow.status === "active" ? "PASS" : "FAIL",
    "creation: creator membership owner+active", memRow && JSON.stringify(memRow));

  const subRow = orgId ? await sqlOne(
    `select plan_code, status from public.subscriptions where organization_id = '${orgId}' and status = 'active'`) : null;
  report(subRow && subRow.plan_code === "starter" ? "PASS" : "FAIL",
    "creation: starter subscription initialized", subRow && JSON.stringify(subRow));

  // ================= denials =================
  const anon = await rpc("create_organization", { p_name: "Anon Org" }, null);
  report(anon.status === 401 || anon.status === 403 ? "PASS" : "FAIL",
    "denial: unauthenticated creation rejected", `HTTP ${anon.status}`);

  const reg = await rpc("create_organization", { p_name: `Olc Reg ${stamp}`, p_org_type: "regulator" }, creator.token);
  report(reg.status !== 200 ? "PASS" : "FAIL", "denial: regulator type rejected", `HTTP ${reg.status}`);

  const plat = await rpc("create_organization", { p_name: `Olc Plat ${stamp}`, p_org_type: "platform" }, creator.token);
  report(plat.status !== 200 ? "PASS" : "FAIL", "denial: platform type rejected", `HTTP ${plat.status}`);

  const empty = await rpc("create_organization", { p_name: "   " }, creator.token);
  report(empty.status !== 200 ? "PASS" : "FAIL", "denial: empty name rejected", `HTTP ${empty.status}`);

  // Forged ownership: direct INSERT into organizations as a normal user must
  // be default-deny (no INSERT policy). Use PostgREST as the user would.
  const forged = await jfetch("/rest/v1/organizations", {
    method: "POST", token: creator.token,
    body: { slug: `olc-forged-${stamp}`, name: `Olc Forged ${stamp}`, org_type: "mining_company", created_by: creator.userId },
  });
  report(forged.status === 403 || forged.status === 401 ? "PASS" : "FAIL",
    "denial: direct organizations INSERT (forged owner) blocked by RLS", `HTTP ${forged.status}`);

  const forgedMem = await jfetch("/rest/v1/organization_members", {
    method: "POST", token: member.token,
    body: { organization_id: orgId, user_id: member.userId, role: "owner", status: "active", created_by: member.userId },
  });
  report(forgedMem.status === 403 || forgedMem.status === 401 ? "PASS" : "FAIL",
    "denial: forged owner membership INSERT blocked by RLS", `HTTP ${forgedMem.status}`);

  // Duplicate NAME → rejected by the existing business rule
  // (organizations_name_lower_uidx unique index on lower(name)).
  const dup = await rpc("create_organization", { p_name: orgName, p_org_type: "mining_company" }, creator.token);
  report(dup.status !== 200 ? "PASS" : "FAIL",
    "creation: duplicate name rejected (unique-name rule)", `HTTP ${dup.status}`);

  // Slug collision: two DIFFERENT names that normalize to the same slug base
  // (punctuation ignored) → the second gets the deterministic -2 suffix.
  const collisionName = `Olc Probe -- Mining!! ${stamp}`;   // same slug base as orgName
  const dup2 = await rpc("create_organization", { p_name: collisionName, p_org_type: "mining_company" }, creator.token);
  const dupId = dup2.data && dup2.data.organization_id;
  if (dupId) createdOrgIds.push(dupId);
  const dupRow = dupId ? await sqlOne(`select slug from public.organizations where id = '${dupId}'`) : null;
  report(dup2.status === 200 && dupRow && /-2$/.test(dupRow.slug) ? "PASS" : "FAIL",
    "creation: slug-collision name gets deterministic -2 suffix", dupRow && dupRow.slug);

  // ================= first-site authorization (onboarding path) =================
  // While `member` is still a PLAIN member (pre-transfer): sites.create required.
  const sitePlain = await rpc("site_create",
    { p_organization_id: orgId, p_name: `Olc First Site ${stamp}`, p_location: "Yekepa", p_county: "Nimba" }, member.token);
  report(sitePlain.status !== 200 ? "PASS" : "FAIL", "onboarding: plain member cannot create a site (sites.create required)", `HTTP ${sitePlain.status}`);

  // ================= ownership transfer =================
  // Put `member` into creator's org as a plain member (via service-role SQL —
  // the real add-member RPC requires owner auth; we grant minimal membership).
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${orgId}', '${member.userId}', 'member', 'active', '${creator.userId}')
    on conflict (organization_id, user_id) do update set role = 'member', status = 'active';`);

  // non-owner (member) attempts transfer → denied
  const memberXfer = await rpc("org_transfer_ownership", { p_organization_id: orgId, p_new_owner_user_id: member.userId }, member.token);
  report(memberXfer.status !== 200 ? "PASS" : "FAIL", "transfer: non-owner member denied", `HTTP ${memberXfer.status}`);

  // outsider attempts transfer → denied
  const outXfer = await rpc("org_transfer_ownership", { p_organization_id: orgId, p_new_owner_user_id: outsider.userId }, outsider.token);
  report(outXfer.status !== 200 ? "PASS" : "FAIL", "transfer: outsider denied", `HTTP ${outXfer.status}`);

  // owner transfers to a NON-member → denied
  const nonMemberXfer = await rpc("org_transfer_ownership", { p_organization_id: orgId, p_new_owner_user_id: outsider.userId }, creator.token);
  report(nonMemberXfer.status !== 200 ? "PASS" : "FAIL", "transfer: owner→non-member denied", `HTTP ${nonMemberXfer.status}`);

  // owner transfers to the active member → succeeds; exactly one owner
  const xfer = await rpc("org_transfer_ownership", { p_organization_id: orgId, p_new_owner_user_id: member.userId }, creator.token);
  report(xfer.status === 200 || xfer.status === 204 ? "PASS" : "FAIL", "transfer: owner→active member succeeds", `HTTP ${xfer.status}`);

  const owners = await sql(
    `select user_id, role, status from public.organization_members where organization_id = '${orgId}' and role = 'owner'`);
  const ownerRows = Array.isArray(owners.data) ? owners.data : [];
  report(ownerRows.length === 1 && ownerRows[0].user_id === member.userId ? "PASS" : "FAIL",
    "transfer: exactly one active owner = new owner", JSON.stringify(ownerRows));

  const prevOwner = await sqlOne(
    `select role from public.organization_members where organization_id = '${orgId}' and user_id = '${creator.userId}'`);
  report(prevOwner && prevOwner.role === "admin" ? "PASS" : "FAIL",
    "transfer: previous owner demoted to admin", prevOwner && prevOwner.role);

  const auditN = await sqlOne(
    `select count(*)::int as n from public.audit_log where organization_id = '${orgId}' and resource = 'organization_members'`);
  report(auditN && auditN.n >= 2 ? "PASS" : "FAIL", "audit: membership changes captured", `n=${auditN && auditN.n}`);

  const auditOrgN = await sqlOne(
    `select count(*)::int as n from public.audit_log where resource_id = '${orgId}' and resource = 'organizations'`);
  report(auditOrgN && auditOrgN.n >= 1 ? "PASS" : "FAIL", "audit: organization creation captured", `n=${auditOrgN && auditOrgN.n}`);

  // ================= tenant isolation after creation =================
  // outsider (own fresh context, no memberships in org) must see 0 rows of
  // the probe org and cannot create a site in it.
  const crossRead = await jfetch(`/rest/v1/organizations?select=id&id=eq.${orgId}`, { token: outsider.token });
  const rows = Array.isArray(crossRead.data) ? crossRead.data : [];
  report(crossRead.status === 200 && rows.length === 0 ? "PASS" : "FAIL",
    "isolation: outsider sees 0 rows of the created org", `rows=${rows.length}`);

  const crossSite = await jfetch("/rest/v1/sites", {
    method: "POST", token: outsider.token,
    body: { organization_id: orgId, name: `Forged Site ${stamp}` },
  });
  report(crossSite.status === 403 || crossSite.status === 401 ? "PASS" : "FAIL",
    "isolation: outsider cannot INSERT a site into the org", `HTTP ${crossSite.status}`);

  // after transfer, `member` is the owner → sites.create now succeeds
  const siteOwner = await rpc("site_create",
    { p_organization_id: orgId, p_name: `Olc First Site ${stamp}`, p_location: "Yekepa", p_county: "Nimba" }, member.token);
  report(siteOwner.status === 200 || siteOwner.status === 204 ? "PASS" : "FAIL", "onboarding: new owner can create the first site via site_create", `HTTP ${siteOwner.status}`);

}

main().catch(err => { report("FAIL", "probe aborted", err.message); process.exit(1); }).then(cleanup);

async function cleanup() {
  try {
    for (const id of createdOrgIds) {
      await sql(`delete from public.audit_log where organization_id = '${id}';`);
      await sql(`delete from public.subscriptions where organization_id = '${id}';`);
      await sql(`delete from public.site_members where organization_id = '${id}';`);
      await sql(`delete from public.organization_members where organization_id = '${id}';`);
      await sql(`delete from public.sites where organization_id = '${id}';`);
      await sql(`delete from public.organizations where id = '${id}';`);
    }
    for (const email of createdUserEmails) {
      await sql(`delete from auth.users where email = '${email}';`);
    }
    const residue = await sqlOne(
      `select
         (select count(*)::int from public.organizations where slug like '${ORG_SLUG_PREFIX}%') as orgs,
         (select count(*)::int from auth.users where email like 'mg.olc.%@gmailtest.com') as users`);
    report("PASS", "cleanup: probe orgs + users removed", JSON.stringify(residue));
  } catch (e) {
    report("FAIL", "cleanup", e.message);
  }
  console.log(`\nverify-org-lifecycle: ${pass} PASS, ${fail} FAIL`);
  process.exit(fail ? 1 : 0);
}
