// throwaway diag 3 — site_manager activation path
import { readFileSync } from "node:fs";

let cfgUrl = "", cfgAnon = "";
try {
  const cfg = readFileSync("config.js", "utf8");
  cfgUrl = (cfg.match(/supabaseUrl:\s*"([^"]+)"/) || [])[1] || "";
  cfgAnon = (cfg.match(/supabaseAnonKey:\s*"([^"]+)"/) || [])[1] || "";
} catch {}
const URL = cfgUrl.replace(/\/+$/, "");
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;

async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const t = await res.text();
  return { status: res.status, data: t ? JSON.parse(t) : null };
}

async function createUser(email) {
  const r = await sql(`with nu as (
      insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
          email_confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data,
          created_at, updated_at, confirmation_token, recovery_token, email_change, email_change_token_new)
      values ('00000000-0000-0000-0000-000000000000', gen_random_uuid(), 'authenticated', 'authenticated',
          '${email}', crypt('MgProbePass!2026', gen_salt('bf')), now(), now(),
          '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '')
      returning id, email
  ) insert into auth.identities (provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
    select email, id, jsonb_build_object('sub', id::text, 'email', email), 'email', now(), now(), now()
    from nu returning user_id as id;`);
  return r.data && r.data[0] ? r.data[0].id : null;
}

async function login(email) {
  const res = await fetch(`${URL}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: cfgAnon, "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: "MgProbePass!2026" }),
  });
  const d = await res.json().catch(() => null);
  return d && d.access_token ? d.access_token : null;
}

async function rpc(fn, args, token) {
  const res = await fetch(`${URL}/rest/v1/rpc/${fn}`, {
    method: "POST",
    headers: { apikey: cfgAnon, Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  const t = await res.text();
  return `${res.status} ${t.slice(0, 140)}`;
}

const stamp = Date.now().toString(36);
const mk = (n) => `mg.p9f.${n}.${stamp}@gmailtest.com`;
const orgId = (await sql(`insert into public.organizations (slug, name, org_type, status, branding)
  values ('p9f-${stamp}', 'P9 Diag3', 'mining_company', 'active', '{}'::jsonb) returning id;`)).data[0].id;
const siteA = (await sql(`insert into public.sites (organization_id, name, location, county)
  values ('${orgId}', 'Alpha', 'Nimba', 'Nimba') returning id;`)).data[0].id;

const smId = await createUser(mk("smgr"));
await sql(`insert into public.site_members (organization_id, site_id, user_id, role, status, created_by)
  values ('${orgId}', '${siteA}', '${smId}', 'site_manager', 'active', '${smId}');`);
const smTok = await login(mk("smgr"));

console.log("site_role:", await rpc("auth_user_site_effective_role", { p_organization_id: orgId, p_site_id: siteA }, smTok));
console.log("site_perm activate:", await rpc("auth_user_has_site_permission", { p_organization_id: orgId, p_site_id: siteA, p_permission: "emergency.activate" }, smTok));
console.log("can_insert:", await rpc("auth_user_can_insert_emergency_event", { p_organization_id: orgId, p_site_id: siteA }, smTok));

// direct insert attempt with full body
const ins = await fetch(`${URL}/rest/v1/emergency_events`, {
  method: "POST",
  headers: { apikey: cfgAnon, Authorization: "Bearer " + smTok, "Content-Type": "application/json" },
  body: JSON.stringify({ organization_id: orgId, site_id: siteA, category: "fire", severity: "critical", client_id: `p9f-ev-${stamp}` }),
});
console.log("INSERT:", ins.status, (await ins.text()).slice(0, 200));

await sql(`delete from public.audit_log where organization_id = '${orgId}';`);
await sql(`delete from public.organizations where id = '${orgId}';`);
await sql(`delete from auth.users where email like 'mg.p9f.%@gmailtest.com';`);
console.log("cleanup done");
