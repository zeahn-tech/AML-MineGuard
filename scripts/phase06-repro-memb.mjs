// Focused repro: site-only supervisor queries public.organization_members.
// Mirrors the failing check in verify-phase06.mjs and prints status + raw body.
import { readFileSync } from "node:fs";
let cfgUrl = "", cfgAnon = "";
try {
  const cfg = readFileSync("config.js", "utf8");
  cfgUrl = (cfg.match(/supabaseUrl:\s*"([^"]+)"/) || [])[1] || "";
  cfgAnon = (cfg.match(/supabaseAnonKey:\s*"([^"]+)"/) || [])[1] || "";
} catch { /* ignore */ }
const URL = (process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || cfgUrl || "").replace(/\/+$/, "");
const ANON = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || cfgAnon || "";
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;
const PASSWORD = "MgProbePass!2026";
const stamp = Date.now().toString(36);
const slug = `p6-repro-${stamp}`;

async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST", headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const t = await res.text(); let d = null; try { d = t ? JSON.parse(t) : null; } catch { d = t; }
  return { status: res.status, data: d };
}
async function jfetch(path, { method = "GET", token, body, headers = {} } = {}) {
  const res = await fetch(URL + path, {
    method,
    headers: {
      apikey: ANON, Accept: "application/json", "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, text };
}
async function signUp(email) {
  await sql(`with nu as (
      insert into auth.users (instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,last_sign_in_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at,confirmation_token,recovery_token,email_change,email_change_token_new)
      values ('00000000-0000-0000-0000-000000000000', gen_random_uuid(),'authenticated','authenticated','${email}',crypt('${PASSWORD}',gen_salt('bf')),now(),now(),'{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','')
      returning id, email
  ) insert into auth.identities (provider_id,user_id,identity_data,provider,last_sign_in_at,created_at,updated_at)
    select email,id,jsonb_build_object('sub',id::text,'email',email),'email',now(),now(),now() from nu
    returning user_id as id;`);
  const s = await jfetch("/auth/v1/token?grant_type=password", { method: "POST", body: { email, password: PASSWORD } });
  return { id: s.text ? JSON.parse(s.text).user.id : null, access_token: s.text ? JSON.parse(s.text).access_token : null };
}

let orgId = null;
try {
  const admin = await signUp(`mg.p6r.admin.${stamp}@gmailtest.com`);
  const sup = await signUp(`mg.p6r.sup.${stamp}@gmailtest.com`);
  const org = await sql(`insert into public.organizations (slug,name,org_type,status,branding) values ('${slug}','Phase06 Repro Org','mining_company','active','{}'::jsonb) returning id;`);
  orgId = org.data[0].id;
  const site = await sql(`insert into public.sites (organization_id,name) values ('${orgId}','Site A') returning id;`);
  await sql(`insert into public.organization_members (organization_id,user_id,role,status,created_by) values ('${orgId}','${admin.id}','owner','active','${admin.id}');`);
  await sql(`insert into public.site_members (organization_id,site_id,user_id,role,status,created_by) values ('${orgId}','${site.data[0].id}','${sup.id}','supervisor','active','${admin.id}');`);
  console.log("siteSup querying organization_members (no org membership):");
  const r = await jfetch(`/rest/v1/organization_members?organization_id=eq.${orgId}&select=id`, { token: sup.access_token });
  console.log("status:", r.status);
  console.log("body:", JSON.stringify(r.text).slice(0, 500));
  console.log("raw:", r.text.slice(0, 500));
} catch (e) {
  console.error("repro error:", e.message);
} finally {
  if (orgId) {
    await sql(`delete from public.audit_log where organization_id = '${orgId}';`);
    await sql(`delete from public.org_invites where organization_id = '${orgId}';`);
    await sql(`delete from public.workers where organization_id = '${orgId}';`);
    await sql(`delete from public.organizational_units where organization_id = '${orgId}';`);
    await sql(`delete from public.site_members where organization_id = '${orgId}';`);
    await sql(`delete from public.organization_members where organization_id = '${orgId}';`);
    await sql(`delete from public.sites where organization_id = '${orgId}';`);
    await sql(`delete from public.organizations where id = '${orgId}';`);
  }
  await sql(`delete from auth.users where email like 'mg.p6r.%@gmailtest.com';`);
  console.log("cleanup done");
}