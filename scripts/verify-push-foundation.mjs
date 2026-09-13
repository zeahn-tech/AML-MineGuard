// One-off: live verification of the push foundation (…113).
// register/deregister are auth.uid-derived; own-row RLS; keys never readable
// cross-user; anonymous denied; upsert refresh is idempotent.
import { readFileSync } from "node:fs";

const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
if (!TOKEN) { console.error("SUPABASE_ACCESS_TOKEN missing"); process.exit(2); }
const REF = JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;
const cfgSrc = readFileSync("config.js", "utf8");
const cfg = eval("(" + cfgSrc.match(/\{[\s\S]*\}/)[0] + ")");
const URL = (cfg.supabaseUrl || "").replace(/\/+$/, "");
const ANON = cfg.supabaseAnonKey || "";

const stamp = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
const PASSWORD = "MgPushPass!2026";
let pass = 0, fail = 0;
const created = { users: [] };

function report(status, label, detail) {
  if (status === "PASS") pass++; else if (status === "FAIL") fail++;
  console.log((status === "PASS" ? "PASS " : status === "FAIL" ? "FAIL " : "INFO ") + label + (detail ? " — " + detail : ""));
}

async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`SQL ${res.status}: ${JSON.stringify(data).slice(0, 300)}`);
  return data;
}
async function sqlOne(query) {
  const rows = await sql(query);
  if (!Array.isArray(rows) || rows.length !== 1) throw new Error(`sqlOne expected 1 row: ${JSON.stringify(rows).slice(0, 200)}`);
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
  if (!Array.isArray(u) || !u.length || !u[0].id) throw new Error(`create user ${email} failed`);
  const s = await rest("/auth/v1/token?grant_type=password", { method: "POST", body: { email, password: PASSWORD } });
  if (s.status !== 200 || !s.data.access_token) throw new Error(`signin ${email}: HTTP ${s.status}`);
  created.users.push(`'${s.data.user.id}'`);
  return { userId: s.data.user.id, email, token: s.data.access_token };
}

async function main() {
  report("INFO", "probe project", REF);

  const alice = await signUp(`mg.push.alice.${stamp}@gmailtest.com`);
  const bob = await signUp(`mg.push.bob.${stamp}@gmailtest.com`);

  // anonymous denied
  let r = await rpc("register_push_subscription", { p_endpoint: "https://push.example/ep-1", p_p256dh: "k1", p_auth: "a1" }, null);
  report(r.status === 401 ? "PASS" : "FAIL", "push: anonymous register denied", `HTTP ${r.status}`);

  // register
  r = await rpc("register_push_subscription",
    { p_endpoint: `https://push.example/ep-${stamp}-a`, p_p256dh: "p256dh-a", p_auth: "auth-a", p_user_agent: "probe-agent" }, alice.token);
  report(r.status === 200 ? "PASS" : "FAIL", "push: register subscription", `HTTP ${r.status}`);

  // upsert refresh (same endpoint) — still one row
  r = await rpc("register_push_subscription",
    { p_endpoint: `https://push.example/ep-${stamp}-a`, p_p256dh: "p256dh-a2", p_auth: "auth-a2" }, alice.token);
  const rows = await sql(`select p256dh, auth, status from public.push_subscriptions where user_id = '${alice.userId}'`);
  report(r.status === 200 && rows.length === 1 && rows[0].p256dh === "p256dh-a2" ? "PASS" : "FAIL",
    "push: re-register same endpoint refreshes keys (single row)", JSON.stringify(rows));

  // forged user_id: the RPC has NO user parameter → PostgREST rejects the
  // unknown argument (404/400) and bob gains nothing — identity is auth.uid only.
  r = await rpc("register_push_subscription",
    { p_endpoint: `https://push.example/ep-${stamp}-b`, p_p256dh: "p", p_auth: "a", p_user_id: bob.userId }, alice.token);
  const bobRows = await sql(`select endpoint_hash from public.push_subscriptions where user_id = '${bob.userId}'`);
  report((r.status === 404 || r.status === 400) && bobRows.length === 0 ? "PASS" : "FAIL",
    "push: forged user_id rejected (no such parameter; auth.uid-derived)", `HTTP ${r.status} bob=${bobRows.length}`);
  // register a second subscription for alice properly
  await rpc("register_push_subscription",
    { p_endpoint: `https://push.example/ep-${stamp}-b`, p_p256dh: "p", p_auth: "a" }, alice.token);

  // RLS: cannot read another user's subscriptions (incl. their keys)
  r = await rest(`/rest/v1/push_subscriptions?select=p256dh,auth`, { token: bob.token });
  report(r.status === 200 && Array.isArray(r.data) && r.data.length === 0 ? "PASS" : "FAIL",
    "push: cross-user subscription read denied (RLS)", `rows=${Array.isArray(r.data) ? r.data.length : "?"}`);

  // direct INSERT denied (RPC-only writes)
  r = await rest("/rest/v1/push_subscriptions", {
    method: "POST", token: bob.token,
    body: [{ user_id: bob.userId, endpoint_hash: "forged", p256dh: "p", auth: "a" }]
  });
  report(r.status === 403 || r.status === 401 ? "PASS" : "FAIL", "push: direct table INSERT denied", `HTTP ${r.status}`);

  // deregister own
  r = await rpc("deregister_push_subscription", { p_endpoint: `https://push.example/ep-${stamp}-a` }, alice.token);
  const afterDel = await sql(`select count(*)::int as n from public.push_subscriptions where user_id = '${alice.userId}'`);
  report((r.status === 200 || r.status === 204) && afterDel[0].n === 1 ? "PASS" : "FAIL",
    "push: deregister own endpoint", `remaining=${afterDel[0].n}`);

  // deregister is scoped to own rows (bob cannot delete alice's)
  r = await rpc("deregister_push_subscription", { p_endpoint: `https://push.example/ep-${stamp}-b` }, bob.token);
  const stillThere = await sql(`select count(*)::int as n from public.push_subscriptions where user_id = '${alice.userId}'`);
  report((r.status === 200 || r.status === 204) && stillThere[0].n === 1 ? "PASS" : "FAIL",
    "push: cross-user deregister is a no-op", `alice rows=${stillThere[0].n}`);

  // cleanup
  await sql(`delete from public.push_subscriptions where user_id in (${created.users.join(",")})`);
  await sql(`delete from auth.identities where user_id in (${created.users.join(",")})`);
  await sql(`delete from auth.users where id in (${created.users.join(",")})`);
  const residue = await sqlOne(
    `select (select count(*)::int from auth.users where email like 'mg.push.%.${stamp}@gmailtest.com') as users,
            (select count(*)::int from public.push_subscriptions where user_id::text not in (select id::text from auth.users)) as orphan_subs`);
  report(residue.users === 0 && residue.orphan_subs === 0 ? "PASS" : "FAIL", "cleanup: probe users removed", JSON.stringify(residue));

  console.log(`\nverify-push-foundation: ${pass} PASS, ${fail} FAIL`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch(err => { console.error("probe error:", err.message); process.exit(1); });
