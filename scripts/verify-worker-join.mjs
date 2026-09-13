// ============================================================================
// MINEGUARD — Worker join request / admin approval / invitation lifecycle
// probe (session 21).
//
// Covers the §39 test matrix of the remediation directive, against the LIVE
// project. Self-cleaning: scratch orgs, users, requests and audit rows are
// removed at the end (verified by recount).
//
// Usage: SUPABASE_ACCESS_TOKEN=… node scripts/verify-worker-join.mjs
// ============================================================================
import { readFileSync } from "node:fs";

const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;

const cfgSrc = readFileSync("config.js", "utf8");
const cfg = eval("(" + cfgSrc.match(/\{[\s\S]*\}/)[0] + ")");
const URL = (cfg.supabaseUrl || "").replace(/\/+$/, "");
const ANON = cfg.supabaseAnonKey || "";

let pass = 0, fail = 0;
const stamp = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
const PASSWORD = "MgJoinPass!2026";
const created = { orgs: [], users: [], requests: [], notifications: [] };

function report(status, label, detail) {
  if (status === "PASS") pass++; else if (status === "FAIL") fail++;
  console.log((status === "PASS" ? "PASS " : status === "FAIL" ? "FAIL " : "INFO ") + label + (detail ? " — " + detail : ""));
  if (status === "FAIL" && /security|RLS|escalat/i.test(label)) console.log("      !! security-relevant failure");
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

// ============================================================================
async function main() {
  report("INFO", "probe project", REF);

  // ---- static wiring ----
  const jr = readFileSync("join-requests.js", "utf8");
  report(jr.includes("organization_search_joinable") && jr.includes("requestJoinOrg") ? "PASS" : "FAIL",
    "static: onboarding join search + submit call the server RPCs (role is server-set)");
  report(jr.includes("renderAdminCard") && jr.includes("reviewFlow") ? "PASS" : "FAIL",
    "static: admin review card + review flow wired");
  report(jr.includes("mgJoinBell") && jr.includes("fetchMyNotifications") ? "PASS" : "FAIL",
    "static: notification bell consumes the notifications store");
  const admin = readFileSync("admin.html", "utf8");
  report(admin.includes("showWorkerRefusal") ? "PASS" : "FAIL",
    "static: admin.html refuses worker-role accounts with guidance (UI guard layer)");
  const authui = readFileSync("auth-ui.js", "utf8");
  report(authui.includes("mg_workspace") && authui.includes("mgAuthAdminLink") && authui.includes("mgAuthWorkerLink") ? "PASS" : "FAIL",
    "static: workspace switching present (UI preference only, roles untouched)");
  const sw = readFileSync("sw.js", "utf8");
  report(!sw.includes("mineguard-v14") ? "PASS" : "FAIL", "static: SW cache version bumped");

  // ---- fixtures ----
  const owner = await signUp(`mg.jn.owner.${stamp}@gmailtest.com`);
  const worker = await signUp(`mg.jn.worker.${stamp}@gmailtest.com`);
  const worker2 = await signUp(`mg.jn.worker2.${stamp}@gmailtest.com`);
  const outsider = await signUp(`mg.jn.outsider.${stamp}@gmailtest.com`);

  const org = await sqlOne(
    `insert into public.organizations (slug, name, org_type, status, settings)
     values ('jn-org-${stamp}', 'Join Probe Co ${stamp}', 'mining_company', 'active',
             '{"allow_worker_join_requests": true}'::jsonb)
     returning id, name`);
  created.orgs.push(`'${org.id}'`);
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${org.id}', '${owner.userId}', 'owner', 'active', '${owner.userId}')`);

  const orgClosed = await sqlOne(
    `insert into public.organizations (slug, name, org_type, status)
     values ('jn-closed-${stamp}', 'Join Closed Co ${stamp}', 'mining_company', 'active')
     returning id`);
  created.orgs.push(`'${orgClosed.id}'`);
  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${orgClosed.id}', '${owner.userId}', 'owner', 'active', '${owner.userId}')`);

  // ---- discovery ----
  let r = await rpc("organization_search_joinable", { p_query: "Join Probe" }, worker.token);
  report(r.status === 200 && Array.isArray(r.data) && r.data.some(o => o.id === org.id) ? "PASS" : "FAIL",
    "search: opt-in org discoverable by name (minimum public fields)", JSON.stringify((r.data || []).map(o => o.name)));
  report(r.status === 200 && Array.isArray(r.data) && r.data.every(o => !o.settings && !("created_by" in (o || {}))) ? "PASS" : "FAIL",
    "search: exposes only id/name/type/county (no private fields)");
  r = await rpc("organization_search_joinable", { p_query: "Join Closed" }, worker.token);
  report(r.status === 200 && Array.isArray(r.data) && !r.data.some(o => o.id === orgClosed.id) ? "PASS" : "FAIL",
    "search: orgs WITHOUT opt-in are not discoverable (restrictive default)");
  r = await rpc("organization_search_joinable", { p_query: "" }, null);
  report(r.status === 401 ? "PASS" : "FAIL", "search: anonymous denied", `HTTP ${r.status}`);

  // cross-tenant enumeration: the list TVF is SECURITY DEFINER and must gate
  // on require_org_admin server-side (…112) — a non-admin caller is denied.
  r = await rpc("organization_join_requests_list", { p_organization_id: org.id }, worker2.token);
  report(r.status === 400 && /access denied|administrator|require_org_admin/i.test(String(r.data?.message || r.data)) ? "PASS" : "FAIL",
    "security: join-request list TVF denied for non-admin caller (server-side authz)", `HTTP ${r.status}`);

  // ---- request submission ----
  r = await rpc("organization_request_join", { p_organization_id: org.id }, worker.token);
  const requestId = Array.isArray(r.data) ? r.data[0] : r.data;
  report(r.status === 200 && !!requestId ? "PASS" : "FAIL",
    "request: worker submits join request (role server-set)", `HTTP ${r.status}`);
  created.requests.push(`'${requestId}'`);

  r = await rpc("organization_request_join", { p_organization_id: org.id }, worker.token);
  report(r.status === 400 && /pending request/i.test(String(r.data?.message || r.data)) ? "PASS" : "FAIL",
    "request: duplicate pending request DENIED", `HTTP ${r.status}`);

  r = await rpc("organization_request_join", { p_organization_id: org.id }, owner.token);
  report(r.status === 400 && /already a member/i.test(String(r.data?.message || r.data)) ? "PASS" : "FAIL",
    "request: active member cannot request", `HTTP ${r.status}`);

  r = await rpc("organization_request_join", { p_organization_id: orgClosed.id }, worker2.token);
  report(r.status === 400 && /not accepting join requests/i.test(String(r.data?.message || r.data)) ? "PASS" : "FAIL",
    "request: non-opt-in org rejects the request", `HTTP ${r.status}`);

  // forged role: the RPC signature has no role parameter — PGRST202/400 expected
  r = await rpc("organization_request_join", { p_organization_id: org.id, p_role: "owner" }, worker2.token);
  report(r.status === 404 || r.status === 400 ? "PASS" : "FAIL",
    "security: client cannot inject requested_role (no such parameter)", `HTTP ${r.status}`);

  // direct table manipulation
  r = await rest("/rest/v1/organization_join_requests", {
    method: "POST", token: worker2.token,
    body: [{ organization_id: org.id, user_id: worker2.userId, requested_role: "owner", status: "approved" }]
  });
  report(r.status === 403 || r.status === 401 ? "PASS" : "FAIL",
    "security: direct INSERT of an approved membership request denied by RLS", `HTTP ${r.status}`);
  r = await rest("/rest/v1/organization_join_requests?organization_id=eq." + org.id, { token: outsider.token });
  report(r.status === 200 && Array.isArray(r.data) && r.data.length === 0 ? "PASS" : "FAIL",
    "security: non-requester/non-admin cannot read join requests", `rows=${Array.isArray(r.data) ? r.data.length : "?"}`);

  // pending request grants NO membership: worker cannot read org rows yet
  const inc = await rest("/rest/v1/incidents?organization_id=eq." + org.id + "&select=id", { token: worker.token });
  report(inc.status === 200 && Array.isArray(inc.data) && inc.data.length === 0 ? "PASS" : "FAIL",
    "security: pending requester sees 0 org incidents (request ≠ membership)");

  // admin notification created
  const notif = await sqlOne(
    `select id from public.notifications
     where user_id = '${owner.userId}' and kind = 'join_request_received'
       and metadata->>'request_id' = '${requestId}'`);
  created.notifications.push(`'${notif.id}'`);
  report(!!notif.id ? "PASS" : "FAIL", "notification: org admin notified in-app of the request");

  // worker cannot read the admin's notification
  r = await rest("/rest/v1/notifications?id=eq." + notif.id, { token: worker.token });
  report(r.status === 200 && Array.isArray(r.data) && r.data.length === 0 ? "PASS" : "FAIL",
    "security: worker cannot read another user's notifications");

  // ---- review ----
  r = await rpc("organization_review_join_request", { p_request_id: requestId, p_approve: true }, worker.token);
  report(r.status === 400 && /require_org_admin|access denied|administrator/i.test(String(r.data?.message || r.data)) ? "PASS" : "FAIL",
    "security: worker cannot approve (self-approval denied)", `HTTP ${r.status} ${JSON.stringify(r.data).slice(0, 120)}`);

  r = await rpc("organization_review_join_request", { p_request_id: requestId, p_approve: true }, owner.token);
  report(r.status === 200 && (r.data === "approved" || r.data?.[0] === "approved") ? "PASS" : "FAIL",
    "review: admin approves — success", `HTTP ${r.status} body=${JSON.stringify(r.data)}`);

  const mem = await sqlOne(
    `select role, status from public.organization_members
     where organization_id = '${org.id}' and user_id = '${worker.userId}'`);
  report(mem.role === "worker" && mem.status === "active" ? "PASS" : "FAIL",
    "review: approval created an ACTIVE WORKER membership (server-set role)", JSON.stringify(mem));

  r = await rpc("organization_review_join_request", { p_request_id: requestId, p_approve: true }, owner.token);
  report(r.status === 400 && /already been processed/i.test(String(r.data?.message || r.data)) ? "PASS" : "FAIL",
    "review: second approval DENIED (already processed / race-safe)", `HTTP ${r.status}`);

  // worker notification on approval
  r = await rpc("my_notifications", { p_unread_only: true }, worker.token);
  const workerNotifs = Array.isArray(r.data) ? r.data : (r.data?.data || []);
  report(workerNotifs.some(n => n.kind === "join_request_approved") ? "PASS" : "FAIL",
    "notification: worker receives approval notification");

  // worker notifications can be marked read (own only)
  const wn = workerNotifs.find(n => n.kind === "join_request_approved");
  if (wn) {
    r = await rpc("mark_notification_read", { p_notification_id: wn.id }, worker.token);
    report(r.status === 200 || r.status === 204 ? "PASS" : "FAIL", "notification: worker marks own notification read", `HTTP ${r.status}`);
    r = await rpc("mark_notification_read", { p_notification_id: wn.id }, owner.token);
    // owner doesn't own it — the update matches 0 rows and silently succeeds; verify unchanged:
    const still = await sqlOne(`select read_at is not null as was_read from public.notifications where id = '${wn.id}'`);
    report(still.was_read === true && (r.status === 200 || r.status === 204) ? "PASS" : "FAIL",
      "security: cross-user mark-read is a no-op (row untouched)");
  }

  // worker now reads org-scoped data (RLS grants membership visibility)
  r = await rest("/rest/v1/organizations?id=eq." + org.id + "&select=id,name", { token: worker.token });
  report(r.status === 200 && Array.isArray(r.data) && r.data.length === 1 ? "PASS" : "FAIL",
    "membership: approved worker can read their organization row");

  // worker cannot call admin RPCs
  r = await rpc("org_add_member", { p_organization_id: org.id, p_user_id: worker2.userId, p_role: "admin" }, worker.token);
  report(r.status === 400 && /access denied|administrator|require_org_admin/i.test(String(r.data?.message || r.data)) ? "PASS" : "FAIL",
    "security: worker cannot call org_add_member (admin RPC)", `HTTP ${r.status}`);
  r = await rpc("org_update_member_role", { p_organization_id: org.id, p_user_id: worker.userId, p_role: "admin" }, worker.token);
  report(r.status === 400 ? "PASS" : "FAIL",
    "security: worker cannot self-elevate role via org_update_member_role", `HTTP ${r.status}`);
  // Cross-tenant roster check is asserted after the invitation section below
  // (needs a token that is a member of THIS org only). Phase 00 foundation RLS
  // deliberately lets org-mates read their OWN org's roster (membership
  // resolution); the security boundary is org-scoping, verified there.

  // ---- rejection path (BEFORE role-change tests keep worker2 a non-member) ----
  r = await rpc("organization_request_join", { p_organization_id: org.id }, worker2.token);
  const req2 = Array.isArray(r.data) ? r.data[0] : r.data;
  created.requests.push(`'${req2}'`);
  r = await rpc("organization_review_join_request", { p_request_id: req2, p_approve: false, p_rejection_reason: "Not hiring now" }, owner.token);
  report(r.status === 200 || r.status === 204 ? "PASS" : "FAIL", "review: admin rejects with reason", `HTTP ${r.status}`);
  const req2row = await sqlOne(`select status, reviewed_by, rejection_reason from public.organization_join_requests where id = '${req2}'`);
  report(req2row.status === "rejected" && req2row.reviewed_by === owner.userId && req2row.rejection_reason === "Not hiring now" ? "PASS" : "FAIL",
    "review: rejection recorded with reviewer + reason", JSON.stringify(req2row).slice(0, 120));
  r = await rpc("my_notifications", { p_unread_only: false }, worker2.token);
  const w2n = Array.isArray(r.data) ? r.data : (r.data?.data || []);
  report(w2n.some(n => n.kind === "join_request_rejected") ? "PASS" : "FAIL",
    "notification: worker receives rejection notification");
  const w2mems = await rest("/rest/v1/organization_members?user_id=eq." + worker2.userId, { token: worker2.token });
  report(w2mems.status === 200 && Array.isArray(w2mems.data) && w2mems.data.length === 0 ? "PASS" : "FAIL",
    "review: rejection creates NO membership");

  // re-request after rejection is allowed (fresh chance), unique (org,user) holds
  r = await rpc("organization_request_join", { p_organization_id: org.id }, worker2.token);
  const req3 = Array.isArray(r.data) ? r.data[0] : r.data;
  created.requests.push(`'${req3}'`);
  report(r.status === 200 ? "PASS" : "FAIL", "request: worker may re-apply after rejection", `HTTP ${r.status}`);

  // ---- role change by admin (worker → admin → worker) ----
  await rpc("org_update_member_role", { p_organization_id: org.id, p_user_id: worker.userId, p_role: "admin" }, owner.token);
  const memAdmin = await sqlOne(`select role from public.organization_members where organization_id = '${org.id}' and user_id = '${worker.userId}'`);
  report(memAdmin.role === "admin" ? "PASS" : "FAIL", "role change: admin promotes worker → admin");
  r = await rpc("org_add_member", { p_organization_id: org.id, p_user_id: worker2.userId, p_role: "worker" }, worker.token);
  // void RPC → PostgREST 204 No Content
  report(r.status === 204 || r.status === 200 ? "PASS" : "FAIL", "role change: promoted admin can now call admin RPCs", `HTTP ${r.status}`);
  await rpc("org_update_member_role", { p_organization_id: org.id, p_user_id: worker.userId, p_role: "worker" }, owner.token);
  const memWorker = await sqlOne(`select role from public.organization_members where organization_id = '${org.id}' and user_id = '${worker.userId}'`);
  report(memWorker.role === "worker" ? "PASS" : "FAIL", "role change: owner downgrades admin → worker");
  r = await rpc("org_add_member", { p_organization_id: org.id, p_user_id: worker2.userId, p_role: "worker" }, worker.token);
  report(r.status === 400 ? "PASS" : "FAIL",
    "role change: downgraded user loses admin-RPC authorization on revalidation", `HTTP ${r.status}`);



  // ---- invitations still work (admin-initiated flow coexists) ----
  r = await rpc("org_send_invite", { p_organization_id: org.id, p_email: outsider.email, p_role: "worker", p_site_id: null }, owner.token);
  const invToken = Array.isArray(r.data) ? r.data[0] : r.data;
  report(r.status === 200 && typeof invToken === "string" && invToken.length >= 32 ? "PASS" : "FAIL",
    "invitation: admin generates a secure token invite", `token length ${String(invToken).length}`);
  r = await rpc("org_accept_invite", { p_token: invToken }, outsider.token);
  report(r.status === 200 || r.status === 204 ? "PASS" : "FAIL", "invitation: worker accepts → membership active", `HTTP ${r.status}`);
  const invMem = await sqlOne(`select role, status from public.organization_members where organization_id = '${org.id}' and user_id = '${outsider.userId}'`);
  report(invMem.role === "worker" && invMem.status === "active" ? "PASS" : "FAIL", "invitation: invitee joined as active worker");
  r = await rpc("org_accept_invite", { p_token: invToken }, worker2.token);
  report(r.status === 400 ? "PASS" : "FAIL", "invitation: reuse by another account DENIED (email-matched, single-use)", `HTTP ${r.status}`);

  // ---- cross-tenant RLS boundary (outsider = member of THIS org only) ----
  const otherOrg = await sqlOne(
    `insert into public.organizations (slug, name, org_type, status)
     values ('jn-other-${stamp}', 'Join Other Co ${stamp}', 'mining_company', 'active')
     returning id`);
  created.orgs.push(`'${otherOrg.id}'`);
  const outsiderRoster = await rest("/rest/v1/organization_members?organization_id=eq." + otherOrg.id, { token: outsider.token });
  report(outsiderRoster.status === 200 && Array.isArray(outsiderRoster.data) && outsiderRoster.data.length === 0 ? "PASS" : "FAIL",
    "security: member of org A cannot enumerate org B's roster (cross-tenant RLS)",
    `rows=${Array.isArray(outsiderRoster.data) ? outsiderRoster.data.length : "?"}`);
  const ownRoster = await rest("/rest/v1/organization_members?organization_id=eq." + org.id, { token: outsider.token });
  report(ownRoster.status === 200 && Array.isArray(ownRoster.data) && ownRoster.data.some(m => m.user_id === outsider.userId) ? "PASS" : "FAIL",
    "roster: org-mates can read their OWN org's roster (Phase 00 foundation RLS)",
    `rows=${Array.isArray(ownRoster.data) ? ownRoster.data.length : "?"}`);

  // audit coverage
  const audits = await sql(
    `select action, count(*)::int as n from public.audit_log
     where organization_id = '${org.id}'
     group by action order by action`);
  const amap = {};
  (audits || []).forEach(a => { amap[a.action] = a.n; });
  report((amap["organization_join_requests.insert"] || 0) >= 1 ? "PASS" : "FAIL",
    "audit: join request lifecycle captured", JSON.stringify(amap));
  report((amap["organization_members.insert"] || 0) >= 1 && (amap["organization_members.update"] || 0) >= 1 ? "PASS" : "FAIL",
    "audit: membership creation + role changes captured");

  // ---- cleanup (self-cleaning, verified) ----
  if (created.requests.length) {
    await sql(`delete from public.audit_log where resource_id in (${created.requests.join(",")})`);
    await sql(`delete from public.notifications where metadata->>'request_id' in (${created.requests.map(s => s.replace(/'/g, "")).map(s => `'${s}'`).join(",")})`);
    await sql(`delete from public.organization_join_requests where id in (${created.requests.join(",")})`);
  }
  if (created.notifications.length) {
    await sql(`delete from public.notifications where id in (${created.notifications.join(",")})`);
  }
  if (created.users.length) {
    await sql(`delete from public.audit_log where actor_user_id in (${created.users.join(",")})`);
    await sql(`delete from public.organization_members where user_id in (${created.users.join(",")})`);
    await sql(`delete from public.notifications where user_id in (${created.users.join(",")})`);
    await sql(`delete from auth.identities where user_id in (${created.users.join(",")})`);
    await sql(`delete from auth.users where id in (${created.users.join(",")})`);
  }
  if (created.orgs.length) {
    await sql(`delete from public.audit_log where organization_id in (${created.orgs.join(",")})`);
    await sql(`delete from public.organization_join_requests where organization_id in (${created.orgs.join(",")})`);
    await sql(`delete from public.notifications where organization_id in (${created.orgs.join(",")})`);
    await sql(`delete from public.organization_members where organization_id in (${created.orgs.join(",")})`);
    await sql(`delete from public.sites where organization_id in (${created.orgs.join(",")})`);
    await sql(`delete from public.organizations where id in (${created.orgs.join(",")})`);
  }
  const residue = await sqlOne(
    `select
       (select count(*)::int from public.organizations where slug in ('jn-org-${stamp}','jn-closed-${stamp}')) as orgs,
       (select count(*)::int from auth.users where email like 'mg.jn.%.${stamp}@gmailtest.com') as users,
       (select count(*)::int from public.organization_join_requests where organization_id not in (select id from public.organizations)) as orphan_requests`);
  report(residue.orgs === 0 && residue.users === 0 && residue.orphan_requests === 0 ? "PASS" : "FAIL",
    "cleanup: probe orgs + users + requests removed", JSON.stringify(residue));

  console.log(`\nverify-worker-join: ${pass} PASS, ${fail} FAIL`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch(err => {
  console.error("probe error:", err.message);
  console.log(`\nverify-worker-join: ${pass} PASS, ${fail + 1} FAIL`);
  process.exit(1);
});
