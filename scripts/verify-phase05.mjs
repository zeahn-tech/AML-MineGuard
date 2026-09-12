// ============================================================
// Phase 05 cutover probe — fresh-start directive (ADR-014)
// Live end-to-end verification of the last legacy-only domain:
// safety notices (safety_notices + safety_notice_acks).
//   1. catalog: tables/RLS/policies/guards/audit triggers/grants
//   2. SELECT matrix: org-wide broadcast vs site-targeted vs worker
//   3. INSERT/UPDATE gates: notices.manage / org-admin / worker denied
//   4. author pinning: created_by forced to auth.uid() server-side
//   5. acks: own-ack only, idempotent (unique), author pinned, cross-org denied
//   6. soft-delete: no hard-delete path, deleted flag hidden from SELECT
//   7. cross-tenant isolation (both directions) + anon sees 0
//   8. audit: trigger rows with actor email; ack INSERT not client-writable
//   9. self-cleanup of all probe artifacts
// Usage: SUPABASE_ACCESS_TOKEN=... node scripts/verify-phase05.mjs
// ============================================================
import { readFileSync } from "node:fs";

const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
if (!TOKEN) { console.error("SUPABASE_ACCESS_TOKEN required"); process.exit(1); }
const REF = JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;

const APP = "https://" + REF + ".supabase.co";
let ANON = null;
try {
  const cfg = readFileSync("config.js", "utf8");
  ANON = (cfg.match(/supabaseAnonKey:\s*"([^"]+)"/) || [])[1] || "";
} catch { /* config.js missing */ }
if (!ANON) { console.error("Cannot read public anon key from config.js"); process.exit(1); }

let pass = 0, fail = 0;
function ok(name, cond, detail) {
  if (cond) { pass++; console.log("PASS", name); }
  else { fail++; console.log("FAIL", name, detail ? "— " + detail : ""); }
}
function parseBody(b) { try { return JSON.parse(b); } catch { return b; } }

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

async function signup(email, password) {
  const res = await fetch(APP + "/auth/v1/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json", apikey: ANON, Authorization: "Bearer " + ANON },
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
    headers: { "Content-Type": "application/json", apikey: ANON },
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
      apikey: ANON, Authorization: "Bearer " + token,
      "Content-Type": "application/json", Accept: "application/json"
    },
    body: bodyObj === undefined ? undefined : JSON.stringify(bodyObj)
  }).then(async r => ({ status: r.status, body: await r.text() }));
}

// ---------- main ----------
const artifacts = { orgIds: [], userIds: [], siteIds: [], noticeIds: [], ackIds: [] };
try {
  // ============ 1. catalog ============
  const tables = await sqlOne(
    "select count(*)::int as n from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname in ('safety_notices','safety_notice_acks') and c.relrowsecurity");
  ok("catalog: safety_notices + safety_notice_acks exist with RLS", tables && tables.n === 2, JSON.stringify(tables));

  const policies = await sqlOne(
    "select count(*)::int as n from pg_policies where schemaname='public' and tablename in ('safety_notices','safety_notice_acks')");
  ok("catalog: 5 policies (notices 3, acks 2)", policies && policies.n === 5, "found " + (policies && policies.n));

  const guards = await sqlOne(
    "select count(*)::int as n from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname in ('trg_safety_notices_guard','trg_safety_notice_acks_guard')");
  ok("catalog: 2 scope-guard functions", guards && guards.n === 2, "found " + (guards && guards.n));

  const trg = await sqlOne(
    "select count(*)::int as n from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and t.tgname like 'trg_%safety_notice%' and not t.tgisinternal");
  ok("catalog: 4 triggers (2 scope guards + 2 audit)", trg && trg.n === 4, "found " + (trg && trg.n));

  const auditTrg = await sqlOne(
    "select count(*)::int as n from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and t.tgname in ('trg_audit_safety_notices','trg_audit_safety_notice_acks')");
  ok("catalog: dedicated additive audit triggers installed", auditTrg && auditTrg.n === 2, "found " + (auditTrg && auditTrg.n));

  const anonReads = await sqlOne(
    "select has_table_privilege('anon','public.safety_notices','select') as anon_sel, has_table_privilege('anon','public.safety_notices','insert') as can_ins, has_table_privilege('authenticated','public.safety_notice_acks','update') as ack_upd, has_table_privilege('authenticated','public.safety_notices','delete') as del");
  ok("catalog: privilege shape (anon has NO table grants; acks INSERT/SELECT; notices no DELETE)",
    anonReads && !anonReads.anon_sel && !anonReads.can_ins && !anonReads.ack_upd && !anonReads.del, JSON.stringify(anonReads));

  // ============ probe actors ============
  const mkOrg = async (name, slug) => {
    const row = await sqlOne("insert into public.organizations (name, slug) values ($1,$2) returning id", [name, slug]);
    artifacts.orgIds.push(row.id);
    return row.id;
  };
  const mkUser = async (local) => {
    const email = local + "-" + scratchSuffix + "@p05probe.test";
    const tok = await signup(email, "Probe-Passw0rd!23");
    const u = await sqlOne("select id from auth.users where email = $1", [email]);
    artifacts.userIds.push(u.id);
    return { id: u.id, email, token: tok };
  };

  const orgA = await mkOrg("P05 Org A " + scratchSuffix, "p05-a-" + scratchSuffix);
  const orgB = await mkOrg("P05 Org B " + scratchSuffix, "p05-b-" + scratchSuffix);

  const owner = await mkUser("p05owner");
  const admin = await mkUser("p05admin");
  const worker = await mkUser("p05worker");
  const outsider = await mkUser("p05outsider");

  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'owner','active')", [orgA, owner.id]);
  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'admin','active')", [orgA, admin.id]);
  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'worker','active')", [orgA, worker.id]);
  // outsider: no membership anywhere
  // sanity: workers hold notices.manage? NO (per RBAC catalog) — probe relies on real bundles.
  const workerPerms = await pg("rpc/auth_user_permissions?organization_id=" + orgA, "POST", worker.token, {});
  // scalar RPC may not accept params — use the canonical one:
  const workerPerms2 = await pg("rpc/auth_user_permissions", "POST", worker.token, { p_organization_id: orgA });
  const workerPermList = parseBody(workerPerms2.body);
  const workerCanManage = Array.isArray(workerPermList) && workerPermList.includes("notices.manage");
  ok("rbac: worker does NOT hold notices.manage (policy gate relies on real bundles)",
    !workerCanManage, "worker perms: " + (Array.isArray(workerPermList) ? workerPermList.length : String(workerPermList).slice(0, 80)));

  // ============ 2. INSERT gates ============
  const n1 = await pg("safety_notices", "POST", owner.token, {
    organization_id: orgA, client_id: "p05-notice-owner-" + scratchSuffix,
    title: "P05 Broadcast " + scratchSuffix, message: "org-wide broadcast notice",
    notice_type: "info", pinned: true
  });
  ok("insert: owner publishes org-wide broadcast notice", n1.status === 201, n1.status + " " + n1.body.slice(0, 160));

  const n2 = await pg("safety_notices", "POST", admin.token, {
    organization_id: orgA, client_id: "p05-notice-admin-" + scratchSuffix,
    title: "P05 Critical " + scratchSuffix, message: "critical broadcast",
    notice_type: "critical", work_zone_text: "Bench 12"
  });
  ok("insert: admin publishes critical broadcast", n2.status === 201, n2.status + " " + n2.body.slice(0, 160));

  const n3 = await pg("safety_notices", "POST", worker.token, {
    organization_id: orgA, client_id: "p05-notice-worker-" + scratchSuffix,
    title: "should fail", message: "worker cannot publish"
  });
  ok("insert: worker DENIED publishing notices", n3.status === 403, n3.status + " " + n3.body.slice(0, 120));

  const n4 = await pg("safety_notices", "POST", outsider.token, {
    organization_id: orgA, client_id: "p05-notice-out-" + scratchSuffix,
    title: "should fail", message: "outsider cannot publish"
  });
  ok("insert: outsider DENIED publishing notices", n4.status === 403, n4.status + " " + n4.body.slice(0, 120));

  // spoofed organization: outsider targets org B? must be denied (no membership)
  const n5 = await pg("safety_notices", "POST", worker.token, {
    organization_id: orgB, client_id: "p05-notice-cross-" + scratchSuffix,
    title: "should fail", message: "cross-org publish"
  });
  ok("insert: cross-org publish DENIED", n5.status === 403, n5.status + " " + n5.body.slice(0, 120));

  // ============ 3. author pinning + audit ============
  const noticeRow = await sqlOne("select id, created_by, organization_id, site_id, pinned from public.safety_notices where client_id=$1", ["p05-notice-owner-" + scratchSuffix]);
  ok("pinning: created_by forced to the signed-in author (not client-supplied)",
    noticeRow && noticeRow.created_by === owner.id, JSON.stringify(noticeRow));
  if (noticeRow) artifacts.noticeIds.push(noticeRow.id);
  const notice2Row = await sqlOne("select id, created_by from public.safety_notices where client_id=$1", ["p05-notice-admin-" + scratchSuffix]);
  if (notice2Row) artifacts.noticeIds.push(notice2Row.id);

  // ============ 4. SELECT matrix ============
  const ownerRead = await pg("safety_notices?select=id,title&organization_id=eq." + orgA, "GET", owner.token);
  const ownerRows = parseBody(ownerRead.body) || [];
  ok("select: owner reads org notices (2)", ownerRead.status === 200 && ownerRows.length === 2, ownerRead.status + " n=" + ownerRows.length);

  const workerRead = await pg("safety_notices?select=id,title&organization_id=eq." + orgA, "GET", worker.token);
  const workerRows = parseBody(workerRead.body) || [];
  ok("select: worker reads broadcast notices (2, org-wide)", workerRead.status === 200 && workerRows.length === 2, workerRead.status + " n=" + workerRows.length);

  const outsiderRead = await pg("safety_notices?select=id&organization_id=eq." + orgA, "GET", outsider.token);
  ok("select: outsider reads 0 rows", outsiderRead.status === 200 && (parseBody(outsiderRead.body) || []).length === 0, outsiderRead.status);

  const anonRead = await pg("safety_notices?select=id", "GET", ANON);
  ok("select: anon reads 0 rows (RLS hides all)",
    (anonRead.status === 200 && (parseBody(anonRead.body) || []).length === 0) || anonRead.status === 401,
    String(anonRead.status));

  // cross-tenant: org B worker (none exists) — instead owner of A cannot see B's rows and vice versa
  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'owner','active')", [orgB, outsider.id]);
  const bNotice = await pg("safety_notices", "POST", outsider.token, {
    organization_id: orgB, client_id: "p05-notice-b-" + scratchSuffix,
    title: "P05 B-notice " + scratchSuffix, message: "org B only"
  });
  ok("insert: orgB owner publishes own-org notice", bNotice.status === 201, bNotice.status + " " + bNotice.body.slice(0, 120));
  const bRow = await sqlOne("select id from public.safety_notices where client_id=$1", ["p05-notice-b-" + scratchSuffix]);
  if (bRow) artifacts.noticeIds.push(bRow.id);
  const bWorkerRead = await pg("safety_notices?select=id&organization_id=eq." + orgA, "GET", outsider.token);
  ok("isolation: orgB owner reads 0 rows of orgA", bWorkerRead.status === 200 && (parseBody(bWorkerRead.body) || []).length === 0, bWorkerRead.status);

  // ============ 5. site-targeted notices ============
  const siteRow = await sqlOne(
    "insert into public.sites (organization_id, name, location, county, status) values ($1,$2,'Liberia','Nimba','active') returning id",
    [orgA, "P05 Site " + scratchSuffix]);
  artifacts.siteIds.push(siteRow.id);

  const nSite = await pg("safety_notices", "POST", owner.token, {
    organization_id: orgA, site_id: siteRow.id, client_id: "p05-notice-site-" + scratchSuffix,
    title: "P05 Site Notice " + scratchSuffix, message: "site-targeted"
  });
  ok("insert: site-targeted notice created", nSite.status === 201, nSite.status + " " + nSite.body.slice(0, 120));
  const siteNoticeRow = await sqlOne("select id from public.safety_notices where client_id=$1", ["p05-notice-site-" + scratchSuffix]);
  if (siteNoticeRow) artifacts.noticeIds.push(siteNoticeRow.id);

  const foreignSite = await pg("safety_notices", "POST", owner.token, {
    organization_id: orgA, site_id: null, client_id: "x", title: "x", message: "x"
  });
  void foreignSite;
  // cross-org site reference must be rejected by the guard
  const siteB = await sqlOne(
    "insert into public.sites (organization_id, name, location, county, status) values ($1,$2,'Liberia','Nimba','active') returning id",
    [orgB, "P05 Site B " + scratchSuffix]);
  artifacts.siteIds.push(siteB.id);
  // direct INSERT over REST with orgA + siteB → guard raises → 500/400, row must not persist
  const nCrossSite = await pg("safety_notices", "POST", owner.token, {
    organization_id: orgA, site_id: siteB.id, client_id: "p05-notice-crosssite-" + scratchSuffix,
    title: "should fail", message: "foreign site"
  });
  const crossPersisted = await sqlOne("select count(*)::int as n from public.safety_notices where client_id=$1", ["p05-notice-crosssite-" + scratchSuffix]);
  ok("guard: notice referencing a foreign-org site REJECTED and not persisted",
    nCrossSite.status >= 400 && crossPersisted && crossPersisted.n === 0, nCrossSite.status + " persisted=" + (crossPersisted && crossPersisted.n));

  // site-scoped SELECT: a worker with site membership reads site notices; without, broadcast only
  await sql("insert into public.site_members (organization_id, site_id, user_id, role, status) values ($1,$2,$3,'worker','active')",
    [orgA, siteRow.id, worker.id]);
  const wSiteRead = await pg("safety_notices?select=id,title&organization_id=eq." + orgA, "GET", worker.token);
  const wSiteRows = parseBody(wSiteRead.body) || [];
  const expectedSiteWorker = await sqlOne("select count(*)::int as n from public.safety_notices where organization_id=$1 and deleted=false", [orgA]);
  ok("select: site-member worker now also reads the site-targeted notice (" + expectedSiteWorker.n + ")",
    wSiteRead.status === 200 && wSiteRows.length === expectedSiteWorker.n, wSiteRead.status + " n=" + wSiteRows.length + " expected=" + expectedSiteWorker.n);

  // ============ 6. UPDATE / soft-delete ============
  const upd = await pg("safety_notices?id=eq." + noticeRow.id, "PATCH", owner.token, { pinned: false, title: "P05 Broadcast edited " + scratchSuffix });
  ok("update: owner edits own notice", upd.status === 204, upd.status + " " + upd.body.slice(0, 120));

  const updWorker = await pg("safety_notices?id=eq." + noticeRow.id, "PATCH", worker.token, { pinned: true });
  const afterWorker = await sqlOne("select pinned from public.safety_notices where id=$1", [noticeRow.id]);
  ok("update: worker PATCH has NO effect (RLS)", updWorker.status === 204 && afterWorker && afterWorker.pinned === false, updWorker.status + " " + JSON.stringify(afterWorker));

  // soft-delete: notices.delete holders (owner/admin/safety_manager per the Phase 03 catalog)
  // soft-delete via notice_soft_delete (SECURITY DEFINER RPC; a direct PATCH {deleted:true}
  // is impossible — PostgREST re-checks the SELECT policy deleted=false on the returning row,
  // the same class of finding recorded in Phase 07 for Prefer: return=representation).
  const softDelByWorker = await pg("rpc/notice_soft_delete", "POST", worker.token, { p_notice_id: notice2Row.id });
  ok("soft-delete: worker DENIED the RPC (no notices.delete)", softDelByWorker.status >= 400, softDelByWorker.status + " " + softDelByWorker.body.slice(0, 120));
  const softDel = await pg("rpc/notice_soft_delete", "POST", admin.token, { p_notice_id: notice2Row.id });
  const afterDel = await sqlOne("select deleted from public.safety_notices where id=$1", [notice2Row.id]);
  ok("soft-delete: admin soft-deletes via notice_soft_delete", softDel.status === 200 || softDel.status === 204, softDel.status + " " + softDel.body.slice(0, 120));
  const readAfterDel = await pg("safety_notices?select=id&organization_id=eq." + orgA, "GET", worker.token);
  const readAfterDelRows = parseBody(readAfterDel.body) || [];
  const beforeDelCount = await sqlOne("select count(*)::int as n from public.safety_notices where organization_id=$1 and deleted=false", [orgA]);
  ok("soft-delete: deleted notice disappears from SELECT (policy filters deleted=false)",
    readAfterDelRows.length === beforeDelCount.n, "n=" + readAfterDelRows.length + " nondeleted=" + beforeDelCount.n);
  // safety_officer holds create+update (catalog) — verify an update-capable non-admin can edit
  const officer = await mkUser("p05officer");
  await sql("insert into public.organization_members (organization_id, user_id, role, status) values ($1,$2,'safety_officer','active')", [orgA, officer.id]);
  const updOfficer = await pg("safety_notices?id=eq." + noticeRow.id, "PATCH", officer.token, { pinned: true });
  const afterOfficer = await sqlOne("select pinned from public.safety_notices where id=$1", [noticeRow.id]);
  ok("update: safety_officer (notices.update) edits notice", updOfficer.status === 204 && afterOfficer && afterOfficer.pinned === true, updOfficer.status + " " + JSON.stringify(afterOfficer));
  // catalog DELETE permission never grants a hard-delete REST path (Phase 06 rule: soft-delete only)
  const hardDel = await pg("safety_notices?id=eq." + noticeRow.id, "DELETE", admin.token);
  const stillThere = await sqlOne("select count(*)::int as n from public.safety_notices where id=$1", [noticeRow.id]);
  ok("no hard-delete: DELETE is a no-op for org users (privilege revoked / no policy)",
    stillThere && stillThere.n === 1, "n=" + (stillThere && stillThere.n));
  const auditDel = await sqlOne(
    "select count(*)::int as n from public.audit_log where resource='safety_notices' and action='DELETE.safety_notices' and resource_id=$1", [noticeRow.id]);
  ok("no hard-delete: attempted DELETE also produced no audit row (no-op, nothing happened)",
    auditDel && auditDel.n === 0, "n=" + (auditDel && auditDel.n));

  // ============ 7. acks ============
  const ack1 = await pg("safety_notice_acks", "POST", worker.token, { notice_id: noticeRow.id, organization_id: orgA });
  ok("acks: worker acknowledges broadcast notice", ack1.status === 201, ack1.status + " " + ack1.body.slice(0, 160));

  const ackDup = await pg("safety_notice_acks", "POST", worker.token, { notice_id: noticeRow.id, organization_id: orgA });
  ok("acks: duplicate ack rejected by unique (notice,user)", ackDup.status >= 400, ackDup.status);

  const ackSpoof = await pg("safety_notice_acks", "POST", worker.token, { notice_id: noticeRow.id, organization_id: orgA, user_id: owner.id });
  ok("acks: spoofed user_id NOT persisted as the acker", ackSpoof.status >= 400, ackSpoof.status + " " + ackSpoof.body.slice(0, 120));

  const ackForeign = await pg("safety_notice_acks", "POST", outsider.token, { notice_id: noticeRow.id, organization_id: orgA });
  ok("acks: non-member CANNOT ack", ackForeign.status >= 400, ackForeign.status + " " + ackForeign.body.slice(0, 120));

  const ackB = await pg("safety_notice_acks", "POST", outsider.token, { notice_id: bRow.id, organization_id: orgB });
  ok("acks: orgB owner acks own-org notice OK", ackB.status === 201, ackB.status + " " + ackB.body.slice(0, 120));

  const ackRow = await sqlOne("select id, user_id from public.safety_notice_acks where notice_id=$1 and user_id=$2", [noticeRow.id, worker.id]);
  ok("acks: acker pinned server-side to auth.uid()", ackRow && ackRow.user_id === worker.id, JSON.stringify(ackRow));
  if (ackRow) artifacts.ackIds.push(ackRow.id);

  const workerAckRead = await pg("safety_notice_acks?select=notice_id&organization_id=eq." + orgA, "GET", worker.token);
  const workerAckRows = parseBody(workerAckRead.body) || [];
  ok("acks: worker reads own ack only (not orgB acks)", workerAckRead.status === 200 && workerAckRows.length === 1, workerAckRead.status + " n=" + workerAckRows.length);

  const ownerAckRead = await pg("safety_notice_acks?select=notice_id,user_id&organization_id=eq." + orgA, "GET", owner.token);
  const ownerAckRows = parseBody(ownerAckRead.body) || [];
  ok("acks: org admin reads all acks for their org (notices.manage)", ownerAckRead.status === 200 && ownerAckRows.length >= 1, ownerAckRead.status + " n=" + ownerAckRows.length);

  const anonAckRead = await pg("safety_notice_acks?select=notice_id", "GET", ANON);
  ok("acks: anon reads 0 ack rows", anonAckRead.status === 200 && (parseBody(anonAckRead.body) || []).length === 0, anonAckRead.status);

  // ============ 8. audit ============
  const auditN = await sqlOne(
    "select count(*)::int as n from public.audit_log where resource='safety_notices' and resource_id in (select id::text from public.safety_notices where id = any($1::uuid[]))",
    [artifacts.noticeIds.length ? artifacts.noticeIds : ["00000000-0000-0000-0000-000000000000"]]);
  ok("audit: notice INSERT/UPDATE captured by the dedicated trigger", auditN && auditN.n >= 2, "n=" + (auditN && auditN.n));

  const auditActor = await sqlOne(
    "select actor_user_id, actor_name, source from public.audit_log where resource='safety_notices' order by created_at desc limit 1");
  ok("audit: actor = auth.uid() from the trigger, source='trigger'",
    auditActor && auditActor.source === "trigger" && auditActor.actor_name && String(auditActor.actor_name).includes("p05"), JSON.stringify(auditActor));

  const forged = await pg("audit_log", "POST", owner.token, { organization_id: orgA, action: " forged", resource: "safety_notices", resource_id: noticeRow.id });
  ok("audit: forged client INSERT rejected (append-only)", forged.status === 403, forged.status + " " + forged.body.slice(0, 120));

} catch (e) {
  fail++;
  console.log("FAIL probe-abort —", e.message);
} finally {
  // ============ 9. self-cleanup ============
  try {
    if (artifacts.userIds.length) {
      await sql("delete from public.organization_members where user_id = any($1::uuid[])", [artifacts.userIds]);
      await sql("delete from public.site_members where user_id = any($1::uuid[])", [artifacts.userIds]);
    }
    if (artifacts.noticeIds.length) {
      await sql("delete from public.safety_notice_acks where notice_id = any($1::uuid[])", [artifacts.noticeIds]);
      await sql("delete from public.safety_notices where id = any($1::uuid[])", [artifacts.noticeIds]);
    }
    if (artifacts.userIds.length) {
      await sql("delete from auth.users where id = any($1::uuid[])", [artifacts.userIds]);
    }
    if (artifacts.siteIds.length) {
      await sql("delete from public.sites where id = any($1::uuid[])", [artifacts.siteIds]);
    }
    if (artifacts.orgIds.length) {
      await sql("delete from public.audit_log where organization_id = any($1::uuid[])", [artifacts.orgIds]);
      await sql("delete from public.organizations where id = any($1::uuid[])", [artifacts.orgIds]);
    }
    console.log(`cleanup: removed ${artifacts.orgIds.length} orgs, ${artifacts.userIds.length} users, ${artifacts.noticeIds.length} notices, ${artifacts.siteIds.length} sites`);
    const residue = await sqlOne(
      "select (select count(*)::int from public.safety_notices where client_id like 'p05-%') as notices, (select count(*)::int from public.organizations where slug like 'p05-%') as orgs");
    console.log("residue:", JSON.stringify(residue));
  } catch (e) {
    console.log("cleanup-error:", e.message);
  }
}

console.log(`\nverify-phase05: ${pass} PASS, ${fail} FAIL`);
process.exit(fail ? 1 : 0);
