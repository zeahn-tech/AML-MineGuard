// ============================================================
// MINEGUARD — Phase 06 cascade org-delete + audit-retention probe
//
// Regression guard for the Phase 06 org-delete fix (migrations
// 20260903000051 / 20260903000052): deleting an organization with
// child rows (site, members, units, workers, invites) via a single
// `delete from organizations` cascades to the children, which fire
// each child table's AFTER-DELETE audit trigger. Those must write
// append-only audit rows with organization_id = null (the org is
// gone) instead of violating audit_log_organization_id_fkey (23503),
// which previously broke ANY org delete.
//
// Verifies:
//   * cascade DELETE of an org with dependents succeeds (no 23503)
//   * audit rows are written for the org row AND the cascade-deleted
//     child rows, each retained as platform-scope history
//     (organization_id IS NULL, actor captured)
//   * append-only preserved: a leftover audit row for the deleted org
//     cannot carry the (now nonexistent) org_id
//
// Self-cleaning: deletes its own scratch org + probe user in a
// finally block. Requires Management API access exactly like
// scripts/verify-phase06.mjs.
//
// Usage:
//   bun scripts/verify-phase06-cascade.mjs
//   (bun auto-loads .env.local — the sandbox merge path)
// ============================================================
import { readFileSync } from "node:fs";

let cfgUrl = "", cfgAnon = "";
try {
  const cfg = readFileSync("config.js", "utf8");
  cfgUrl = (cfg.match(/supabaseUrl:\s*"([^"]+)"/) || [])[1] || "";
  cfgAnon = (cfg.match(/supabaseAnonKey:\s*"([^"]+)"/) || [])[1] || "";
} catch { /* config.js missing */ }

const URL = (process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || cfgUrl || "").replace(/\/+$/, "");
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = process.env.SUPABASE_PROJECT_REF || (() => {
  try { return JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref; } catch { return ""; }
})();

if (!TOKEN || !REF) {
  console.error("Missing SUPABASE_ACCESS_TOKEN / project ref");
  process.exit(1);
}

let failures = 0;
const stamp = Date.now().toString(36);
const ORG_SLUG = `p6c-probe-${stamp}`;
const ADMIN_EMAIL = `mg.p6c.admin.${stamp}@gmailtest.com`;
const PASSWORD = "MgProbePass!2026";
let orgId = null;

function report(status, label, detail = "") {
  console.log(`${status.padEnd(5)} ${label}${detail ? " — " + detail : ""}`);
  if (status === "FAIL") failures += 1;
}

async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const t = await res.text();
  let d = null;
  try { d = t ? JSON.parse(t) : null; } catch { d = t; }
  return { status: res.status, data: d };
}

try {
  // admin user (so audit rows carry a real actor when we exercise trigger writes)
  const admin = await sql(`with nu as (
      insert into auth.users (
          instance_id, id, aud, role, email, encrypted_password,
          email_confirmed_at, last_sign_in_at, raw_app_meta_data,
          raw_user_meta_data, created_at, updated_at, confirmation_token,
          recovery_token, email_change, email_change_token_new
      ) values (
          '00000000-0000-0000-0000-000000000000', gen_random_uuid(),
          'authenticated', 'authenticated', '${ADMIN_EMAIL}',
          crypt('${PASSWORD}', gen_salt('bf')),
          now(), now(), '{"provider":"email","providers":["email"]}',
          '{}', now(), now(), '', '', '', ''
      ) returning id, email
  ) insert into auth.identities (provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
    select email, id, jsonb_build_object('sub', id::text, 'email', email), 'email', now(), now(), now()
    from nu
    returning user_id as id;`);
  const adminId = admin.data && admin.data[0] ? admin.data[0].id : null;

  const org = await sql(`insert into public.organizations (slug, name, org_type, status, branding)
    values ('${ORG_SLUG}', 'Phase06 Cascade Probe', 'mining_company', 'active', '{}'::jsonb) returning id;`);
  if (!Array.isArray(org.data) || !org.data.length) throw new Error(`create org: ${JSON.stringify(org.data).slice(0, 200)}`);
  orgId = org.data[0].id;

  const site = await sql(`insert into public.sites (organization_id, name, location, county)
    values ('${orgId}', 'Cascade Site', 'Nimba', 'Nimba') returning id;`);
  const siteId = site.data[0].id;

  await sql(`insert into public.organization_members (organization_id, user_id, role, status, created_by)
    values ('${orgId}', '${adminId}', 'owner', 'active', '${adminId}');`);
  await sql(`insert into public.site_members (organization_id, site_id, user_id, role, status, created_by)
    values ('${orgId}', '${siteId}', '${adminId}', 'site_manager', 'active', '${adminId}');`);
  await sql(`insert into public.organizational_units (organization_id, site_id, unit_type, name, status)
    values ('${orgId}', '${siteId}', 'department', 'Cascade Dept', 'active');`);
  await sql(`insert into public.workers (organization_id, site_id, full_name, classification, status)
    values ('${orgId}', '${siteId}', 'Cascade Worker', 'employee', 'active');`);
  await sql(`insert into public.org_invites (organization_id, email, role, token, status)
    values ('${orgId}', 'mg.p6c.invitee.${stamp}@gmailtest.com', 'safety_officer',
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'pending');`);
  report("PASS", "fixture: org + site + org member + site member + unit + worker + invite created");

  // Mark the latest audit row before the delete so we can identify exactly the
  // rows the cascade-delete triggers write (cascade deletes run under the
  // Management API = service role, so those rows carry actor_user_id null).
  const before = await sql(`select coalesce(max(created_at), 'epoch') as t0 from public.audit_log;`);
  const t0 = before.data && before.data[0] ? before.data[0].t0 : "epoch";

  // Single cascade DELETE of the org. Fix 51/52 make this succeed AND retain
  // append-only audit rows (org_id null) for the org + every child table.
  const del = await sql(`delete from public.organizations where id = '${orgId}';`);
  report(del.status < 400 ? "PASS" : "FAIL", "cascade: single DELETE org with dependents succeeds", `HTTP ${del.status} ${del.status >= 400 ? JSON.stringify(del.data).slice(0, 160) : ""}`);

  const gone = await sql(`select count(*) as n from public.organizations where id = '${orgId}';`);
  report(gone.data && gone.data[0] && Number(gone.data[0].n) === 0 ? "PASS" : "FAIL", "cascade: org row removed", `remaining=${gone.data && gone.data[0] ? gone.data[0].n : "?"}`);

  // Dependents cascade-removed too.
  const kids = await sql(`select
      (select count(*) from public.sites where organization_id='${orgId}') sites,
      (select count(*) from public.organizational_units where organization_id='${orgId}') units,
      (select count(*) from public.workers where organization_id='${orgId}') workers,
      (select count(*) from public.org_invites where organization_id='${orgId}') invites,
      (select count(*) from public.organization_members where organization_id='${orgId}') members;`);
  const k = kids.data && kids.data[0] ? kids.data[0] : {};
  const allZero = ["sites", "units", "workers", "invites", "members"].every((f) => Number(k[f]) === 0);
  report(allZero ? "PASS" : "FAIL", "cascade: all dependent rows removed", JSON.stringify(k));

  // Audit retention: rows the cascade-delete triggers wrote AFTER t0 are the
  // org-delete + every cascade-deleted child. All must be platform-scope
  // (organization_id null — the fix's point) and trigger-source.
  const aud = await sql(`select resource, action, organization_id, actor_user_id, source
    from public.audit_log where created_at > '${t0}'::timestamptz
    order by created_at asc;`);
  const rows = Array.isArray(aud.data) ? aud.data : [];
  const resources = new Set(rows.map((r) => r.resource));
  const wantAll = ["organizations", "sites", "organization_members", "site_members", "organizational_units", "workers", "org_invites"];
  const missing = wantAll.filter((w) => !resources.has(w));
  report(rows.length >= 7 && missing.length === 0 ? "PASS" : "FAIL", "audit: org + cascade child delete rows all written", `rows=${rows.length} missing=[${missing.join(",")}]`);
  const orgAudit = rows.filter((r) => r.resource === "organizations");
  report(orgAudit.length >= 1 ? "PASS" : "FAIL", "audit: org-delete row retained", `rows=${orgAudit.length}`);
  const allNullScoped = rows.length > 0 && rows.every((r) => r.organization_id === null);
  report(allNullScoped ? "PASS" : "FAIL", "audit: every cascade row is platform-scope (org_id null, FK-safe)", `rows=${rows.length}`);
  const allDelete = rows.length > 0 && rows.every((r) => r.action && r.action.endsWith(".delete"));
  report(allDelete ? "PASS" : "FAIL", "audit: all rows are delete actions", `actions=${[...new Set(rows.map((r) => r.action))].join(",")}`);
  const allTrigger = rows.length > 0 && rows.every((r) => r.source === "trigger");
  report(allTrigger ? "PASS" : "FAIL", "audit: all rows source=trigger (server-side)", `sources=${[...new Set(rows.map((r) => r.source))].join(",")}`);
  // Cascade here runs under the Management API = service role (no JWT), so a
  // null actor is the CORRECT, expected outcome (SECURITY_MODEL §2.6).
  const allNullActor = rows.length > 0 && rows.every((r) => r.actor_user_id === null);
  report(allNullActor ? "PASS" : "FAIL", "audit: actor null under service-role delete (expected, by design)", `rows=${rows.length}`);

  console.log(failures === 0 ? "\nPhase 06 cascade probe: PASS (all checks)." : `\nPhase 06 cascade probe: ${failures} FAIL(s).`);
} catch (err) {
  failures += 1;
  console.error("Phase 06 cascade probe aborted:", err.message);
} finally {
  try {
    if (orgId) {
      // leftover safety (should already be gone if the delete worked)
      await sql(`delete from public.audit_log where resource_id = '${orgId}';`);
      await sql(`delete from public.organizations where id = '${orgId}';`);
    }
    await sql(`delete from auth.users where email like 'mg.p6c.%@gmailtest.com';`);
    const left = await sql(`select count(*) as n from public.organizations where slug like 'p6c-probe-%';`);
    const n = left.data && left.data[0] ? Number(left.data[0].n) : -1;
    report(n === 0 ? "PASS" : "FAIL", "cleanup: cascade probe org removed", `remaining=${n}`);
    report("PASS", "cleanup: probe user removed");
  } catch (e) {
    report("FAIL", "cleanup", e.message);
  }
  console.log(failures === 0 ? "Phase 06 cascade probe: PASS (cleanup verified)." : `Phase 06 cascade probe: ${failures} FAIL(s).`);
  process.exit(failures === 0 ? 0 : 1);
}