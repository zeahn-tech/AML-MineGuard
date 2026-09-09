// Read-only Phase 11 object check against the live project.
// Usage: bun scripts/phase11-dbcheck.mjs
import { readFileSync } from "node:fs";

const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = (() => {
  try { return JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref; }
  catch { return ""; }
})();

if (!TOKEN) { console.error("missing SUPABASE_ACCESS_TOKEN"); process.exit(1); }
if (!REF) { console.error("missing project ref (link the project)"); process.exit(1); }

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

const checks = [
  ["government_grants table",
   `select count(*)::int as n from information_schema.tables where table_schema='public' and table_name='government_grants'`],
  ["phase11 policies",
   `select count(*)::int as n from pg_policies where schemaname='public' and policyname like '%_regulator'`],
  ["phase11 helper functions",
   `select count(*)::int as n from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname in
      ('auth_user_is_regulator_org_member','auth_user_is_regulator_user_in',
       'current_user_active_government_grants','auth_user_has_regulator_grant_for',
       'bootstrap_first_regulator_admin','regulator_issue_grant','regulator_revoke_grant',
       'regulator_update_user_role')`],
  ["government_grants audit trigger",
   `select count(*)::int as n from pg_trigger t join pg_class c on c.oid=t.tgrelid
    join pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relname='government_grants' and not t.tgisinternal and t.tgname='trg_audit_government_grants'`],
];

let bad = 0;
for (const [label, q] of checks) {
  const r = await sql(q);
  const n = Array.isArray(r.data) && r.data[0] ? r.data[0].n : null;
  const ok = r.status < 300 && Number(n) > 0;
  if (!ok) bad += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${label} (status ${r.status}, count ${n}) ${r.status !== 200 ? JSON.stringify(r.data).slice(0, 200) : ""}`);
}
process.exit(bad ? 1 : 0);
