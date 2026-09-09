// One-off FK-safe cleanup for Phase 06 probe orphan orgs (slug 'p6-probe-%').
// Deletes dependents first (audit, invites, workers, units, site_members,
// org_members, sites) then the org row, then leftover probe users.
import { readFileSync } from "node:fs";
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = (() => {
  try { return JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref; } catch { return ""; }
})();
async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const t = await res.text(); let d = null; try { d = t ? JSON.parse(t) : null; } catch { d = t; }
  return { status: res.status, data: d };
}
const found = await sql(`select id, slug from public.organizations where slug like 'p6-probe-%';`);
console.log("probe orgs:", JSON.stringify(found.data));
const ids = (Array.isArray(found.data) ? found.data : []).map((r) => r.id);
for (const id of ids) {
  const steps = [
    `delete from public.audit_log where organization_id = '${id}';`,
    `delete from public.org_invites where organization_id = '${id}';`,
    `delete from public.workers where organization_id = '${id}';`,
    `delete from public.organizational_units where organization_id = '${id}';`,
    `delete from public.site_members where organization_id = '${id}';`,
    `delete from public.organization_members where organization_id = '${id}';`,
    `delete from public.sites where organization_id = '${id}';`,
    `delete from public.organizations where id = '${id}';`,
  ];
  for (const s of steps) {
    const r = await sql(s);
    if (r.status >= 400) { console.log("FAIL", r.status, s.split(" ")[2], JSON.stringify(r.data).slice(0, 200)); }
  }
}
const left = await sql(`select id, slug from public.organizations where slug like 'p6-probe-%';`);
console.log("remaining probe orgs:", JSON.stringify(left.data));
await sql(`delete from auth.users where email like 'mg.p6.%@gmailtest.com';`);
const users = await sql(`select count(*) as n from auth.users where email like 'mg.p6.%@gmailtest.com';`);
console.log("probe users remaining:", JSON.stringify(users.data));