// Read-only diagnostic: locate Phase 06 probe orphan org(s) and their dependent rows.
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
const orgs = await sql(`select id, slug, name from public.organizations where slug like 'p6-probe-%' or lower(name) = 'phase06 probe org' or lower(name) = 'phase 06 probe org';`);
console.log("probe orgs:", JSON.stringify(orgs.data));
if (orgs.data && orgs.data.length) {
  for (const o of orgs.data) {
    const counts = await sql(`select
      (select count(*) from public.sites where organization_id='${o.id}') sites,
      (select count(*) from public.organizational_units where organization_id='${o.id}') units,
      (select count(*) from public.workers where organization_id='${o.id}') workers,
      (select count(*) from public.org_invites where organization_id='${o.id}') invites,
      (select count(*) from public.organization_members where organization_id='${o.id}') members,
      (select count(*) from public.site_members where organization_id='${o.id}') site_members,
      (select count(*) from public.audit_log where organization_id='${o.id}') audit;`);
    console.log("dependents for", o.slug, JSON.stringify(counts.data));
  }
}