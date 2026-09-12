// One-off: FK-safe cleanup for leftover p8-probe orgs (timed-out suite run).
import { readFileSync } from "node:fs";
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;
async function sql(query) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  const t = await res.text(); let d = null; try { d = t ? JSON.parse(t) : null; } catch { d = t; }
  return { status: res.status, data: d };
}
const PAT = `slug like 'p8-probe%' or slug like 'p9-probe%' or slug like 'p10-probe%' or slug like 'p11-probe%' or slug like 'p12-probe%' or slug like 'p13-probe%'`;
const found = await sql(`select id, slug from public.organizations where ${PAT};`);
console.log("leftover orgs:", JSON.stringify(found.data));
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
    if (r.status >= 400) console.log("FAIL", r.status, s.trim().split(/\s+/)[2], JSON.stringify(r.data).slice(0, 160));
  }
}
const left = await sql(`select id, slug from public.organizations where ${PAT};`);
console.log("remaining:", JSON.stringify(left.data));
