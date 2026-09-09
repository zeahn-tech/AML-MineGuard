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
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}
const slug = await sql(`select id, slug from public.organizations where slug like 'p6-probe-%' or slug like 'p4-probe-%';`);
console.log("probe orgs:", JSON.stringify(slug.data));
if (slug.data && slug.data.length) {
  for (const o of slug.data) {
    const delAudit = await sql(`delete from public.audit_log where organization_id = '${o.id}';`);
    console.log("del audit:", delAudit.status, JSON.stringify(delAudit.data).slice(0, 300));
    const delOrg = await sql(`delete from public.organizations where id = '${o.id}';`);
    console.log("del org:", delOrg.status, JSON.stringify(delOrg.data).slice(0, 400));
  }
}
const left = await sql(`select id, slug from public.organizations where slug like 'p6-probe-%' or slug like 'p4-probe-%';`);
console.log("remaining:", JSON.stringify(left.data));
const aud = await sql(`select count(*) as n from public.audit_log where organization_id in (select id from public.organizations where slug like 'p6-probe-%');`);
console.log("audit left:", JSON.stringify(aud.data));
