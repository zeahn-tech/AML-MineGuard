// Read-only residue check for probe scratch data (all known prefixes).
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
const PAT = `slug like 'p05-%' or slug like 'p4-probe-%' or slug like 'p6-probe-%' or slug like 'rbac-probe-%'`;
const orgs = await sql(`select id, slug from public.organizations where ${PAT} order by slug;`);
console.log("leftover orgs:", JSON.stringify(orgs.data));
const notices = await sql(`select count(*)::int as n from public.safety_notices where client_id like 'p05-%';`);
console.log("leftover p05 notices:", JSON.stringify(notices.data));
const users = await sql(`select count(*)::int as n from auth.users where email like 'mg.p05.%@gmailtest.com' or email like 'mg.p4.%@gmailtest.com' or email like 'mg.p6.%@gmailtest.com' or email like 'mg.rbac.%@gmailtest.com' or email like 'mg.p6r.%@gmailtest.com';`);
console.log("leftover probe users:", JSON.stringify(users.data));
