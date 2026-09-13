// Durable utility: apply a SQL file to the linked Supabase project via the
// management API. Usage:
//   SUPABASE_ACCESS_TOKEN=sbp_... node scripts/apply-migration.mjs <file.sql>
// Prints the server result (or error) and exits non-zero on failure.
import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: node scripts/apply-migration.mjs <file.sql>");
  process.exit(2);
}
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
if (!TOKEN) {
  console.error("SUPABASE_ACCESS_TOKEN is required");
  process.exit(2);
}
const REF = JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;
const sql = readFileSync(file, "utf8");

const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
  method: "POST",
  headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
  body: JSON.stringify({ query: sql }),
});
const text = await res.text();
console.log(`HTTP ${res.status}`);
try {
  console.log(JSON.stringify(JSON.parse(text), null, 2).slice(0, 4000));
} catch {
  console.log(text.slice(0, 4000));
}
process.exit(res.ok ? 0 : 1);
