// ============================================================
// MINEGUARD — Apply one SQL migration to the linked Supabase
// project via the Management API SQL endpoint (transactional:
// multi-statement query strings fail atomically).
//
// Equivalent to `supabase db push` for environments where the
// CLI project link is present but config.toml is not. Reads the
// project ref from supabase/.temp/linked-project.json and the
// access token from SUPABASE_ACCESS_TOKEN (never from the repo).
//
// Usage:
//   node scripts/apply-migration.mjs supabase/migrations/20260903000050_phase06_rls_audit.sql
// ============================================================

import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: node scripts/apply-migration.mjs <migration.sql>");
  process.exit(1);
}
const sql = readFileSync(file, "utf8");
const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
const REF = process.env.SUPABASE_PROJECT_REF || (() => {
  try {
    return JSON.parse(readFileSync("supabase/.temp/linked-project.json", "utf8")).ref;
  } catch {
    return "";
  }
})();
if (!TOKEN) {
  console.error("Missing SUPABASE_ACCESS_TOKEN (managed env)");
  process.exit(1);
}
if (!REF) {
  console.error("Cannot determine project ref — link the project or set SUPABASE_PROJECT_REF");
  process.exit(1);
}

const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
  method: "POST",
  headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
  body: JSON.stringify({ query: sql }),
});
const text = await res.text();
if (res.status >= 200 && res.status < 300) {
  console.log(`PASS applied ${file} to ${REF} (HTTP ${res.status})`);
  if (text.trim()) console.log(text.slice(0, 800));
} else {
  console.error(`FAIL apply ${file} (HTTP ${res.status})`);
  console.error(text.slice(0, 3000));
  process.exit(1);
}
