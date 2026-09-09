// Prints ONLY the presence of expected env var names (never values).
// Used to diagnose which managed credentials are available.
const names = [
  "NEXT_PUBLIC_SUPABASE_URL",
  "NEXT_PUBLIC_SUPABASE_ANON_KEY",
  "SUPABASE_URL",
  "SUPABASE_ANON_KEY",
  "SUPABASE_ACCESS_TOKEN",
  "SUPABASE_SERVICE_ROLE_KEY",
  "SUPABASE_DB_URL",
  "SUPABASE_PROJECT_REF",
];
for (const n of names) console.log(`${n}: ${n in process.env ? "SET" : "missing"}`);
