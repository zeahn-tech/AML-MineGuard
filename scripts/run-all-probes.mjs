// ============================================================
// MINEGUARD — Run all live verification probes (Phase 13
// TESTING_STRATEGY rollout: the suite every session has been
// running manually, now one durable command with a summary and
// non-zero exit on any failure — CI-gateable).
//
// Each probe is self-cleaning and exits 0 on all-PASS.
//
// Usage:
//   node scripts/run-all-probes.mjs              # full suite
//   node scripts/run-all-probes.mjs 12 13        # subset
// Env:
//   SUPABASE_ACCESS_TOKEN — management-API token (required)
// ============================================================
import { spawnSync } from "node:child_process";

const TOKEN = process.env.SUPABASE_ACCESS_TOKEN || "";
if (!TOKEN) {
  console.error("run-all-probes: SUPABASE_ACCESS_TOKEN required");
  process.exit(2);
}

const PROBES = [
  ["04",  "verify-phase04.mjs",        "Phase 04 — site hierarchy + org-admin flows"],
  ["olc", "verify-org-lifecycle.mjs",  "Org lifecycle — creation + ownership transfer + isolation"],
  ["reg", "verify-regulator-lifecycle.mjs", "Regulator lifecycle — provisioning + claim + authorization"],
  ["join", "verify-worker-join.mjs",   "Worker join requests — approval, rejection, role change, audit"],
  ["push", "verify-push-foundation.mjs", "Push foundation — subscription store + ownership + authz"],
  ["gate", "verify-auth-gate.mjs",     "Auth gate — entry routing + destination resolver + logout"],
  ["05",  "verify-phase05.mjs",        "Phase 05 — fresh-start cutover (safety notices)"],
  ["06",  "verify-phase06.mjs",        "Phase 06 — RLS + audit foundation"],
  ["06c", "verify-phase06-cascade.mjs","Phase 06 — cascade-delete regression"],
  ["07",  "verify-phase07.mjs",        "Phase 07 — incidents + evidence"],
  ["08",  "verify-phase08.mjs",        "Phase 08 — JSA + inspections + CAPA"],
  ["09",  "verify-phase09.mjs",        "Phase 09 — emergency + SOS"],
  ["10",  "verify-phase10.mjs",        "Phase 10 — offline sync engine"],
  ["11",  "verify-phase11.mjs",        "Phase 11 — government command center"],
  ["12",  "verify-phase12.mjs",        "Phase 12 — SaaS + enterprise admin"],
  ["13",  "verify-phase13.mjs",        "Phase 13 — hardening + security scan"],
];

const args = process.argv.slice(2);
const selected = args.length
  ? PROBES.filter(([k]) => args.includes(k))
  : PROBES;

const results = [];
for (const [, file, label] of selected) {
  console.log(`\n=== ${label} (${file}) ===`);
  const r = spawnSync("node", [`scripts/${file}`], {
    stdio: "inherit",
    env: process.env,
    timeout: 10 * 60 * 1000,
  });
  results.push({ file, label, code: r.status });
}

console.log("\n==== SUITE SUMMARY ====");
let failed = 0;
for (const r of results) {
  const status = r.code === 0 ? "PASS" : `FAIL(exit ${r.code})`;
  if (r.code !== 0) failed++;
  console.log(`${status.padEnd(14)} ${r.label}`);
}
console.log(`\n${results.length - failed}/${results.length} probe suites PASS`);
process.exit(failed ? 1 : 0);
