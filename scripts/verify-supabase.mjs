// ============================================================
// MINEGUARD — Supabase connectivity / RLS smoke check (dev)
// Zero dependencies: plain fetch against PostgREST + Auth.
//
// Usage:
//   NEXT_PUBLIC_SUPABASE_URL=... NEXT_PUBLIC_SUPABASE_ANON_KEY=... \
//   [SUPABASE_SERVICE_ROLE_KEY=...] node scripts/verify-supabase.mjs
//
// Checks (each prints PASS/FAIL/INFO with evidence):
//   1. Project reachability.
//   2. Tenant schema + seed rows (requires SUPABASE_SERVICE_ROLE_KEY;
//      otherwise reported INFO — anon cannot see tenant rows by design).
//   3. RLS: anon SELECT on organizations must return an EMPTY 200 (table
//      privileges granted, RLS policies `to authenticated` exclude anon).
//      A 42501 here means privileges are missing, not isolation.
//   4. Helper RPC as anon must return false (no session => no access).
// Missing schema (migration not applied yet) is reported as INFO.
// ============================================================

import { readFileSync } from "node:fs";

// Public config.js fallbacks (URL + anon key are public by design; secrets
// are never derived from the repo).
let cfgUrl = "", cfgAnon = "";
try {
  const cfg = readFileSync("config.js", "utf8");
  cfgUrl = (cfg.match(/supabaseUrl:\s*"([^"]+)"/) || [])[1] || "";
  cfgAnon = (cfg.match(/supabaseAnonKey:\s*"([^"]+)"/) || [])[1] || "";
} catch { /* config.js missing */ }

const URL = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || cfgUrl;
const ANON = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || cfgAnon;
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

if (!URL || !ANON) {
  console.error("Missing NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY");
  process.exit(1);
}

let failures = 0;

function report(status, label, detail = "") {
  console.log(`${status.padEnd(5)} ${label}${detail ? " — " + detail : ""}`);
  if (status === "FAIL") failures += 1;
}

async function pgRest(path, key, method = "GET", body) {
  const res = await fetch(`${URL}/rest/v1${path}`, {
    method,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  const text = await res.text();
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

function isMissingTable(r) {
  return r.status === 404 || (r.data && r.data.code === "PGRST205");
}

// 1. Reachability
try {
  const res = await fetch(`${URL}/auth/v1/health`);
  report(res.status === 200 ? "PASS" : "INFO", "auth/v1/health reachable", `HTTP ${res.status}`);
} catch (e) {
  report("FAIL", "auth/v1/health reachable", e.message);
}

// 2. Schema + seed (service role bypasses RLS)
if (SERVICE) {
  const orgs = await pgRest("/organizations?select=slug,name,org_type&order=slug", SERVICE);
  if (isMissingTable(orgs)) {
    report("INFO", "organizations table present", "migration not applied yet (PGRST205)");
  } else if (orgs.status === 200 && Array.isArray(orgs.data)) {
    report("PASS", "organizations readable (service role)", `${orgs.data.length} rows`);
    const aml = orgs.data.find(o => o.slug === "arcelormittal-liberia");
    report(aml ? "PASS" : "FAIL", "tenant #1 (ArcelorMittal Liberia) seeded", aml ? aml.name : "missing");
    const regulator = orgs.data.find(o => o.slug === "liberia-regulator");
    report(regulator ? "PASS" : "INFO", "regulator placeholder org seeded", regulator ? regulator.name : "missing");
  } else {
    report("FAIL", "organizations query (service role)", `HTTP ${orgs.status} ${JSON.stringify(orgs.data || "").slice(0, 200)}`);
  }
  const sites = await pgRest("/sites?select=organization_id,name&limit=5", SERVICE);
  report(sites.status === 200 ? "PASS" : "FAIL", "sites readable (service role)", `HTTP ${sites.status}`);
} else {
  report("INFO", "schema + seed check", "skipped — set SUPABASE_SERVICE_ROLE_KEY to verify tenant rows");
}

// 3. RLS: anon must see ZERO tenant rows (empty 200). A 42501 privilege error
//    is a FAIL (grants missing), not an isolation pass.
const anonOrgs = await pgRest("/organizations?select=slug", ANON);
if (anonOrgs.status === 200 && Array.isArray(anonOrgs.data)) {
  report(anonOrgs.data.length === 0 ? "PASS" : "FAIL", "RLS: anon sees zero organizations", `${anonOrgs.data.length} rows returned`);
} else if (isMissingTable(anonOrgs)) {
  report("INFO", "RLS: anon organizations check", "migration not applied yet");
} else if (anonOrgs.status === 401) {
  report("FAIL", "RLS: anon organizations check", "HTTP 401 — table privileges not granted to anon (run grant migration)");
} else {
  report("INFO", "RLS: anon organizations check", `HTTP ${anonOrgs.status} ${JSON.stringify(anonOrgs.data || "").slice(0, 160)}`);
}

// 4. Helper function via RPC as anon (must be false — no session)
const rpc = await pgRest("/rpc/auth_user_has_org_access", ANON, "POST", { p_organization_id: "00000000-0000-0000-0000-000000000000" });
if (rpc.status === 200) {
  report(rpc.data === false ? "PASS" : "FAIL", "helper: auth_user_has_org_access(anon) = false", `got ${JSON.stringify(rpc.data)}`);
} else if (isMissingTable(rpc) || rpc.status === 404) {
  report("INFO", "helper: auth_user_has_org_access", "function not applied yet");
} else {
  report("INFO", "helper: auth_user_has_org_access", `HTTP ${rpc.status} ${JSON.stringify(rpc.data || "").slice(0, 160)}`);
}

// 5. Phase 03 RBAC: RPCs as anon must deny (no session)
const rpcPerm = await pgRest("/rpc/auth_user_has_permission", ANON, "POST", { p_organization_id: "00000000-0000-0000-0000-000000000000", p_permission: "incidents.create" });
if (rpcPerm.status === 200) {
  report(rpcPerm.data === false ? "PASS" : "FAIL", "rbac: auth_user_has_permission(anon) = false", `got ${JSON.stringify(rpcPerm.data)}`);
} else if (rpcPerm.status === 404 || isMissingTable(rpcPerm)) {
  report("INFO", "rbac: auth_user_has_permission", "Phase 03 migration not applied yet");
} else {
  report("INFO", "rbac: auth_user_has_permission", `HTTP ${rpcPerm.status} ${JSON.stringify(rpcPerm.data || "").slice(0, 160)}`);
}

const rpcRole = await pgRest("/rpc/auth_user_effective_role", ANON, "POST", { p_organization_id: "00000000-0000-0000-0000-000000000000" });
if (rpcRole.status === 200) {
  report(rpcRole.data == null ? "PASS" : "FAIL", "rbac: auth_user_effective_role(anon) = null", `got ${JSON.stringify(rpcRole.data)}`);
} else if (rpcRole.status === 404 || isMissingTable(rpcRole)) {
  report("INFO", "rbac: auth_user_effective_role", "Phase 03 migration not applied yet");
} else {
  report("INFO", "rbac: auth_user_effective_role", `HTTP ${rpcRole.status} ${JSON.stringify(rpcRole.data || "").slice(0, 160)}`);
}

// 6. Phase 03 RBAC catalog + seeded bundles (requires SUPABASE_SERVICE_ROLE_KEY)
if (SERVICE) {
  const roles = await pgRest("/roles?select=code,scope&order=code", SERVICE);
  if (isMissingTable(roles)) {
    report("INFO", "rbac: roles table present", "Phase 03 migration not applied yet");
  } else if (roles.status === 200 && Array.isArray(roles.data)) {
    const orgRoles = ["owner", "admin", "safety_manager", "safety_officer", "site_manager", "supervisor", "worker", "contractor", "member"];
    const missing = orgRoles.filter(c => !roles.data.some(r => r.code === c));
    report(missing.length === 0 ? "PASS" : "FAIL", "rbac: organization roles seeded", `${roles.data.length} roles total${missing.length ? "; missing: " + missing.join(",") : ""}`);
  } else {
    report("FAIL", "rbac: roles query (service role)", `HTTP ${roles.status} ${JSON.stringify(roles.data || "").slice(0, 200)}`);
  }
  const perms = await pgRest("/permissions?select=code&limit=100", SERVICE);
  if (perms.status === 200 && Array.isArray(perms.data)) {
    report(perms.data.length >= 40 ? "PASS" : "FAIL", "rbac: permissions catalog seeded", `${perms.data.length} permissions`);
  } else if (!isMissingTable(perms)) {
    report("INFO", "rbac: permissions catalog", `HTTP ${perms.status} ${JSON.stringify(perms.data || "").slice(0, 160)}`);
  }
  const ownerRow = (await pgRest("/roles?select=id&code=eq.owner", SERVICE)).data;
  if (Array.isArray(ownerRow) && ownerRow.length) {
    const bundle = await pgRest(`/role_permissions?select=permissions(code)&role_id=eq.${ownerRow[0].id}&limit=100`, SERVICE);
    const codes = (bundle.data || []).map(r => r.permissions && r.permissions.code).filter(Boolean);
    report(codes.includes("organizations.manage") && codes.includes("billing.manage")
      ? "PASS" : "FAIL", "rbac: owner bundle = full org set", `${codes.length} permissions; has organizations.manage=${codes.includes("organizations.manage")}, billing.manage=${codes.includes("billing.manage")}`);
  } else {
    report("FAIL", "rbac: owner role row", "code=owner not found");
  }
  const workerRow = (await pgRest("/roles?select=id&code=eq.worker", SERVICE)).data;
  if (Array.isArray(workerRow) && workerRow.length) {
    const bundle = await pgRest(`/role_permissions?select=permissions(code)&role_id=eq.${workerRow[0].id}&limit=100`, SERVICE);
    const codes = (bundle.data || []).map(r => r.permissions && r.permissions.code).filter(Boolean);
    report(codes.includes("incidents.create") && !codes.includes("organizations.manage") && !codes.includes("billing.manage")
      ? "PASS" : "FAIL", "rbac: worker bundle = minimal self-service set", `${codes.length} permissions`);
  } else {
    report("FAIL", "rbac: worker role row", "code=worker not found");
  }
} else {
  report("INFO", "rbac: catalog + bundle checks", "skipped — set SUPABASE_SERVICE_ROLE_KEY; run scripts/verify-rbac.mjs for the live probe matrix");
}

console.log(failures === 0 ? "\nAll executed checks passed (no FAIL)." : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
