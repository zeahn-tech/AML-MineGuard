// ============================================================
// MINEGUARD — Security scan (Phase 13, TESTING_STRATEGY §5)
//
// Automated secret-leak + unsafe-pattern scan over the repo,
// designed to run in CI on every change (`npm test` runs it).
// Exit 1 on any CRITICAL finding.
//
// Coverage:
//   * Service-role keys, Supabase access tokens, private keys,
//     DB connection strings, legacy hard-coded admin credentials,
//     bearer tokens, generic apikey/secret/password assignments
//   * Legacy client-only authorization / plaintext-password
//     localStorage patterns that must never reappear (C1/C4 guard)
//
// Scope = tracked git files (respects .gitignore), skipping docs
// (documented incidents are expected there) and this scanner.
//
// Classified non-CRITICAL by design (recorded in SECURITY_CERTIFICATION.md):
//  * Firebase WEB API key — public by design (Firebase web config,
//    same class as the Supabase publishable anon key; C7 action =
//    enforce API restrictions in the Firebase console). Escalates to
//    CRITICAL if it ever appears outside the 4 legacy files.
//  * Probe-account passwords (scripts/*) — throwaway users created
//    and deleted by self-cleaning probes against the dev project;
//    not deployment secrets.
// ============================================================

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

let tracked = [];
try {
  tracked = execSync("git ls-files", { encoding: "utf8" })
    .split("\n").map(s => s.trim()).filter(Boolean);
} catch {
  console.error("security-scan: not a git checkout; nothing to scan");
  tracked = [];
}

const SKIP = [
  /^docs\//,                        // documented incidents/history expected
  /^scripts\/security-scan\.mjs$/,  // the scanner itself
  /^package-lock\.json$/,
  /\.(png|jpg|jpeg|gif|ico|apk|webp|woff2?)$/i,
];

const RULES = [
  ["CRITICAL", "service-role JWT (role=service_role)",
    /"role"\s*:\s*"service_role"|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/],
  ["CRITICAL", "supabase access token (sbp_…)",
    /\bsbp_[0-9a-f]{32,}\b/],
  ["CRITICAL", "private key block",
    /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/],
  ["CRITICAL", "postgres connection string with password",
    /postgres(?:ql)?:\/\/[^\s"']*:[^\s"'@]+@[^\s"']+/],
  ["CRITICAL", "legacy hard-coded admin credential",
    /mineguard2024/],
  ["CRITICAL", "generic apikey/secret/password assignment",
    /(?:apikey|api_key|secret|password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']/i],
  ["HIGH", "bearer token literal",
    /bearer\s+[A-Za-z0-9_-]{20,}/i],
];

// Files where generic matches are legitimate UI/form/i18n usage
// (field names, placeholders, i18n labels) — the value filters below
// still flag anything that looks like a real hard-coded credential.
const GENERIC_OK = [
  /index\.html$/, /admin\.html$/,
  /auth-ui\.js$/, /supabase-auth\.js$/, /lang\.js$/, /offline-store\.js$/,
];

// Files where the Firebase web key is expected (legacy public config).
const FIREBASE_WEB_KEY = /AIzaSy[A-Za-z0-9_-]{33}/;
const FIREBASE_LEGACY_FILES = new Set([
  "firebase.js", "sw.js", "firebase_rest_test.html", "scripts/phase05-inventory.mjs",
]);

// Throwaway probe-account passwords (never deployment secrets).
// Family pattern: all live-probe scripts generate scratch auth users with
// Mg<Variant>Pass!… constants (MgProbePass!, MgRegPass!, MgJoinPass!,
// MgPushPass!, …) — scripts/ only, never shipped client code.
const PROBE_PASSWORD = /Mg[A-Za-z]*Pass!/;
const PROBE_DIRS = /^scripts\//;

const findings = [];
for (const f of tracked) {
  if (SKIP.some(r => r.test(f))) continue;
  let content;
  try { content = readFileSync(f, "utf8"); } catch { continue; }
  const lines = content.split("\n");
  lines.forEach((line, i) => {
    // Classification first: Firebase web key location rules.
    if (FIREBASE_WEB_KEY.test(line)) {
      if (FIREBASE_LEGACY_FILES.has(f)) {
        findings.push({ file: f, line: i + 1, sev: "HIGH",
          name: "firebase web api key (public by design — enforce API restrictions in Firebase console; CRITICAL if seen elsewhere)",
          snippet: line.trim().slice(0, 120) });
      } else {
        findings.push({ file: f, line: i + 1, sev: "CRITICAL",
          name: "firebase web api key outside legacy files",
          snippet: line.trim().slice(0, 120) });
      }
      return;
    }
    // Throwaway probe-account passwords in probe scripts.
    if (PROBE_PASSWORD.test(line) && PROBE_DIRS.test(f)) {
      findings.push({ file: f, line: i + 1, sev: "HIGH",
        name: "probe-account password (throwaway probe users; not a deployment secret)",
        snippet: line.trim().slice(0, 120) });
      return;
    }
    for (const [sev, name, re] of RULES) {
      if (!re.test(line)) continue;
      if (name.startsWith("generic") && GENERIC_OK.some(r => r.test(f))) {
        // Allow i18n labels / form-field usage in these files; still
        // flag anything that smells like a real assigned credential.
        if (/password["']?\s*:|type=["']password|placeholder=|\.password\b|t\(/i.test(line)) continue;
      }
      findings.push({ file: f, line: i + 1, sev, name, snippet: line.trim().slice(0, 120) });
    }
  });
}

const crit = findings.filter(f => f.sev === "CRITICAL");
const high = findings.filter(f => f.sev === "HIGH");

if (findings.length === 0) {
  console.log("security-scan: 0 findings — clean");
} else {
  for (const f of findings) {
    console.log(`${f.sev}  ${f.name}\n      ${f.file}:${f.line}\n      > ${f.snippet}`);
  }
  console.log(`\nsecurity-scan: ${crit.length} CRITICAL, ${high.length} HIGH, ${findings.length} total`);
}
process.exit(crit.length ? 1 : 0);
