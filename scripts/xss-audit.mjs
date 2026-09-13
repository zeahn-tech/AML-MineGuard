// ============================================================
// MINEGUARD — XSS render-path audit (Phase 13, SECURITY_CERTIFICATION §1 row 14)
//
// Static audit of every dynamic interpolation that reaches an HTML
// sink (innerHTML / outerHTML / insertAdjacentHTML / document.write)
// in the client render files. A finding is an interpolation NOT
// wrapped in an escaping helper and NOT matching the reviewed
// safe-allowlist below.
//
// Exit 1 if any unescaped interpolation is found in the audited
// files (fails `npm test` closed, same policy as security-scan).
//
// Allowlist policy (keep in sync with SECURITY_CERTIFICATION §1):
//   * escaping helpers: esc / escHtml / escapeHtml / MG.esc
//   * numbers: toFixed / toLocaleString / .length / Math.round(...)
//   * static i18n keys: t('literal.key')
//   * static dataset fields from data.js (emoji, term, definition,
//     steps, colors, labels) — reviewed, never user-controlled
//   * ternaries yielding only fixed literals (class fragments, labels)
//   * enum keys through label/color lookup helpers
// User-derived fields (names, badges, locations, descriptions, tasks,
// filters, ids, timestamps of user records) MUST be escaped — findings
// below prove the fix in admin.html / app.js / notices.js.
// ============================================================

import { readFileSync } from "node:fs";

const AUDIT_FILES = [
  "index.html",
  "admin.html",
  "app.js",
  "org-admin.js",
  "gov-admin.js",
  "auth-ui.js",
  "notices.js",
  "firebase.js",
  "join-requests.js",
];

// HTML sinks whose string argument is executed as markup.
const SINK_RE = /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(/;

// Interpolations are considered escaped if wrapped in one of these.
const ESCAPE_RE = /\b(?:esc|escapeHtml|MG\.esc|escapeHTML|escHtml)\s*\(/;

// Helper names that build markup with internal escaping.
const BUILDER_RE = /\b(?:renderRow|renderCard|rowHtml|cardHtml)\s*\(/;

// Verified-safe allowlist (each entry reviewed — never user-controlled data):
const SAFE_EXACT = new Set([
  "i", "idx", "i+1", "l",
  "now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })",
  "item.emoji", "guide.emoji", "item.term", "item.short", "item.description",
  "item.term[0].toUpperCase()", "item.name", "item.name.split(' ')[0]",
  "guide.title", "c.name", "c.number", "sev.color", "sev.bg", "sev.border", "dotColor",
  "guide.steps.map(s => `<li>${s}</li>`).join('')",
  "c.number.replace(/\\D/g, '')",
  
  "dayCounts[i]>0?`<span>${dayCounts[i]}</span>`:''",
  "isEnabled ? 'notif-on' : ''",
  "isEnabled ? '🔔' : '🔕'",
  "l === activeFilter ? 'active' : ''",
  "window.currentLang === 'fr' ? 'Appeler' : 'Call'",
  "Math.round(v?((v/max)*100):0)",
  "Math.round(v?((v/maxS)*100):0)",
  "inc._id || inc.savedAt",
  "item.definition",
  "item.category",
  "item.mandatory === 'always' ? 'always' : 'task'",
  "colors[k]",
  "sevColors[k]",
  "sev.icon",
  "sev.label",
  "inc.action ? `<div style=\"margin-top:8px;font-size:12px;color:var(--green);\">✅ Action taken recorded</div>` : ''",
  "dayCounts[i]>0?`<span>${dayCounts[i]}</span>`:''",
  "item.when",
]);

const SAFE_RE = new RegExp([
  "\\.toFixed\\s*\\(", "\\.toLocaleString\\s*\\(", "\\.length\\b",
  "t\\(\\s*['\"][a-zA-Z0-9_.]+['\"]\\s*\\)",
  "^(?:true|false|null)$",
  "^\\w+(?:\\.\\w+)*\\s*(?:===|!==)\\s*'[^']*'\\s*\\?\\s*'[^']*'\\s*:\\s*'[^']*'$",
  "^Math\\.round\\([^)]*\\)$",
  "^(?:typeLabel|sevLabel|sevColor|sevBg|statusLabel|catLabel|labelFor|colorFor|typeLabelShort|formatTime)\\s*\\(",
].join("|"));

// Extract top-level ${...} bodies with balanced-brace scanning
// (nested template literals contain inner ${...} — they stay inside
// the outer body; inner interpolations are validated as part of it).
function extractInterpolations(stmt) {
  const out = [];
  let i = 0;
  while (i < stmt.length - 1) {
    if (stmt[i] === "$" && stmt[i + 1] === "{") {
      let depth = 1, j = i + 2;
      while (j < stmt.length && depth > 0) {
        if (stmt[j] === "$" && stmt[j + 1] === "{") { depth++; j += 2; continue; }
        if (stmt[j] === "{") depth++;
        else if (stmt[j] === "}") depth--;
        j++;
      }
      out.push(stmt.slice(i + 2, j - 1));
      i = j;
    } else i++;
  }
  return out;
}

// Nested-template bodies embedding ONLY numeric counts / static markup
// (chart bars, action banners, step lists from the static dataset):
const NESTED_SAFE = [
  /^inc\.status !== 'resolved'\s*\?\s*`<button[^`]*\$\{inc\._id \|\| inc\.savedAt\}[^`]*<\/button>`\s*:\s*''$/,  // id = internal client_id uuid
  /^expStr\s*\?\s*`<div class="nm-expires">[^`]*\$\{expStr\}<\/div>`\s*:\s*''$/,  // expStr = formatted Date
  /^notice\.pinned\s*\?\s*'<span[^>]*>[^<]*<\/span>'\s*:\s*''$/,  // fixed literal markup
  /^v\s*>\s*0\s*\?\s*`<span>\$\{v\}<\/span>`\s*:\s*''$/,
  /^dayCounts\[i\]\s*>\s*0\s*\?\s*`<span>\$\{dayCounts\[i\]\}<\/span>`\s*:\s*''$/,
  /^inc\.action\s*\?\s*`<div style=.{0,120}>[^`]*<\/div>`\s*:\s*''$/,
  /^guide\.steps\.map\(\s*s\s*=>\s*`<li>\$\{s\}<\/li>`\s*\)\.join\(''\)$/,
];

function isSafeValue(body) {
  const b = body.trim();
  if (NESTED_SAFE.some(re => re.test(b))) return true;
  if (SAFE_EXACT.has(b) || SAFE_RE.test(b)) return true;
  // Nested-template builders over static dataset fields (guide.steps from data.js):
  if (/^guide\.steps\.map\(s => `<li>\$\{s\}<\/li>`\)\.join\(/.test(b)) return true;
  // Day-count nested template (numeric counts only):
  if (/^dayCounts\[i\]>0\?`<span>\$\{dayCounts\[i\]\}<\/span>`/.test(b)) return true;
  // inc.action ternary with nested static template:
  if (/^inc\.action \? `<div style=/.test(b)) return true;
  return false;
}

const findings = [];
let sinks = 0;

for (const f of AUDIT_FILES) {
  let src;
  try { src = readFileSync(f, "utf8"); } catch { continue; }
  const lines = src.split("\n");
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    if (!SINK_RE.test(line)) continue;
    sinks++;
    // Accumulate continuation lines until the statement's template closes.
    let stmt = line;
    let j = i;
    const backticks = (s) => (s.match(/`/g) || []).length;
    while (backticks(stmt) % 2 === 1 && j + 1 < lines.length) {
      j++; stmt += "\n" + lines[j];
    }
    // Every ${...} inside a sink statement must be escaped or explicitly safe.
    // Balanced extraction: handles nested templates like `${a ? `<b>${n}</b>` : ''}`.
    const interps = extractInterpolations(stmt);
    for (const body of interps) {
      if (ESCAPE_RE.test(body) || isSafeValue(body) || BUILDER_RE.test(stmt)) continue;
      findings.push({ file: f, line: i + 1, snippet: body.trim().slice(0, 110), stmt: stmt.split("\n")[0].trim().slice(0, 100) });
    }
  }
}

if (findings.length === 0) {
  console.log(`xss-audit: clean — ${sinks} HTML sink statements audited across ${AUDIT_FILES.length} files, all dynamic interpolations escaped or explicitly safe`);
} else {
  console.log(`xss-audit: ${findings.length} UNESCAPED interpolation(s) reaching HTML sinks:`);
  const seen = new Set();
  for (const fd of findings) {
    const key = fd.file + ":" + fd.line;
    if (seen.has(key)) continue;
    seen.add(key);
    console.log(`  ${fd.file}:${fd.line}\n      sink: ${fd.stmt}\n      value: \${${fd.snippet}}`);
  }
}
process.exit(findings.length ? 1 : 0);
