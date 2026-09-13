// Loads key=value pairs from .env.local into process.env (existing vars win),
// then dynamically imports the script passed as the first argument.
// Usage: node scripts/with-env.mjs scripts/<target>.mjs [args...]
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

try {
  const lines = readFileSync(".env.local", "utf8").split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    const key = m[1];
    let val = m[2];
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = val;
  }
} catch {
  // no .env.local — fall through; the target may use its own auth
}

const target = process.argv[2];
if (!target) {
  console.error("with-env: missing target script argument");
  process.exit(2);
}
// Drop the loader itself from argv so the target sees [node, target, ...args].
process.argv.splice(1, 1);
await import(pathToFileURL(target).href);
