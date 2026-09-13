// One-off fidelity check for 20260903000111_join_request_audit_cases.sql:
// the republished trg_audit_capture() must equal the …090 definition with
// EXACTLY two new cases (organization_join_requests, notifications) inserted.
import { readFileSync } from "node:fs";

function extractBody(file) {
  const src = readFileSync(file, "utf8");
  const start = src.indexOf("create or replace function public.trg_audit_capture()");
  if (start < 0) throw new Error(`start not found in ${file}`);
  const end = src.indexOf("$$;", start);
  if (end < 0) throw new Error(`end not found in ${file}`);
  return src.slice(start, end + 3);
}

const b090 = extractBody("supabase/migrations/20260903000090_phase11_government_authorization.sql");
const b111 = extractBody("supabase/migrations/20260903000111_join_request_audit_cases.sql");

const newCases = [
  "        when 'organization_join_requests' then",
  "            v_org_id      := coalesce(new.organization_id, old.organization_id);",
  "            v_resource_id := coalesce(new.id, old.id)::text;",
  "            v_meta := jsonb_build_object(",
  "                'requested_role', coalesce(new.requested_role, old.requested_role),",
  "                'status', coalesce(new.status, old.status),",
  "                'status_previous', old.status,",
  "                'requested_by', coalesce(new.user_id, old.user_id),",
  "                'reviewed_by', new.reviewed_by);",
  "        when 'notifications' then",
  "            v_org_id      := coalesce(new.organization_id, old.organization_id);",
  "            v_resource_id := coalesce(new.id, old.id)::text;",
  "            v_meta := jsonb_build_object(",
  "                'kind', coalesce(new.kind, old.kind),",
  "                'recipient', coalesce(new.user_id, old.user_id));",
].join("\n");

const stripped = b111.replace("\n" + newCases, "");
let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log(`PASS ${name}`); }
  else { fail++; console.log(`FAIL ${name}`); }
}

check("…111 minus new cases === …090 byte-exact", stripped === b090);
check("…111 adds organization_join_requests", b111.includes("when 'organization_join_requests'"));
check("…111 adds notifications", b111.includes("when 'notifications'"));
check("…090 does NOT already have join_requests case", !b090.includes("organization_join_requests"));
check("…090 does NOT already have notifications case", !b090.includes("when 'notifications'"));
const c090 = (b090.match(/when '/g) || []).length;
const c111 = (b111.match(/when '/g) || []).length;
check(`case count 090=${c090} → 111=${c111} (+2)`, c111 === c090 + 2);
check("single function definition in 111", (readFileSync("supabase/migrations/20260903000111_join_request_audit_cases.sql", "utf8").match(/create or replace function public\.trg_audit_capture\(\)/g) || []).length === 1);

console.log(`\n${fail === 0 ? "FIDELITY: PASS" : "FIDELITY: FAIL"} (${pass}/${pass + fail})`);
process.exit(fail === 0 ? 0 : 1);
