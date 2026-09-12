#!/bin/sh
# Probe runner — credentials come from the environment, NEVER from
# this file (Phase 13 security scan: scripts/security-scan.mjs).
# An earlier revision hard-coded the service-role key + DB password
# here; those were removed and must be ROTATED (see SECURITY_CERTIFICATION.md).
# Required env:
#   SUPABASE_ACCESS_TOKEN   — management-API token (migrations/SQL probes)
#   NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY — public app keys
#   SUPABASE_SERVICE_ROLE_KEY / SUPABASE_DB_URL — only for verify-supabase.mjs
set -eu
: "${SUPABASE_ACCESS_TOKEN:?set SUPABASE_ACCESS_TOKEN in your environment}"

PHASE="${1:-11}"
node "scripts/verify-phase${PHASE}.mjs"
