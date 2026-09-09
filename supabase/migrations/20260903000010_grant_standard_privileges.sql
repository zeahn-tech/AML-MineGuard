-- ============================================================================
-- MINEGUARD LIBERIA — Phase 01 follow-up: standard role privileges
--
-- Supabase convention: roles need base TABLE/FUNCTION privileges; ROW LEVEL
-- SECURITY (policies in 20260903000000_tenant_foundation.sql) then decides
-- which rows are visible/editable. Without these grants PostgREST returns
-- 42501 "permission denied for table" before RLS is ever evaluated.
--
--   * anon:          SELECT only. RLS policies are scoped `to authenticated`,
--                    so anonymous requests see ZERO rows (they cannot match a
--                    membership policy).
--   * authenticated: full DML privileges; RLS default-deny still blocks every
--                    row operation without a matching policy (membership-based
--                    SELECT only, for now).
--   * helper fns:    EXECUTE for anon + authenticated (anon calls return false
--                    because auth.uid() is null).
--
-- Default privileges are set so tables created in later phases inherit the
-- same convention automatically.
--
-- NOTE: never edit an already-applied migration (checksum drift). Append a new
-- migration instead.
-- ============================================================================

begin;

grant usage on schema public to anon, authenticated;

-- Tenancy tables (Phase 01)
grant select on table public.organizations, public.sites, public.organization_members
    to anon, authenticated;
grant insert, update, delete on table public.organizations, public.sites, public.organization_members
    to authenticated;

-- Authorization helpers (callable via RPC; RLS policies reference them too)
grant execute on function public.current_user_org_ids() to anon, authenticated;
grant execute on function public.auth_user_has_org_access(uuid) to anon, authenticated;
grant execute on function public.auth_user_is_org_admin(uuid) to anon, authenticated;

-- Default privileges for future phases (tables created by the migration role)
alter default privileges in schema public
    grant select, insert, update, delete on tables to anon, authenticated;
alter default privileges in schema public
    grant usage, select on sequences to anon, authenticated;

commit;
