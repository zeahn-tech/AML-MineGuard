-- ============================================================================
-- 20260903000101_regulator_lifecycle_platform_roles.sql — companion to …100.
--
-- Latent bug found while wiring the regulator provisioning authorization:
-- organization_members_role_check (…030, extended …092 with government roles)
-- still does NOT include the three platform role codes seeded in the Phase 03
-- roles catalog (platform_super_admin / platform_support_admin /
-- platform_auditor). Any attempt to insert a platform-org membership fails
-- with 23514 — meaning bootstrap_first_platform_admin() (Phase 12, which
-- inserts role='platform_super_admin') has been latent-broken since …094,
-- and provision_regulator_organization() (…100, which authorizes callers by
-- platform-scoped membership) could never succeed either.
--
-- Fix (additive, mirrors the …092 precedent for government roles):
--   * Recreate organization_members_role_check including the 3 platform
--     codes. No existing row or policy changes; purely widens the value set.
--
-- This does NOT weaken authorization: platform roles remain assignable only
-- through the one-shot bootstrap_first_platform_admin RPC (orgless users,
-- memberless platform org) — direct INSERTs are still RLS default-deny.
-- ============================================================================

begin;

alter table public.organization_members
    drop constraint if exists organization_members_role_check;

alter table public.organization_members
    add constraint organization_members_role_check
    check (role in (
        -- organization roles (Phase 03)
        'owner', 'admin', 'safety_manager', 'safety_officer', 'site_manager',
        'supervisor', 'worker', 'contractor', 'member',
        -- government roles (Phase 03 catalog; membership in regulator orgs)
        'national_regulatory_admin', 'government_safety_inspector',
        'government_compliance_officer', 'government_analyst',
        -- platform roles (Phase 03 catalog; membership in platform orgs)
        'platform_super_admin', 'platform_support_admin', 'platform_auditor'
    ));

comment on constraint organization_members_role_check on public.organization_members is
    'Role codes allowed in organization_members: 9 organization roles (Phase 03) + 4 government roles (extended …092) + 3 platform roles (extended …101, fixes latent 23514 in bootstrap_first_platform_admin). Assignability is still governed by RPC authorization + RLS, not by this constraint.';

commit;
