-- ============================================================================
-- MINEGUARD LIBERIA — Phase 11 fix 2: allow government roles in org membership
--
-- Defect found by the Phase 11 live probe (2026-09-03): bootstrap of a
-- regulator admin failed with 23514 because organization_members_role_check
-- (Phase 03) whitelists only the 9 organization role codes, while the Phase 03
-- roles catalog deliberately seeds 4 government roles (scope='government')
-- with permission bundles for regulator-org members
-- (national_regulatory_admin, government_safety_inspector,
-- government_compliance_officer, government_analyst).
--
-- Regulator users are members OF a regulator organization — their membership
-- rows live in organization_members with those government role codes (that is
-- what every Phase 11 helper/policy resolves: organization_members ⋈ roles
-- where scope = 'government'). The check constraint was never expanded to
-- accept them.
--
-- Fix: extend organization_members_role_check with the 4 seeded government
-- role codes. No data changes; no existing role assignments affected.
-- Platform roles (scope='platform') remain NOT allowed as membership roles —
-- platform administration is not org membership.
-- ============================================================================

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
        'government_compliance_officer', 'government_analyst'
    ));
