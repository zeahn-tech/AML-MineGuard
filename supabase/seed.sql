-- ============================================================================
-- MINEGUARD LIBERIA — Seed data (idempotent)
-- Phase 01: register ArcelorMittal Liberia as tenant #1 (its legacy Firestore
-- data becomes this org's records during Phase 05 migration) and a placeholder
-- regulator organization for the Phase 11 government platform.
--
-- Apply AFTER 20260903000000_tenant_foundation.sql. Safe to run repeatedly
-- (upsert-on-slug semantics via ON CONFLICT DO NOTHING).
-- ============================================================================

-- ArcelorMittal Liberia — tenant #1 (legacy hard-coded tenant becomes data)
insert into public.organizations (slug, name, county, org_type, status, branding, settings)
values (
    'arcelormittal-liberia',
    'ArcelorMittal Liberia',
    'Nimba',
    'mining_company',
    'active',
    '{"displayName":"ArcelorMittal Liberia","tagline":"Iron Ore Mining","country":"Liberia"}'::jsonb,
    '{"legacySite":"Nimba Mine"}'::jsonb
)
on conflict (slug) do nothing;

-- Sites for tenant #1 (Nimba Mine + Port Operations from the legacy app / README)
insert into public.sites (organization_id, name, location, county, status)
select o.id, s.name, s.location, s.county, 'active'
from public.organizations o
cross join (values
    ('Nimba Mine',      'Nimba County', 'Nimba'),
    ('Port Operations', 'Buchanan',     'Grand Bassa')
) as s(name, location, county)
where o.slug = 'arcelormittal-liberia'
on conflict (organization_id, name) do nothing;

-- Regulator organization placeholder (Phase 11 government platform space)
insert into public.organizations (slug, name, county, org_type, status, branding)
values (
    'liberia-regulator',
    'Liberia Minerals Regulator',
    NULL,
    'regulator',
    'active',
    '{"displayName":"Liberia Minerals Regulator","country":"Liberia"}'::jsonb
)
on conflict (slug) do nothing;

-- NOTE: departments/teams + worker profiles land in Phase 04 (site hierarchy).
-- NOTE: no membership rows are seeded here — users arrive with real identity in
-- Phase 02 and are attached to organizations by owners/admins (Phase 02/04).
