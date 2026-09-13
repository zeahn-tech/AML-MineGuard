-- ============================================================================
-- 20260903000114_restore_phase04_permissions.sql — session 21 follow-up.
--
-- Follow-up to the …102 reseed: the authoritative reseed reproduced the
-- Phase 03 (+…073) + Phase 12 catalog exactly, but Phase 04's additive
-- permission rows were NOT part of that block — they were wiped with the
-- catalog and never re-seeded. Live symptom: organizational_units.update had
-- ZERO role bundles, breaking organizational-unit management for
-- site_manager (and thinning owner/admin/safety_manager/safety_officer).
--
-- Fix: restore the Phase 04 additions verbatim from …040 (same codes,
-- domains, descriptions, bundles). Additive + idempotent (on conflict do
-- nothing); touches nothing else.
-- ============================================================================

begin;

-- Phase 04 permission catalog additions (verbatim from …040 §1)
insert into public.permissions (code, domain, description) values
    ('organizational_units.create', 'organizational_units', 'Create departments/teams/work zones'),
    ('organizational_units.update', 'organizational_units', 'Update/soft-delete departments/teams/work zones')
on conflict (code) do nothing;

insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code in ('owner', 'admin', 'safety_manager')
  and p.code = 'organizational_units.create'
on conflict do nothing;

insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code in ('owner', 'admin', 'safety_manager', 'safety_officer', 'site_manager')
  and p.code = 'organizational_units.update'
on conflict do nothing;

commit;
