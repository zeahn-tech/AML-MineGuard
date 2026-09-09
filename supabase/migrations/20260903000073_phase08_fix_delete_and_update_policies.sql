-- =============================================================================
-- Migration 073: Phase 08 fix — delete permissions + CAPA update for site members
-- =============================================================================

begin;

-- 1. Add missing permission codes
insert into public.permissions (code, domain, description) values
    ('inspections.delete', 'inspections', 'Hard delete inspections (admin only)'),
    ('corrective_actions.delete', 'corrective_actions', 'Hard delete corrective actions (admin only)')
on conflict (code) do nothing;

-- Grant to owner (all perms)
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'owner' and p.code in ('inspections.delete', 'corrective_actions.delete')
on conflict do nothing;

-- Grant to admin (all perms minus billing.manage)
insert into public.role_permissions (role_id, permission_id)
select r.id, p.id from public.roles r, public.permissions p
where r.code = 'admin' and p.code in ('inspections.delete', 'corrective_actions.delete')
on conflict do nothing;

-- 2. Fix auth_user_can_update_capa: site-only members (supervisor/site_manager)
-- who are the assignee must be able to update. The original function requires
-- auth_user_has_org_access which excludes site-only members. Change to use
-- auth_user_has_site_access (which checks org_members OR site_members).
create or replace function public.auth_user_can_update_capa(p_capa_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1 from public.corrective_actions c
        where c.id = p_capa_id
          and public.auth_user_has_site_access(c.organization_id, c.site_id)
          and (
              c.assigned_to = auth.uid()
              or public.auth_user_effective_role(c.organization_id)
                  in ('owner','admin','safety_manager')
          )
    );
$$;

-- 3. Fix CAPA INSERT for site-only members (supervisor/site_manager)
-- who have corrective_actions.create permission. The original function requires
-- auth_user_has_site_access which already works for site members. But let's
-- also fix auth_user_can_insert_capa for the null-site case:
create or replace function public.auth_user_can_insert_capa(p_organization_id uuid, p_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.auth_user_has_site_access(p_organization_id, p_site_id)
       and (public.auth_user_has_permission(p_organization_id, 'corrective_actions.create')
            or public.auth_user_has_site_permission(p_organization_id, p_site_id, 'corrective_actions.create'));
$$;

-- 4. Fix auth_user_can_delete_capa: also needs site-access (not just org-access)
-- for consistency with update. But hard-delete is admin/owner only via permission.
create or replace function public.auth_user_can_delete_capa(p_capa_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1 from public.corrective_actions c
        where c.id = p_capa_id
          and public.auth_user_has_org_access(c.organization_id)
          and public.auth_user_has_permission(c.organization_id, 'corrective_actions.delete')
    );
$$;

commit;
