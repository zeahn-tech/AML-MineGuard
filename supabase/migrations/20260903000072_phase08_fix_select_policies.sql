-- =============================================================================
-- Migration 072: Phase 08 fix — inspection SELECT restriction + CAPA SELECT
-- for site-only members
--
-- Fix 1: inspections_select was too broad (allowed workers to see all
-- inspections at their site). Restricted to org-wide safety/admin roles
-- and site-scoped supervisor/site_manager roles per RLS_MATRIX.
--
-- Fix 2: capa_select required auth_user_has_org_access which excludes
-- site-only members (supervisor/site_manager). Changed to use
-- auth_user_has_site_access as the base gate.
-- =============================================================================

begin;

-- Fix 1: inspection SELECT — restrict to org roles + site roles (not workers)
drop policy if exists inspections_select on public.inspections;
create policy inspections_select on public.inspections
    for select to authenticated
    using (
        deleted_at is null
        and (
            -- Org-wide safety/admin roles see all inspections
            (public.auth_user_has_org_access(organization_id)
             and public.auth_user_effective_role(organization_id)
                 in ('owner', 'admin', 'safety_manager', 'safety_officer'))
            -- Site-scoped roles see inspections at their site
            or (public.auth_user_has_site_access(organization_id, site_id)
                and public.auth_user_site_effective_role(organization_id, site_id)
                    in ('site_manager', 'supervisor'))
        )
    );

-- Fix 2: CAPA SELECT — use auth_user_has_site_access instead of auth_user_has_org_access
-- so site-only members (supervisor/site_manager) can see CAPAs at their site.
drop policy if exists capa_select on public.corrective_actions;
create policy capa_select on public.corrective_actions
    for select to authenticated
    using (
        deleted_at is null
        and (
            -- Org-wide safety/admin roles see all CAPAs
            (public.auth_user_has_org_access(organization_id)
             and public.auth_user_effective_role(organization_id)
                 in ('owner', 'admin', 'safety_manager'))
            -- Site-scoped roles see CAPAs at their site (site_id must match)
            or (site_id is not null
                and public.auth_user_has_site_access(organization_id, site_id)
                and public.auth_user_site_effective_role(organization_id, site_id)
                    in ('site_manager', 'supervisor'))
        )
    );

commit;
