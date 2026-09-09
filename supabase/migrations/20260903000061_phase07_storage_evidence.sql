-- ============================================================================
-- MINEGUARD LIBERIA — Phase 07: incident evidence object storage
-- Target database: Supabase (PostgreSQL 15+)
--
-- Evidence media (photos/videos/documents) lives in a PRIVATE storage bucket
-- `incident-evidence`, NOT in database rows. This migration creates the bucket
-- and the storage.objects RLS policies that authorize every access by joining
-- the object key back to the incident row (SECURITY_MODEL §2.4/§2.5:
-- "object storage keyed organizations/{org}/… with server-side authz per
-- request — knowing a path grants nothing").
--
-- Object key layout (both accepted):
--   new uploads:   organizations/{org_uuid}/sites/{site_uuid}/incidents/{incident_uuid}/{file}
--   Phase 05      organizations/{org_slug}/sites/{site_slug}/incidents/{client_id}/{i}.jpg
--   (legacy map)  …incident token is the 6th path segment; it may be an
--                 incident UUID or the legacy client_id (offline idempotency
--                 key). Authorization is resolved through the incident row,
--                 never by trusting the path itself.
--
-- Policy semantics mirror RLS_MATRIX §1.2 evidence:
--   SELECT  → current user can VIEW the incident (org-wide roles, site roles,
--             own reports, site_notice_scope broadcast)
--   INSERT  → current user can attach evidence to the incident (uploader =
--             reporter of own incident or incident-update-capable role)
--   UPDATE  → current user can update the incident (update-capable roles)
--   DELETE  → hard-delete gated to owner/admin/safety_manager (via
--             auth_user_can_delete_incident)
-- The EXISTS subqueries below read public.incidents under the CURRENT user's
-- RLS, so the incident's own row-level policy IS the storage authorization —
-- a worker can only ever reach their own incident's objects, never another
-- org's or another worker's evidence, and never by guessing a path.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. Private bucket (10 MB/object; image/pdf/video content types)
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
    'incident-evidence',
    'incident-evidence',
    false,
    10485760,
    array['image/jpeg', 'image/png', 'image/webp', 'application/pdf', 'video/mp4']
)
on conflict (id) do update
    set public = false,
        file_size_limit = excluded.file_size_limit,
        allowed_mime_types = excluded.allowed_mime_types;

-- ---------------------------------------------------------------------------
-- 2. storage.objects policies (scope: incident-evidence bucket only)
-- ---------------------------------------------------------------------------
-- Segment helpers used inline:
--   s5 = split_part(name,'/',5)  → must be 'incidents'
--   s6 = split_part(name,'/',6)  → incident token (uuid OR client_id)
-- The incident lookup uses the current user's RLS on public.incidents.

drop policy if exists incident_evidence_objects_select on storage.objects;
create policy incident_evidence_objects_select
    on storage.objects for select to authenticated
    using (
        bucket_id = 'incident-evidence'
        and split_part(name, '/', 5) = 'incidents'
        and exists (
            select 1
            from public.incidents i
            where i.id::text = split_part(name, '/', 6)
               or i.client_id  = split_part(name, '/', 6)
        )
    );

drop policy if exists incident_evidence_objects_insert on storage.objects;
create policy incident_evidence_objects_insert
    on storage.objects for insert to authenticated
    with check (
        bucket_id = 'incident-evidence'
        and split_part(name, '/', 5) = 'incidents'
        and exists (
            select 1
            from public.incidents i
            where (i.id::text = split_part(name, '/', 6)
                   or i.client_id = split_part(name, '/', 6))
              and (i.reported_by_user_id = auth.uid()
                   or public.auth_user_can_update_incident(i.id))
        )
    );

drop policy if exists incident_evidence_objects_update on storage.objects;
create policy incident_evidence_objects_update
    on storage.objects for update to authenticated
    using (
        bucket_id = 'incident-evidence'
        and split_part(name, '/', 5) = 'incidents'
        and exists (
            select 1
            from public.incidents i
            where (i.id::text = split_part(name, '/', 6)
                   or i.client_id = split_part(name, '/', 6))
              and public.auth_user_can_update_incident(i.id)
        )
    )
    with check (
        bucket_id = 'incident-evidence'
        and split_part(name, '/', 5) = 'incidents'
    );

drop policy if exists incident_evidence_objects_delete on storage.objects;
create policy incident_evidence_objects_delete
    on storage.objects for delete to authenticated
    using (
        bucket_id = 'incident-evidence'
        and split_part(name, '/', 5) = 'incidents'
        and exists (
            select 1
            from public.incidents i
            where (i.id::text = split_part(name, '/', 6)
                   or i.client_id = split_part(name, '/', 6))
              and public.auth_user_can_delete_incident(i.id)
        )
    );

-- No anon policies: without an authenticated session the bucket is fully
-- private (Supabase default deny). Service role (server-side import in
-- Phase 05) bypasses RLS by design.

commit;