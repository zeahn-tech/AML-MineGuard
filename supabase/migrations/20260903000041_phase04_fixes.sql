-- ============================================================================
-- MINEGUARD LIBERIA — Phase 04 fixes (appended; never edit applied migrations)
--
-- Two live-probe findings on project vuniwebbrvpgxscdsfei:
--   1. org_send_invite: gen_random_bytes() lives in the pgcrypto extension,
--      which is NOT on the fixed `search_path = public` of the SECURITY
--      DEFINER function -> 42883 at runtime. Replaced with core-only
--      sha256(convert_to(random…)) — no extension dependency.
--   2. org_list_members: auth.users.email is character varying(255); a
--      `returns table (... email text …)` function demands an EXACT column
--      type match (42804). Cast to text in the return query.
-- ============================================================================

begin;

create or replace function public.org_send_invite(p_organization_id uuid, p_email text, p_role text, p_site_id uuid)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
    v_email  text := lower(trim(p_email));
    v_token  text := encode(sha256(convert_to(
                   random()::text || clock_timestamp()::text || auth.uid()::text, 'utf8')), 'hex');
    v_uid    uuid;
begin
    if auth.uid() is null then
        raise exception 'authentication required';
    end if;
    perform public.require_org_admin(p_organization_id);

    if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
        raise exception 'invalid email address';
    end if;
    if p_role not in ('owner','admin','safety_manager','safety_officer','site_manager',
                      'supervisor','worker','contractor','member') then
        raise exception 'invalid role: %', p_role;
    end if;
    if p_role = 'owner' then
        raise exception 'ownership is granted by an existing owner, not by invite';
    end if;
    if p_site_id is not null and not exists (
        select 1 from public.sites where id = p_site_id and organization_id = p_organization_id
    ) then
        raise exception 'site does not belong to the given organization';
    end if;

    select id into v_uid from auth.users where lower(email) = v_email limit 1;
    if v_uid is not null and exists (
        select 1 from public.organization_members
        where organization_id = p_organization_id and user_id = v_uid and status <> 'removed'
    ) then
        raise exception 'user is already a member of this organization';
    end if;

    insert into public.org_invites (organization_id, site_id, email, role, token, invited_by)
    values (p_organization_id, p_site_id, v_email, p_role, v_token, auth.uid())
    on conflict (organization_id, lower(email)) where status = 'pending'
        do update set role = excluded.role, site_id = excluded.site_id,
                      token = excluded.token, expires_at = excluded.expires_at,
                      invited_by = excluded.invited_by, updated_at = now()
    returning token into v_token;

    return v_token;
end;
$$;

create or replace function public.org_list_members(p_organization_id uuid)
returns table (user_id uuid, email text, role text, status text, created_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null or not public.auth_user_has_org_access(p_organization_id) then
        raise exception 'access denied: organization membership required';
    end if;
    return query
        select m.user_id, u.email::text, m.role, m.status, m.created_at
        from public.organization_members m
        left join auth.users u on u.id = m.user_id
        where m.organization_id = p_organization_id
        order by m.created_at asc;
end;
$$;

-- Re-assert the intended ACLs (CREATE OR REPLACE retains grants, but be explicit).
revoke all on function public.org_send_invite(uuid, text, text, uuid) from public, anon;
revoke all on function public.org_list_members(uuid) from public, anon;
grant execute on function public.org_send_invite(uuid, text, text, uuid) to authenticated;
grant execute on function public.org_list_members(uuid) to authenticated;

commit;