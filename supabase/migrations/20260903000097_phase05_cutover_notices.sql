-- ============================================================
-- Phase 05 (fresh-start cutover) — safety notices
--
-- Owner directive 2026-09-10 (recorded in ADR-014): the Firestore
-- data migration is WAIVED — the platform starts afresh with new
-- data in Supabase. The one legacy domain without a Supabase home
-- is safety notices (admin broadcasts read by workers). This
-- migration brings notices into the tenant model per RLS_MATRIX
-- §1.2 shape: org+site scoped, org-wide safety roles read/write,
-- broadcast notices readable by all org members, worker
-- acknowledgements per user (idempotent), audited via a dedicated
-- additive trigger (Phase 06 …053 / Phase 12 …094 convention — the
-- shared trg_audit_capture is NOT rewritten).
-- ============================================================

create table public.safety_notices (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null, -- null = org-wide broadcast
    client_id       text unique,
    title           text not null check (length(trim(title)) > 0),
    message         text not null,
    notice_type     text not null default 'info'
                    check (notice_type in ('info', 'warning', 'critical')),
    work_zone_text  text,
    created_by_text text,                       -- legacy display name (display only)
    created_by      uuid references auth.users(id) on delete set null,
    lang            text not null default 'en',
    pinned          boolean not null default false,
    expires_at      timestamptz,
    deleted         boolean not null default false,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

create index safety_notices_org_idx     on public.safety_notices (organization_id, created_at desc);
create index safety_notices_site_idx    on public.safety_notices (site_id) where site_id is not null;
create index safety_notices_pinned_idx  on public.safety_notices (organization_id, pinned, created_at desc);

create table public.safety_notice_acks (
    id              uuid primary key default gen_random_uuid(),
    notice_id       uuid not null references public.safety_notices(id) on delete cascade,
    user_id         uuid not null references auth.users(id) on delete cascade,
    organization_id uuid not null references public.organizations(id) on delete cascade,
    site_id         uuid references public.sites(id) on delete set null,
    client_id       text unique,
    acked_at        timestamptz not null default now(),
    unique (notice_id, user_id)
);

create index safety_notice_acks_notice_idx on public.safety_notice_acks (notice_id);
create index safety_notice_acks_user_idx   on public.safety_notice_acks (user_id);

-- ---- guards (Phase 06/07 convention: server-side scope + identity pins) ----
create or replace function public.trg_safety_notices_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    if tg_op = 'INSERT' then
        if new.site_id is not null and not exists (
            select 1 from public.sites s
            where s.id = new.site_id and s.organization_id = new.organization_id
        ) then
            raise exception 'P0001: notice site does not belong to the notice organization';
        end if;
        if new.created_by is null and auth.uid() is not null then
            new.created_by := auth.uid();       -- author pinned server-side
        end if;
    end if;
    return new;
end;
$$;

create trigger trg_safety_notices_scope
    before insert on public.safety_notices
    for each row execute function public.trg_safety_notices_guard();

create or replace function public.trg_safety_notice_acks_guard()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org  uuid;
    v_site uuid;
begin
    if tg_op = 'INSERT' then
        select n.organization_id, n.site_id into v_org, v_site
        from public.safety_notices n where n.id = new.notice_id;
        if v_org is null then
            raise exception 'P0001: notice not found';
        end if;
        new.organization_id := v_org;           -- scope mirrored from the notice
        new.site_id := v_site;
        if auth.uid() is not null then
            new.user_id := auth.uid();          -- acker pinned server-side
        end if;
    end if;
    return new;
end;
$$;

create trigger trg_safety_notice_acks_scope
    before insert on public.safety_notice_acks
    for each row execute function public.trg_safety_notice_acks_guard();

-- ---- RLS -------------------------------------------------------------------
alter table public.safety_notices enable row level security;
alter table public.safety_notice_acks enable row level security;

-- SELECT: org members. Broadcast notices (site_id null) are org-wide;
-- site-targeted notices additionally require access to that site OR a
-- notice-managing role (Phase 07 site_notice_scope semantics).
create policy safety_notices_select on public.safety_notices
    for select to authenticated
    using (
        deleted = false
        and public.auth_user_has_org_access(organization_id)
        and (
            site_id is null
            or public.auth_user_has_site_access(organization_id, site_id)
            or public.auth_user_has_permission(organization_id, 'notices.manage')
            or public.auth_user_is_org_admin(organization_id)
        )
    );

-- INSERT/UPDATE: notices.manage holders or org admins. DELETE: none (soft
-- delete via UPDATE; hard delete is service-role/cascade — Phase 06 rule).
create policy safety_notices_insert on public.safety_notices
    for insert to authenticated
    with check (
        public.auth_user_has_permission(organization_id, 'notices.manage')
        or public.auth_user_is_org_admin(organization_id)
    );

create policy safety_notices_update on public.safety_notices
    for update to authenticated
    using (
        public.auth_user_has_permission(organization_id, 'notices.manage')
        or public.auth_user_is_org_admin(organization_id)
    )
    with check (
        public.auth_user_has_permission(organization_id, 'notices.manage')
        or public.auth_user_is_org_admin(organization_id)
    );

-- Acks: your own ack (any active org member); notice managers read all.
create policy safety_notice_acks_select on public.safety_notice_acks
    for select to authenticated
    using (
        user_id = auth.uid()
        or public.auth_user_has_permission(organization_id, 'notices.manage')
        or public.auth_user_is_org_admin(organization_id)
    );

create policy safety_notice_acks_insert on public.safety_notice_acks
    for insert to authenticated
    with check (
        user_id = auth.uid()
        and public.auth_user_has_org_access(organization_id)
    );

-- ---- audit: dedicated additive trigger (21st → 22nd/23rd trigger) ----------
create or replace function public.trg_audit_notices_capture()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    if tg_table_name = 'safety_notices' then
        insert into public.audit_log
            (organization_id, actor_user_id, actor_name, action, resource, resource_id, metadata, source)
        values
            (coalesce(new.organization_id, old.organization_id),
             auth.uid(),
             (select email::text from auth.users where id = auth.uid()),
             tg_op || '.' || tg_table_name,
             tg_table_name,
             coalesce(new.id, old.id)::text,
             jsonb_build_object(
                 'title', coalesce(new.title, old.title),
                 'notice_type', coalesce(new.notice_type, old.notice_type),
                 'pinned', coalesce(new.pinned, old.pinned),
                 'deleted', coalesce(new.deleted, old.deleted),
                 'site_id', coalesce(new.site_id, old.site_id)),
             'trigger');
    else -- safety_notice_acks
        insert into public.audit_log
            (organization_id, actor_user_id, actor_name, action, resource, resource_id, metadata, source)
        values
            (coalesce(new.organization_id, old.organization_id),
             auth.uid(),
             (select email::text from auth.users where id = auth.uid()),
             tg_op || '.' || tg_table_name,
             tg_table_name,
             coalesce(new.id, old.id)::text,
             jsonb_build_object(
                 'notice_id', coalesce(new.notice_id, old.notice_id),
                 'user_id', coalesce(new.user_id, old.user_id)),
             'trigger');
    end if;
    return coalesce(new, old);
end;
$$;

drop trigger if exists trg_audit_safety_notices on public.safety_notices;
create trigger trg_audit_safety_notices
    after insert or update or delete on public.safety_notices
    for each row execute function public.trg_audit_notices_capture();

drop trigger if exists trg_audit_safety_notice_acks on public.safety_notice_acks;
create trigger trg_audit_safety_notice_acks
    after insert or update or delete on public.safety_notice_acks
    for each row execute function public.trg_audit_notices_capture();

-- ---- standard privileges (Phase 01 convention) ------------------------------
-- No DELETE privilege: soft-delete via the deleted flag is the only removal
-- path (Phase 06 rule — hard delete is service-role/cascade only).
grant select, insert, update on public.safety_notices to authenticated;
grant select, insert on public.safety_notice_acks to authenticated;
grant select on public.safety_notices to anon;   -- RLS hides everything from anon
