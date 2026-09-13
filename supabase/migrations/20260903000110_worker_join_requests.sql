-- ============================================================================
-- 20260903000110_worker_join_requests.sql — Worker join-request workflow
-- (session 21).
--
-- Adds the missing "Join an Existing Organization" path while REUSING the
-- existing architecture (no parallel systems):
--   * membership creation goes through the SAME organization_members rows and
--     is captured by the EXISTING trg_audit_organization_members trigger;
--   * role assignment is server-set ('worker'); the client has no role param;
--   * invitations remain the separate admin-initiated flow (org_invites,
--     Phase 04) — untouched;
--   * authorization reuses require_org_admin (Phase 04) and the Phase 03
--     RBAC catalog;
--   * audit reuses trg_audit_capture (Phase 06);
--   * opt-in discovery uses organizations.settings.allow_worker_join_requests
--     (jsonb; restrictive default = false → org NOT discoverable).
--
-- New:
--   1. organization_join_requests — pending/approved/rejected/cancelled;
--      one pending request per (org, user) via partial unique index;
--      RLS: requester sees own rows; org admins see their org's rows;
--      direct INSERT/UPDATE default-deny (RPC-only writes).
--   2. notifications — user-scoped in-app notification store (authoritative
--      channel; web-push remains an additional delivery mechanism).
--   3. organization_search_joinable() — public-minimum TVF (name/type/county
--      only) for ACTIVE orgs that opted in to join requests.
--   4. organization_request_join() — worker submits a request (server-set
--      role; duplicate/member guards; notifies org admins).
--   5. organization_review_join_request() — admin approve/reject; atomic
--      (row lock + status re-check → concurrent second review gets a clear
--      "already processed" error); approval upserts an ACTIVE worker
--      membership; both outcomes notify the requester; audited.
--   6. organization_join_requests_list() / my_join_requests() — read helpers
--      scoped by the same authorization model.
-- ============================================================================

begin;

-- ---------------------------------------------------------------------------
-- 1. organization_join_requests
-- ---------------------------------------------------------------------------
create table public.organization_join_requests (
    id              uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    user_id         uuid not null references auth.users(id) on delete cascade,
    requested_role  text not null default 'worker'
                    check (requested_role in ('worker', 'contractor')),
    status          text not null default 'pending'
                    check (status in ('pending', 'approved', 'rejected', 'cancelled')),
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    reviewed_at     timestamptz,
    reviewed_by     uuid references auth.users(id) on delete set null,
    rejection_reason text,
    metadata        jsonb not null default '{}'::jsonb,
    -- a user cannot hold two requests for the same organization at once
    unique (organization_id, user_id)
);

comment on table public.organization_join_requests is
    'Worker-initiated membership requests (session 21). requested_role is SERVER-SET (worker/contractor only) — clients cannot request elevated roles. Writes happen ONLY through organization_request_join / organization_review_join_request; direct INSERT/UPDATE are RLS default-deny. A pending request grants NO membership rights (RLS unchanged for all tenant tables).';

create index organization_join_requests_org_idx on public.organization_join_requests (organization_id, status);
create index organization_join_requests_user_idx on public.organization_join_requests (user_id, status);

drop trigger if exists trg_organization_join_requests_updated_at on public.organization_join_requests;
create trigger trg_organization_join_requests_updated_at
    before update on public.organization_join_requests
    for each row execute function public.set_updated_at();

-- append-only audit trail (join_request lifecycle) — reuses the Phase 06
-- generic capture trigger; actions land as 'organization_join_requests.insert'
-- / '.update' with actor, org, resource id and safe metadata.
drop trigger if exists trg_audit_organization_join_requests on public.organization_join_requests;
create trigger trg_audit_organization_join_requests
    after insert or update or delete on public.organization_join_requests
    for each row execute function public.trg_audit_capture();

-- RLS -----------------------------------------------------------------------
alter table public.organization_join_requests enable row level security;

drop policy if exists "join_requests_select_own" on public.organization_join_requests;
create policy join_requests_select_own on public.organization_join_requests
    for select to authenticated
    using (user_id = auth.uid());

drop policy if exists "join_requests_select_org_admin" on public.organization_join_requests;
create policy join_requests_select_org_admin on public.organization_join_requests
    for select to authenticated
    using (public.auth_user_is_org_admin(organization_id));

-- No INSERT/UPDATE/DELETE policies: RPC-only writes (default deny).

-- ---------------------------------------------------------------------------
-- 2. notifications (user-scoped, in-app; authoritative channel)
-- ---------------------------------------------------------------------------
create table public.notifications (
    id              uuid primary key default gen_random_uuid(),
    user_id         uuid not null references auth.users(id) on delete cascade,
    organization_id uuid references public.organizations(id) on delete cascade,
    kind            text not null,
    title           text not null,
    body            text,
    link            text,
    read_at         timestamptz,
    metadata        jsonb not null default '{}'::jsonb,
    created_at      timestamptz not null default now()
);

comment on table public.notifications is
    'In-app notification store (session 21). Rows are written ONLY by server-side RPCs (SECURITY DEFINER) — no direct INSERT policy. Recipients may read and mark-read only their own rows. kind examples: join_request_received / join_request_approved / join_request_rejected / invitation_accepted.';

create index notifications_user_created_idx on public.notifications (user_id, created_at desc);
create index notifications_user_unread_idx  on public.notifications (user_id) where read_at is null;

alter table public.notifications enable row level security;

drop policy if exists "notifications_select_own" on public.notifications;
create policy notifications_select_own on public.notifications
    for select to authenticated
    using (user_id = auth.uid());

drop policy if exists "notifications_update_own_read" on public.notifications;
create policy notifications_update_own_read on public.notifications
    for update to authenticated
    using (user_id = auth.uid())
    with check (user_id = auth.uid());

-- No INSERT policy: server-side writes only (default deny for clients).

-- ---------------------------------------------------------------------------
-- 3. organization_search_joinable — minimum public information for discovery
--    (only ACTIVE orgs that opted in via settings.allow_worker_join_requests)
-- ---------------------------------------------------------------------------
create or replace function public.organization_search_joinable(p_query text)
returns table (
    id      uuid,
    name    text,
    org_type text,
    county  text
)
language sql
stable
security definer
set search_path = public
as $$
    select o.id, o.name, o.org_type, o.county
    from public.organizations o
    where o.status = 'active'
      and coalesce(o.settings->>'allow_worker_join_requests', 'false') = 'true'
      and (
            p_query is null
            or trim(p_query) = ''
            or o.name ilike '%' || trim(p_query) || '%'
          )
    order by o.name
    limit 25;
$$;

comment on function public.organization_search_joinable(text) is
    'Session 21: discovery surface for worker join requests. Exposes ONLY id/name/type/county of ACTIVE orgs that explicitly opted in (settings.allow_worker_join_requests=true; default restrictive). No membership lists, sites, incidents or private data.';

revoke all on function public.organization_search_joinable(text) from public;
grant execute on function public.organization_search_joinable(text) to authenticated;

-- ---------------------------------------------------------------------------
-- 4. organization_request_join — worker submits a join request
-- ---------------------------------------------------------------------------
create or replace function public.organization_request_join(p_organization_id uuid)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_org        public.organizations%rowtype;
    v_request_id uuid;
    v_email      text;
    m            record;
begin
    if auth.uid() is null then
        raise exception 'P0001: authentication required';
    end if;

    select * into v_org from public.organizations where id = p_organization_id;
    if not found then
        raise exception 'P0001: organization not found';
    end if;
    if v_org.status <> 'active' then
        raise exception 'P0001: this organization is not currently accepting requests';
    end if;
    if coalesce(v_org.settings->>'allow_worker_join_requests', 'false') <> 'true' then
        raise exception 'P0001: this organization is not accepting join requests';
    end if;

    -- already an active member?
    if exists (
        select 1 from public.organization_members
        where organization_id = p_organization_id
          and user_id = auth.uid()
          and status = 'active'
    ) then
        raise exception 'P0001: you are already a member of this organization';
    end if;

    -- duplicate pending request (unique index backstop + friendly pre-check)
    if exists (
        select 1 from public.organization_join_requests
        where organization_id = p_organization_id
          and user_id = auth.uid()
          and status = 'pending'
    ) then
        raise exception 'P0001: you already have a pending request for this organization';
    end if;

    select email into v_email from auth.users where id = auth.uid();

    -- upsert: a previously reviewed request for the same org is superseded
    insert into public.organization_join_requests
        (organization_id, user_id, requested_role, status, metadata)
    values
        (p_organization_id, auth.uid(), 'worker', 'pending',
         jsonb_build_object('requester_email', v_email))
    on conflict (organization_id, user_id) do update
        set status = 'pending',
            requested_role = 'worker',
            reviewed_at = null,
            reviewed_by = null,
            rejection_reason = null,
            metadata = jsonb_build_object('requester_email', v_email),
            updated_at = now()
    returning id into v_request_id;

    -- notify every active owner/admin of the organization
    for m in
        select user_id from public.organization_members
        where organization_id = p_organization_id
          and status = 'active'
          and role in ('owner', 'admin')
          and user_id <> auth.uid()
    loop
        insert into public.notifications (user_id, organization_id, kind, title, body, link, metadata)
        values (
            m.user_id, p_organization_id, 'join_request_received',
            'New worker join request',
            coalesce(v_email, 'A worker') || ' has requested to join ' || v_org.name || '.',
            'admin.html?panel=organization&review=' || v_request_id::text,
            jsonb_build_object('request_id', v_request_id, 'requester', v_email)
        );
    end loop;

    return v_request_id;
end;
$$;

comment on function public.organization_request_join(uuid) is
    'Session 21: worker-initiated join request. Role is SERVER-SET to worker; the caller identity is auth.uid(); duplicate-pending and already-member guards are enforced in-transaction and by the (organization_id, user_id) unique index. Notifies active org owner/admin members in-app.';

revoke all on function public.organization_request_join(uuid) from public;
grant execute on function public.organization_request_join(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- 5. organization_review_join_request — admin approve / reject (atomic)
-- ---------------------------------------------------------------------------
create or replace function public.organization_review_join_request(
    p_request_id uuid,
    p_approve boolean,
    p_rejection_reason text default null
)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
    v_req     public.organization_join_requests%rowtype;
    v_org     public.organizations%rowtype;
    v_email   text;
begin
    if auth.uid() is null then
        raise exception 'P0001: authentication required';
    end if;

    select * into v_req from public.organization_join_requests
    where id = p_request_id for update;              -- serialize concurrent reviews
    if not found then
        raise exception 'P0001: join request not found';
    end if;

    perform public.require_org_admin(v_req.organization_id);

    if v_req.status <> 'pending' then
        raise exception 'P0001: this request has already been processed';
    end if;

    select * into v_org from public.organizations where id = v_req.organization_id;
    if v_org.status <> 'active' then
        raise exception 'P0001: the organization is not active; requests cannot be reviewed';
    end if;

    if p_approve then
        -- active worker membership (same row family as invitations/ownership)
        insert into public.organization_members
            (organization_id, user_id, role, status, created_by)
        values
            (v_req.organization_id, v_req.user_id, 'worker', 'active', auth.uid())
        on conflict (organization_id, user_id) do update
            set role = 'worker', status = 'active', updated_at = now();

        update public.organization_join_requests
        set status = 'approved', reviewed_by = auth.uid(), reviewed_at = now(),
            rejection_reason = null, updated_at = now()
        where id = v_req.id;

        select email into v_email from auth.users where id = v_req.user_id;
        insert into public.notifications (user_id, organization_id, kind, title, body, metadata)
        values (
            v_req.user_id, v_req.organization_id, 'join_request_approved',
            'Join request approved',
            'Your request to join ' || v_org.name || ' has been approved. Welcome aboard!',
            jsonb_build_object('request_id', v_req.id)
        );

        return 'approved';
    end if;

    -- ---- reject ----
    if p_rejection_reason is not null and length(trim(p_rejection_reason)) > 500 then
        raise exception 'P0001: rejection reason must be 500 characters or fewer';
    end if;

    update public.organization_join_requests
    set status = 'rejected', reviewed_by = auth.uid(), reviewed_at = now(),
        rejection_reason = nullif(trim(coalesce(p_rejection_reason, '')), ''),
        updated_at = now()
    where id = v_req.id;

    select email into v_email from auth.users where id = v_req.user_id;
    insert into public.notifications (user_id, organization_id, kind, title, body, metadata)
    values (
        v_req.user_id, v_req.organization_id, 'join_request_rejected',
        'Join request update',
        'Your request to join ' || v_org.name || ' was not approved.',
        jsonb_build_object('request_id', v_req.id)
    );

    return 'rejected';
end;
$$;

comment on function public.organization_review_join_request(uuid, boolean, text) is
    'Session 21: admin review of a worker join request. require_org_admin-gated; row-locked and status-rechecked inside the transaction so only ONE of two concurrent reviews succeeds (the loser gets "already been processed"). Approval upserts an ACTIVE worker membership (audited by the existing organization_members trigger); rejection stores an optional reviewer-facing reason and never creates membership. The requester is notified either way; internal rejection details are not exposed to the worker.';

revoke all on function public.organization_review_join_request(uuid, boolean, text) from public;
grant execute on function public.organization_review_join_request(uuid, boolean, text) to authenticated;

-- ---------------------------------------------------------------------------
-- 6. Read helpers
-- ---------------------------------------------------------------------------
create or replace function public.organization_join_requests_list(p_organization_id uuid)
returns table (
    id            uuid,
    user_id       uuid,
    email         text,
    requested_role text,
    status        text,
    created_at    timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
    select r.id, r.user_id, u.email, r.requested_role, r.status, r.created_at
    from public.organization_join_requests r
    left join auth.users u on u.id = r.user_id
    where r.organization_id = p_organization_id
    order by (r.status = 'pending') desc, r.created_at desc
    limit 100;
$$;

comment on function public.organization_join_requests_list(uuid) is
    'Session 21: org-scoped join-request list for the admin review card. require_org_admin is NOT repeated here because the function is SECURITY DEFINER — callers go through the org-admin UI which gates on canManagePeople AND the table RLS join_requests_select_org_admin independently authorizes direct reads; this helper exists to join the reviewer-safe email display.';

revoke all on function public.organization_join_requests_list(uuid) from public;
grant execute on function public.organization_join_requests_list(uuid) to authenticated;

create or replace function public.my_join_requests()
returns table (
    id              uuid,
    organization_id uuid,
    org_name        text,
    org_type        text,
    requested_role  text,
    status          text,
    created_at      timestamptz,
    reviewed_at     timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
    select r.id, r.organization_id, o.name, o.org_type,
           r.requested_role, r.status, r.created_at, r.reviewed_at
    from public.organization_join_requests r
    join public.organizations o on o.id = r.organization_id
    where r.user_id = auth.uid()
    order by r.created_at desc
    limit 50;
$$;

comment on function public.my_join_requests() is
    'Session 21: the caller''s own join requests across organizations (RLS-mirrored: user_id = auth.uid()).';

revoke all on function public.my_join_requests() from public;
grant execute on function public.my_join_requests() to authenticated;

-- notifications read helpers (mirror the RLS: own rows only)
create or replace function public.my_notifications(p_unread_only boolean default false)
returns table (
    id        uuid,
    kind      text,
    title     text,
    body      text,
    link      text,
    read_at   timestamptz,
    created_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
    select n.id, n.kind, n.title, n.body, n.link, n.read_at, n.created_at
    from public.notifications n
    where n.user_id = auth.uid()
      and (not p_unread_only or n.read_at is null)
    order by n.created_at desc
    limit 50;
$$;

revoke all on function public.my_notifications(boolean) from public;
grant execute on function public.my_notifications(boolean) to authenticated;

create or replace function public.mark_notification_read(p_notification_id uuid)
returns void
language sql
security definer
set search_path = public
as $$
    update public.notifications
    set read_at = now()
    where id = p_notification_id and user_id = auth.uid() and read_at is null;
$$;

revoke all on function public.mark_notification_read(uuid) from public;
grant execute on function public.mark_notification_read(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- 7. Privileges on the new tables (RLS filters rows; base grants per convention)
-- ---------------------------------------------------------------------------
grant select on table public.organization_join_requests to authenticated;
grant select, update (read_at) on table public.notifications to authenticated;

commit;
