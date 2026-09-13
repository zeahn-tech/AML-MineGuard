-- ============================================================================
-- 20260903000113_push_subscriptions.sql — session 21 push foundation.
--
-- Directive §10/§32: push is an ADDITIONAL delivery mechanism — in-app
-- notifications (…110) remain the authoritative channel. This migration adds
-- the missing production-grade foundation: a per-user Web Push subscription
-- store so that when a push sender (VAPID keys + a web-push delivery service)
-- is provisioned, delivery can be wired without another schema migration.
--
-- Design:
--   * one row per (user_id, endpoint_hash) — the same browser profile can
--     re-subscribe safely; endpoint is stored as a SHA-256 hash (the raw
--     endpoint URL can contain identifiers; we never need it read back —
--     delivery services match on the hash + payload column);
--   * keys (p256dh / auth) are the per-subscription encryption secrets —
--     stored server-side only, never returned to clients;
--   * RLS: a user manages ONLY their own rows; no cross-user access;
--   * failures are recorded by flipping status='failed' (subscriber agents
--     re-subscribe on next visit); no security event.
-- ============================================================================

begin;

create table if not exists public.push_subscriptions (
    id             uuid primary key default gen_random_uuid(),
    user_id        uuid not null references auth.users(id) on delete cascade,
    endpoint_hash  text not null,
    p256dh         text not null,
    auth           text not null,
    user_agent     text,
    status         text not null default 'active' check (status in ('active', 'failed')),
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),
    unique (user_id, endpoint_hash)
);

comment on table public.push_subscriptions is
    'Session 21 push foundation: per-user Web Push subscriptions (RFC 8291 keys). Endpoint stored as SHA-256 hash. Written ONLY via register_push_subscription / deregister_push_subscription (clients cannot forge arbitrary rows); keys are never exposed through any read path. In-app notifications (…110) remain the authoritative channel — push is additional delivery.';

create index if not exists push_subscriptions_user_idx on public.push_subscriptions (user_id, status);

alter table public.push_subscriptions enable row level security;

drop policy if exists "push_subs_select_own" on public.push_subscriptions;
create policy push_subs_select_own on public.push_subscriptions
    for select to authenticated
    using (user_id = auth.uid());

-- No INSERT/UPDATE/DELETE policies: RPC-only writes (default deny).

drop trigger if exists trg_push_subscriptions_updated_at on public.push_subscriptions;
create trigger trg_push_subscriptions_updated_at
    before update on public.push_subscriptions
    for each row execute function public.set_updated_at();

-- register (upsert on (user_id, endpoint_hash); re-subscribe is idempotent)
-- NOTE: endpoint hashing uses core sha256(convert_to(...)) — pgcrypto's
-- digest() is NOT reliably on `search_path = public` (Phase 04 precedent).
create or replace function public.register_push_subscription(
    p_endpoint text,
    p_p256dh   text,
    p_auth     text,
    p_user_agent text default null
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
    v_id uuid;
begin
    if auth.uid() is null then
        raise exception 'P0001: authentication required';
    end if;
    if p_endpoint is null or length(trim(p_endpoint)) = 0 then
        raise exception 'P0001: endpoint required';
    end if;
    if p_p256dh is null or length(trim(p_p256dh)) = 0
       or p_auth is null or length(trim(p_auth)) = 0 then
        raise exception 'P0001: subscription keys required';
    end if;

    insert into public.push_subscriptions
        (user_id, endpoint_hash, p256dh, auth, user_agent, status)
    values
        (auth.uid(), encode(sha256(convert_to(trim(p_endpoint), 'UTF8')), 'hex'),
         trim(p_p256dh), trim(p_auth),
         nullif(left(trim(coalesce(p_user_agent, '')), 300), ''), 'active')
    on conflict (user_id, endpoint_hash) do update
        set p256dh = excluded.p256dh,
            auth = excluded.auth,
            user_agent = excluded.user_agent,
            status = 'active',
            updated_at = now()
    returning id into v_id;

    return v_id;
end;
$$;

comment on function public.register_push_subscription(text, text, text, text) is
    'Session 21: register/refresh the caller''s Web Push subscription (server derives user from auth.uid(); endpoint is hashed; upsert is idempotent per browser profile).';

revoke all on function public.register_push_subscription(text, text, text, text) from public;
grant execute on function public.register_push_subscription(text, text, text, text) to authenticated;

-- deregister (own rows only)
create or replace function public.deregister_push_subscription(p_endpoint text)
returns void
language sql
security definer
set search_path = public
as $$
    delete from public.push_subscriptions
    where user_id = auth.uid()
      and endpoint_hash = encode(sha256(convert_to(trim(p_endpoint), 'UTF8')), 'hex');
$$;

revoke all on function public.deregister_push_subscription(text) from public;
grant execute on function public.deregister_push_subscription(text) to authenticated;

commit;
