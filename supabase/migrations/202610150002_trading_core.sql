-- Trading core for the independent P2P marketplace.
-- This remains sandbox-only until custody, payments, compliance, and production
-- controls are separately approved and implemented.

create type public.p2p_order_event_type as enum (
  'created',
  'payment_marked',
  'payment_unmarked',
  'cancelled',
  'disputed',
  'completed',
  'expired'
);

create table public.p2p_supported_assets (
  code text primary key check (code ~ '^[A-Z0-9]{2,12}$'),
  name text not null check (char_length(name) between 1 and 80),
  decimals smallint not null default 8 check (decimals between 0 and 18),
  enabled boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.p2p_payment_methods (
  id uuid primary key default gen_random_uuid(),
  code text not null unique check (code ~ '^[a-z0-9_]{3,40}$'),
  name text not null check (char_length(name) between 1 and 80),
  enabled boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.p2p_ad_payment_methods (
  ad_id uuid not null references public.p2p_ads(id) on delete cascade,
  payment_method_id uuid not null references public.p2p_payment_methods(id) on delete restrict,
  primary key (ad_id, payment_method_id)
);

create table public.p2p_order_state_history (
  id bigint generated always as identity primary key,
  order_id uuid not null references public.p2p_orders(id) on delete restrict,
  from_status public.p2p_order_status,
  to_status public.p2p_order_status not null,
  actor_id uuid references public.profiles(id) on delete set null,
  reason text not null default '' check (char_length(reason) <= 500),
  created_at timestamptz not null default now()
);
create index p2p_order_state_history_order_idx
  on public.p2p_order_state_history(order_id, created_at);

-- Seed only non-production configuration. Assets/payment methods are disabled
-- until the operator explicitly enables them.
insert into public.p2p_supported_assets(code, name, decimals, enabled)
values ('USDT', 'Tether USD', 6, false), ('BTC', 'Bitcoin', 8, false)
on conflict (code) do nothing;

insert into public.p2p_payment_methods(code, name, enabled)
values
  ('bank_transfer', 'Bank Transfer', false),
  ('mobile_money', 'Mobile Money', false),
  ('digital_wallet', 'Digital Wallet', false)
on conflict (code) do nothing;

alter table public.p2p_supported_assets enable row level security;
alter table public.p2p_payment_methods enable row level security;
alter table public.p2p_ad_payment_methods enable row level security;
alter table public.p2p_order_state_history enable row level security;

revoke all on public.p2p_supported_assets, public.p2p_payment_methods,
  public.p2p_ad_payment_methods, public.p2p_order_state_history
from anon, authenticated;

grant select on public.p2p_supported_assets, public.p2p_payment_methods to anon, authenticated;
grant select on public.p2p_ad_payment_methods, public.p2p_order_state_history to authenticated;

grant select on public.p2p_supported_assets, public.p2p_payment_methods
  to anon, authenticated;

create policy "Enabled assets are publicly readable"
  on public.p2p_supported_assets for select to anon, authenticated
  using (enabled = true);

create policy "Enabled payment methods are publicly readable"
  on public.p2p_payment_methods for select to anon, authenticated
  using (enabled = true);

create policy "Order participants can read ad payment methods"
  on public.p2p_ad_payment_methods for select to authenticated
  using (
    exists (
      select 1 from public.p2p_orders o
      where o.ad_id = ad_id
        and ((select auth.uid()) = o.buyer_id or (select auth.uid()) = o.seller_id)
    )
    or exists (
      select 1 from public.p2p_ads a
      where a.id = ad_id and a.owner_id = (select auth.uid())
    )
  );

create policy "Order participants can read state history"
  on public.p2p_order_state_history for select to authenticated
  using (
    exists (
      select 1 from public.p2p_orders o
      where o.id = order_id
        and ((select auth.uid()) = o.buyer_id or (select auth.uid()) = o.seller_id)
    )
  );

-- Replace the first order RPC with a stricter version that validates the asset
-- against the supported-asset registry. It still creates sandbox orders only.
create or replace function public.create_p2p_order(
  p_ad_id uuid,
  p_asset_quantity numeric
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_ad public.p2p_ads%rowtype;
  v_order_id uuid;
  v_buyer_id uuid;
  v_seller_id uuid;
  v_fiat_amount numeric;
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if p_asset_quantity is null or p_asset_quantity <= 0 then
    raise exception 'Asset quantity must be positive' using errcode = '22023';
  end if;

  if not exists (
    select 1 from public.profiles p
    where p.id = v_user and p.account_status = 'active'
  ) then
    raise exception 'Active account required' using errcode = '42501';
  end if;

  select * into v_ad
  from public.p2p_ads a
  where a.id = p_ad_id
  for update;

  if not found then
    raise exception 'Advertisement not found' using errcode = 'P0002';
  end if;
  if v_ad.status <> 'active' then
    raise exception 'Advertisement is not active' using errcode = '55000';
  end if;
  if not exists (
    select 1 from public.p2p_supported_assets sa
    where sa.code = v_ad.asset_code and sa.enabled = true
  ) then
    raise exception 'Asset is not enabled for trading' using errcode = '55000';
  end if;
  if v_ad.owner_id = v_user then
    raise exception 'You cannot trade against your own advertisement' using errcode = '22023';
  end if;
  if v_ad.available_quantity < p_asset_quantity then
    raise exception 'Insufficient available quantity' using errcode = '22023';
  end if;

  v_fiat_amount := p_asset_quantity * v_ad.price;
  if v_fiat_amount < v_ad.min_fiat_amount or v_fiat_amount > v_ad.max_fiat_amount then
    raise exception 'Order value is outside this advertisement limits' using errcode = '22023';
  end if;

  if v_ad.side = 'sell' then
    v_buyer_id := v_user;
    v_seller_id := v_ad.owner_id;
  else
    v_buyer_id := v_ad.owner_id;
    v_seller_id := v_user;
  end if;

  update public.p2p_ads
  set available_quantity = available_quantity - p_asset_quantity,
      status = case when available_quantity - p_asset_quantity = 0
                    then 'closed'::public.p2p_ad_status else status end,
      updated_at = now()
  where id = v_ad.id;

  insert into public.p2p_orders (
    ad_id, buyer_id, seller_id, asset_code, fiat_currency, price,
    asset_quantity, fiat_amount, status, is_sandbox, expires_at
  )
  values (
    v_ad.id, v_buyer_id, v_seller_id, v_ad.asset_code, v_ad.fiat_currency, v_ad.price,
    p_asset_quantity, v_fiat_amount, 'awaiting_payment', true, now() + interval '15 minutes'
  )
  returning id into v_order_id;

  insert into public.p2p_order_events(order_id, actor_id, event_type, details)
  values (
    v_order_id, v_user, 'sandbox_order_created',
    jsonb_build_object('ad_id', v_ad.id, 'quantity', p_asset_quantity, 'is_sandbox', true)
  );

  insert into public.p2p_order_state_history(order_id, from_status, to_status, actor_id, reason)
  values (v_order_id, null, 'awaiting_payment', v_user, 'Order created');

  return v_order_id;
end;
$$;

-- Centralized order transition function. Clients never update order status directly.
create or replace function public.transition_p2p_order(
  p_order_id uuid,
  p_target_status text,
  p_reason text default ''
)
returns public.p2p_order_status
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_order public.p2p_orders%rowtype;
  v_target public.p2p_order_status;
  v_allowed boolean := false;
  v_returned boolean := false;
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  begin
    v_target := lower(p_target_status)::public.p2p_order_status;
  exception when others then
    raise exception 'Invalid target order status' using errcode = '22023';
  end;

  select * into v_order
  from public.p2p_orders
  where id = p_order_id
  for update;

  if not found then
    raise exception 'Order not found' using errcode = 'P0002';
  end if;
  if v_user <> v_order.buyer_id and v_user <> v_order.seller_id then
    raise exception 'You are not a participant in this order' using errcode = '42501';
  end if;
  if char_length(coalesce(p_reason, '')) > 500 then
    raise exception 'Reason is too long' using errcode = '22023';
  end if;

  -- Sandbox state machine. Production payment verification/release is intentionally absent.
  if v_order.status = 'awaiting_payment' and v_target = 'payment_marked' and v_user = v_order.buyer_id then
    v_allowed := true;
  elsif v_order.status = 'payment_marked' and v_target = 'awaiting_payment' and v_user = v_order.buyer_id then
    v_allowed := true;
  elsif v_order.status in ('awaiting_payment', 'payment_marked') and v_target = 'cancelled' then
    v_allowed := true;
  elsif v_order.status in ('awaiting_payment', 'payment_marked') and v_target = 'disputed' then
    v_allowed := true;
  else
    raise exception 'Invalid order state transition' using errcode = '55000';
  end if;

  update public.p2p_orders
  set status = v_target, updated_at = now()
  where id = p_order_id;

  insert into public.p2p_order_state_history(order_id, from_status, to_status, actor_id, reason)
  values (p_order_id, v_order.status, v_target, v_user, coalesce(p_reason, ''));

  insert into public.p2p_order_events(order_id, actor_id, event_type, details)
  values (
    p_order_id,
    v_user,
    case v_target
      when 'payment_marked' then 'payment_marked'
      when 'awaiting_payment' then 'payment_unmarked'
      when 'cancelled' then 'cancelled'
      when 'disputed' then 'disputed'
      else 'created'
    end,
    jsonb_build_object('from', v_order.status, 'to', v_target, 'reason', coalesce(p_reason, ''))
  );

  if v_target = 'cancelled' then
    update public.p2p_ads
    set available_quantity = least(total_quantity, available_quantity + v_order.asset_quantity),
        status = case when status = 'closed' then 'active'::public.p2p_ad_status else status end,
        updated_at = now()
    where id = v_order.ad_id;
  end if;

  return v_target;
end;
$$;

revoke all on function public.transition_p2p_order(uuid, text, text) from public, anon;
grant execute on function public.transition_p2p_order(uuid, text, text) to authenticated;

-- Never expose direct mutation of the new order history/state tables.
revoke insert, update, delete on public.p2p_order_state_history from anon, authenticated;
revoke insert, update, delete on public.p2p_ad_payment_methods from anon, authenticated;
