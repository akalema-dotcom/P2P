-- Initial P2P marketplace schema.
-- All orders created by this migration are sandbox records. No crypto is held,
-- no payment is verified, and no asset is released by this database workflow.

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create type public.p2p_ad_side as enum ('buy', 'sell');
create type public.p2p_ad_status as enum ('draft', 'active', 'paused', 'closed');
create type public.p2p_order_status as enum (
  'awaiting_payment',
  'payment_marked',
  'disputed',
  'completed',
  'cancelled',
  'expired'
);

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'Trader' check (char_length(display_name) between 1 and 40),
  avatar_url text,
  country_code text check (country_code is null or country_code ~ '^[A-Z]{2}$'),
  verification_status text not null default 'unverified'
    check (verification_status in ('unverified', 'pending', 'verified', 'rejected')),
  account_status text not null default 'active'
    check (account_status in ('active', 'suspended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.p2p_ads (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete restrict,
  side public.p2p_ad_side not null,
  asset_code text not null check (asset_code ~ '^[A-Z0-9]{2,12}$'),
  fiat_currency text not null check (fiat_currency ~ '^[A-Z]{3}$'),
  price numeric(24, 10) not null check (price > 0),
  min_fiat_amount numeric(24, 8) not null check (min_fiat_amount > 0),
  max_fiat_amount numeric(24, 8) not null check (max_fiat_amount >= min_fiat_amount),
  total_quantity numeric(24, 10) not null check (total_quantity > 0),
  available_quantity numeric(24, 10) not null check (available_quantity >= 0 and available_quantity <= total_quantity),
  payment_method_types text[] not null
    check (
      cardinality(payment_method_types) between 1 and 8
      and payment_method_types <@ array['bank_transfer', 'mobile_money', 'digital_wallet', 'other']::text[]
    ),
  terms text not null default '' check (char_length(terms) <= 2000),
  status public.p2p_ad_status not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (min_fiat_amount <= max_fiat_amount)
);

create index p2p_ads_marketplace_idx
  on public.p2p_ads (fiat_currency, asset_code, side, price)
  where status = 'active';
create index p2p_ads_owner_idx on public.p2p_ads (owner_id, created_at desc);

create table public.p2p_orders (
  id uuid primary key default gen_random_uuid(),
  ad_id uuid not null references public.p2p_ads(id) on delete restrict,
  buyer_id uuid not null references public.profiles(id) on delete restrict,
  seller_id uuid not null references public.profiles(id) on delete restrict,
  asset_code text not null check (asset_code ~ '^[A-Z0-9]{2,12}$'),
  fiat_currency text not null check (fiat_currency ~ '^[A-Z]{3}$'),
  price numeric(24, 10) not null check (price > 0),
  asset_quantity numeric(24, 10) not null check (asset_quantity > 0),
  fiat_amount numeric(24, 8) not null check (fiat_amount > 0),
  status public.p2p_order_status not null default 'awaiting_payment',
  is_sandbox boolean not null default true check (is_sandbox = true),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (buyer_id <> seller_id)
);

create index p2p_orders_buyer_idx on public.p2p_orders (buyer_id, created_at desc);
create index p2p_orders_seller_idx on public.p2p_orders (seller_id, created_at desc);
create index p2p_orders_ad_idx on public.p2p_orders (ad_id);

create table public.p2p_order_events (
  id bigint generated always as identity primary key,
  order_id uuid not null references public.p2p_orders(id) on delete restrict,
  actor_id uuid references public.profiles(id) on delete set null,
  event_type text not null check (char_length(event_type) between 1 and 80),
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index p2p_order_events_order_idx on public.p2p_order_events (order_id, created_at);

create table public.p2p_order_messages (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.p2p_orders(id) on delete restrict,
  author_id uuid not null references public.profiles(id) on delete restrict,
  body text not null check (char_length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);
create index p2p_order_messages_order_idx on public.p2p_order_messages (order_id, created_at);

-- Profiles contain only fields intended for public display; never store email,
-- payment account numbers, identity documents, or secrets in this table.
alter table public.profiles enable row level security;
alter table public.p2p_ads enable row level security;
alter table public.p2p_orders enable row level security;
alter table public.p2p_order_events enable row level security;
alter table public.p2p_order_messages enable row level security;

revoke all on public.profiles, public.p2p_ads, public.p2p_orders,
  public.p2p_order_events, public.p2p_order_messages from anon, authenticated;
grant select on public.profiles to anon, authenticated;
grant update (display_name, avatar_url, country_code) on public.profiles to authenticated;
grant select on public.p2p_ads to anon, authenticated;
grant select on public.p2p_orders, public.p2p_order_events, public.p2p_order_messages to authenticated;
grant insert on public.p2p_order_messages to authenticated;
grant usage, select on sequence public.p2p_order_events_id_seq to authenticated;

create policy "Public profiles are readable"
  on public.profiles for select to anon, authenticated using (true);
create policy "Users update their own public profile"
  on public.profiles for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

create policy "Active ads are public; owners can see their own ads"
  on public.p2p_ads for select to anon, authenticated
  using (status = 'active' or owner_id = (select auth.uid()));

create policy "Order participants can read orders"
  on public.p2p_orders for select to authenticated
  using ((select auth.uid()) = buyer_id or (select auth.uid()) = seller_id);
create policy "Order participants can read order events"
  on public.p2p_order_events for select to authenticated
  using (
    exists (
      select 1 from public.p2p_orders o
      where o.id = order_id
        and ((select auth.uid()) = o.buyer_id or (select auth.uid()) = o.seller_id)
    )
  );
create policy "Order participants can read messages"
  on public.p2p_order_messages for select to authenticated
  using (
    exists (
      select 1 from public.p2p_orders o
      where o.id = order_id
        and ((select auth.uid()) = o.buyer_id or (select auth.uid()) = o.seller_id)
    )
  );
create policy "Participants can send messages on their orders"
  on public.p2p_order_messages for insert to authenticated
  with check (
    author_id = (select auth.uid())
    and exists (
      select 1 from public.p2p_orders o
      where o.id = order_id
        and o.status in ('awaiting_payment', 'payment_marked', 'disputed')
        and ((select auth.uid()) = o.buyer_id or (select auth.uid()) = o.seller_id)
    )
  );

-- New auth users get a safe public profile. User metadata is untrusted input.
create or replace function private.create_profile_for_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    coalesce(nullif(left(btrim(new.raw_user_meta_data ->> 'display_name'), 40), ''), 'Trader')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

revoke all on function private.create_profile_for_new_user() from public, anon, authenticated;

create trigger on_auth_user_created_create_profile
  after insert on auth.users
  for each row execute function private.create_profile_for_new_user();

-- Create a marketplace advertisement. Ads are data listings only; they do not
-- prove the owner controls the advertised asset.
create or replace function public.create_p2p_ad(
  p_side text,
  p_asset_code text,
  p_fiat_currency text,
  p_price numeric,
  p_min_fiat_amount numeric,
  p_max_fiat_amount numeric,
  p_total_quantity numeric,
  p_payment_method_types text[],
  p_terms text default ''
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_ad_id uuid;
  v_side public.p2p_ad_side;
  v_methods text[];
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if not exists (
    select 1 from public.profiles p
    where p.id = v_user and p.account_status = 'active'
  ) then
    raise exception 'Active account required' using errcode = '42501';
  end if;

  begin
    v_side := lower(p_side)::public.p2p_ad_side;
  exception when others then
    raise exception 'Side must be buy or sell' using errcode = '22023';
  end;

  if p_asset_code is null or upper(p_asset_code) !~ '^[A-Z0-9]{2,12}$'
     or p_fiat_currency is null or upper(p_fiat_currency) !~ '^[A-Z]{3}$' then
    raise exception 'Invalid asset or fiat currency code' using errcode = '22023';
  end if;
  if p_price is null or p_price <= 0
     or p_min_fiat_amount is null or p_min_fiat_amount <= 0
     or p_max_fiat_amount is null or p_max_fiat_amount < p_min_fiat_amount
     or p_total_quantity is null or p_total_quantity <= 0 then
    raise exception 'Price, quantity, and order limits must be positive and consistent' using errcode = '22023';
  end if;
  if p_payment_method_types is null or cardinality(p_payment_method_types) < 1
     or cardinality(p_payment_method_types) > 8
     or not (p_payment_method_types <@ array['bank_transfer', 'mobile_money', 'digital_wallet', 'other']::text[]) then
    raise exception 'Choose one to eight supported payment method types' using errcode = '22023';
  end if;
  if coalesce(char_length(p_terms), 0) > 2000 then
    raise exception 'Terms cannot exceed 2000 characters' using errcode = '22023';
  end if;

  select array_agg(distinct m order by m) into v_methods
  from unnest(p_payment_method_types) as u(m);

  insert into public.p2p_ads (
    owner_id, side, asset_code, fiat_currency, price,
    min_fiat_amount, max_fiat_amount, total_quantity, available_quantity,
    payment_method_types, terms
  )
  values (
    v_user, v_side, upper(p_asset_code), upper(p_fiat_currency), p_price,
    p_min_fiat_amount, p_max_fiat_amount, p_total_quantity, p_total_quantity,
    v_methods, coalesce(p_terms, '')
  )
  returning id into v_ad_id;

  return v_ad_id;
end;
$$;

-- Creates a sandbox order and reserves quantity atomically. This is not an
-- escrow service and does not verify a bank/mobile-money payment or release crypto.
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

  if not exists (
    select 1 from public.profiles p
    where p.id = v_ad.owner_id and p.account_status = 'active'
  ) then
    raise exception 'Advertisement owner is not eligible to trade' using errcode = '42501';
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

  insert into public.p2p_order_events (order_id, actor_id, event_type, details)
  values (
    v_order_id, v_user, 'sandbox_order_created',
    jsonb_build_object('ad_id', v_ad.id, 'quantity', p_asset_quantity, 'is_sandbox', true)
  );

  return v_order_id;
end;
$$;

revoke all on function public.create_p2p_ad(text, text, text, numeric, numeric, numeric, numeric, text[], text) from public, anon;
revoke all on function public.create_p2p_order(uuid, numeric) from public, anon;
grant execute on function public.create_p2p_ad(text, text, text, numeric, numeric, numeric, numeric, text[], text) to authenticated;
grant execute on function public.create_p2p_order(uuid, numeric) to authenticated;
