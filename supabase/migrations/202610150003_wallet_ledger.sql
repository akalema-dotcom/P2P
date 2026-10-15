-- Internal sandbox ledger foundation.
-- This is NOT a custody system and does not represent real blockchain balances.
-- Production custody must be implemented separately with qualified custody/payment
-- providers, compliance controls, reconciliation, and security review.

create type public.p2p_ledger_entry_type as enum ('credit', 'debit', 'hold', 'release_hold', 'capture_hold');

create table public.p2p_wallets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete restrict,
  asset_code text not null references public.p2p_supported_assets(code) on delete restrict,
  available numeric(36,18) not null default 0 check (available >= 0),
  held numeric(36,18) not null default 0 check (held >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(user_id, asset_code)
);

create table public.p2p_ledger_entries (
  id bigint generated always as identity primary key,
  wallet_id uuid not null references public.p2p_wallets(id) on delete restrict,
  order_id uuid references public.p2p_orders(id) on delete restrict,
  entry_type public.p2p_ledger_entry_type not null,
  amount numeric(36,18) not null check (amount > 0),
  balance_available_after numeric(36,18) not null check (balance_available_after >= 0),
  balance_held_after numeric(36,18) not null check (balance_held_after >= 0),
  reference text not null,
  created_at timestamptz not null default now()
);
create index p2p_wallets_user_idx on public.p2p_wallets(user_id, asset_code);
create index p2p_ledger_wallet_idx on public.p2p_ledger_entries(wallet_id, created_at);
create index p2p_ledger_order_idx on public.p2p_ledger_entries(order_id, created_at);

alter table public.p2p_wallets enable row level security;
alter table public.p2p_ledger_entries enable row level security;
revoke all on public.p2p_wallets, public.p2p_ledger_entries from anon, authenticated;
grant select on public.p2p_wallets to authenticated;
grant select on public.p2p_ledger_entries to authenticated;

create policy "Users can read their own sandbox wallets"
  on public.p2p_wallets for select to authenticated
  using (user_id = (select auth.uid()));

create policy "Users can read their own sandbox ledger"
  on public.p2p_ledger_entries for select to authenticated
  using (
    exists (
      select 1 from public.p2p_wallets w
      where w.id = wallet_id and w.user_id = (select auth.uid())
    )
  );

-- The client cannot mutate wallet balances or ledger entries directly.
revoke insert, update, delete on public.p2p_wallets, public.p2p_ledger_entries from anon, authenticated;

create or replace function public.get_or_create_sandbox_wallet(p_asset_code text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_wallet uuid;
  v_code text := upper(trim(p_asset_code));
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if not exists (
    select 1 from public.p2p_supported_assets
    where code = v_code and enabled = true
  ) then
    raise exception 'Asset is not enabled for trading' using errcode = '55000';
  end if;

  insert into public.p2p_wallets(user_id, asset_code)
  values (v_user, v_code)
  on conflict (user_id, asset_code) do nothing
  returning id into v_wallet;

  if v_wallet is null then
    select id into v_wallet
    from public.p2p_wallets
    where user_id = v_user and asset_code = v_code;
  end if;
  return v_wallet;
end;
$$;

revoke all on function public.get_or_create_sandbox_wallet(text) from public, anon;
grant execute on function public.get_or_create_sandbox_wallet(text) to authenticated;

-- Controlled sandbox funding for development only. It is deliberately capped and
-- cannot be used as a representation of real funds.
create or replace function public.credit_sandbox_wallet(p_asset_code text, p_amount numeric)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_wallet public.p2p_wallets%rowtype;
  v_code text := upper(trim(p_asset_code));
  v_amount numeric := p_amount;
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if v_amount is null or v_amount <= 0 or v_amount > 100000 then
    raise exception 'Sandbox credit must be between 0 and 100000 units' using errcode = '22023';
  end if;
  if not exists (select 1 from public.p2p_supported_assets where code=v_code and enabled=true) then
    raise exception 'Asset is not enabled for trading' using errcode = '55000';
  end if;

  insert into public.p2p_wallets(user_id, asset_code)
  values (v_user, v_code)
  on conflict (user_id, asset_code) do nothing;

  select * into v_wallet
  from public.p2p_wallets
  where user_id=v_user and asset_code=v_code
  for update;

  if v_wallet.available + v_amount > 100000 then
    raise exception 'Sandbox wallet cap exceeded' using errcode = '22023';
  end if;

  update public.p2p_wallets
  set available=available+v_amount, updated_at=now()
  where id=v_wallet.id;

  insert into public.p2p_ledger_entries(wallet_id,entry_type,amount,balance_available_after,balance_held_after,reference)
  values (v_wallet.id,'credit',v_amount,v_wallet.available+v_amount,v_wallet.held,'sandbox_funding');

  return v_wallet.id;
end;
$$;

revoke all on function public.credit_sandbox_wallet(text,numeric) from public, anon;
grant execute on function public.credit_sandbox_wallet(text,numeric) to authenticated;
