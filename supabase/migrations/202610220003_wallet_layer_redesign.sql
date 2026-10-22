-- Wallet layer redesign: Main Wallet + Sub-Wallet/Worker architecture.
-- Sandbox accounting only. No private keys, blockchain custody, or real withdrawals
-- are implemented by this migration.

create type public.wallet_account_scope as enum (
  'user_available',
  'user_held',
  'treasury_sandbox'
);

create type public.wallet_entry_type as enum (
  'credit',
  'debit',
  'hold',
  'release',
  'settlement',
  'refund',
  'adjustment'
);

create type public.wallet_hold_status as enum (
  'active',
  'released',
  'consumed',
  'cancelled'
);

create type public.wallet_job_status as enum (
  'queued',
  'processing',
  'completed',
  'failed',
  'cancelled'
);

create table public.wallet_accounts (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid references public.profiles(id) on delete restrict,
  asset_code text not null check (asset_code ~ '^[A-Z0-9]{2,12}$'),
  scope public.wallet_account_scope not null,
  available_balance numeric(38, 18) not null default 0 check (available_balance >= 0),
  held_balance numeric(38, 18) not null default 0 check (held_balance >= 0),
  version bigint not null default 0 check (version >= 0),
  is_sandbox boolean not null default true check (is_sandbox = true),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((scope = 'treasury_sandbox' and owner_id is null) or
         (scope in ('user_available', 'user_held') and owner_id is not null)),
  unique(owner_id, asset_code, scope)
);

create index wallet_accounts_owner_idx
  on public.wallet_accounts(owner_id, asset_code);

create table public.wallet_ledger_entries (
  id bigint generated always as identity primary key,
  account_id uuid not null references public.wallet_accounts(id) on delete restrict,
  asset_code text not null check (asset_code ~ '^[A-Z0-9]{2,12}$'),
  entry_type public.wallet_entry_type not null,
  amount numeric(38, 18) not null check (amount > 0),
  balance_after numeric(38, 18) not null check (balance_after >= 0),
  reference_type text not null check (reference_type ~ '^[a-z_]{2,40}$'),
  reference_id uuid,
  idempotency_key text not null unique check (char_length(idempotency_key) between 8 and 120),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index wallet_ledger_account_idx
  on public.wallet_ledger_entries(account_id, id desc);
create index wallet_ledger_reference_idx
  on public.wallet_ledger_entries(reference_type, reference_id);

create table public.wallet_holds (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references public.wallet_accounts(id) on delete restrict,
  order_id uuid references public.p2p_orders(id) on delete restrict,
  amount numeric(38, 18) not null check (amount > 0),
  status public.wallet_hold_status not null default 'active',
  reason text not null default 'p2p_order' check (char_length(reason) <= 200),
  created_at timestamptz not null default now(),
  released_at timestamptz,
  unique(order_id, account_id)
);

create unique index wallet_active_hold_per_order_idx
  on public.wallet_holds(order_id, account_id)
  where status = 'active';

create table public.wallet_jobs (
  id uuid primary key default gen_random_uuid(),
  job_type text not null check (job_type ~ '^[a-z_]{3,50}$'),
  wallet_account_id uuid references public.wallet_accounts(id) on delete restrict,
  order_id uuid references public.p2p_orders(id) on delete restrict,
  idempotency_key text not null unique check (char_length(idempotency_key) between 8 and 120),
  status public.wallet_job_status not null default 'queued',
  attempts integer not null default 0 check (attempts >= 0),
  available_at timestamptz not null default now(),
  locked_at timestamptz,
  completed_at timestamptz,
  last_error text,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index wallet_jobs_queue_idx
  on public.wallet_jobs(status, available_at, created_at)
  where status in ('queued', 'failed');

create table public.wallet_audit_log (
  id bigint generated always as identity primary key,
  actor_id uuid references public.profiles(id) on delete set null,
  action text not null check (action ~ '^[a-z_]{3,60}$'),
  wallet_account_id uuid references public.wallet_accounts(id) on delete set null,
  reference_type text,
  reference_id uuid,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index wallet_audit_log_reference_idx
  on public.wallet_audit_log(reference_type, reference_id, created_at desc);

alter table public.wallet_accounts enable row level security;
alter table public.wallet_ledger_entries enable row level security;
alter table public.wallet_holds enable row level security;
alter table public.wallet_jobs enable row level security;
alter table public.wallet_audit_log enable row level security;

revoke all on public.wallet_accounts, public.wallet_ledger_entries, public.wallet_holds,
  public.wallet_jobs, public.wallet_audit_log from anon, authenticated;

grant select on public.wallet_accounts to authenticated;
grant select on public.wallet_ledger_entries, public.wallet_holds to authenticated;

create policy "Users can read their own wallet accounts"
  on public.wallet_accounts for select to authenticated
  using (owner_id = (select auth.uid()));

create policy "Users can read their own ledger"
  on public.wallet_ledger_entries for select to authenticated
  using (exists (
    select 1 from public.wallet_accounts a
    where a.id = account_id and a.owner_id = (select auth.uid())
  ));

create policy "Users can read their own holds"
  on public.wallet_holds for select to authenticated
  using (exists (
    select 1 from public.wallet_accounts a
    where a.id = account_id and a.owner_id = (select auth.uid())
  ));

-- No client INSERT/UPDATE/DELETE policies exist for balances, ledger, holds,
-- jobs, or audit logs. Mutations must go through security-definer functions.

create or replace function public.ensure_user_wallet(
  p_asset_code text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_id uuid;
  v_asset text := upper(p_asset_code);
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if v_asset is null or v_asset !~ '^[A-Z0-9]{2,12}$' then
    raise exception 'Invalid asset code' using errcode = '22023';
  end if;
  if not exists (select 1 from public.profiles where id = v_user and account_status = 'active') then
    raise exception 'Active account required' using errcode = '42501';
  end if;

  insert into public.wallet_accounts(owner_id, asset_code, scope)
  values (v_user, v_asset, 'user_available')
  on conflict (owner_id, asset_code, scope) do nothing
  returning id into v_id;

  if v_id is null then
    select id into v_id from public.wallet_accounts
    where owner_id = v_user and asset_code = v_asset and scope = 'user_available';
  end if;
  return v_id;
end;
$$;

create or replace function public.get_or_create_wallet(
  p_asset_code text
)
returns table (
  id uuid,
  asset_code text,
  available_balance numeric,
  held_balance numeric,
  version bigint
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_id uuid;
begin
  v_id := public.ensure_user_wallet(p_asset_code);
  return query
    select a.id, a.asset_code, a.available_balance, a.held_balance, a.version
    from public.wallet_accounts a
    where a.id = v_id;
end;
$$;

-- Main Wallet operation: only trusted server-side code should call this function.
-- It records a ledger entry and updates the account atomically.
create or replace function public.wallet_credit_sandbox(
  p_account_id uuid,
  p_amount numeric,
  p_reference_type text,
  p_reference_id uuid,
  p_idempotency_key text,
  p_metadata jsonb default '{}'::jsonb
)
returns numeric
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_account public.wallet_accounts%rowtype;
  v_new_balance numeric;
begin
  if p_amount is null or p_amount <= 0 then
    raise exception 'Credit amount must be positive' using errcode = '22023';
  end if;

  select * into v_account from public.wallet_accounts where id = p_account_id for update;
  if not found then raise exception 'Wallet account not found' using errcode = 'P0002'; end if;

  if exists (select 1 from public.wallet_ledger_entries where idempotency_key = p_idempotency_key) then
    select balance_after into v_new_balance from public.wallet_ledger_entries where idempotency_key = p_idempotency_key;
    return v_new_balance;
  end if;

  v_new_balance := v_account.available_balance + p_amount;
  update public.wallet_accounts
  set available_balance = v_new_balance, version = version + 1, updated_at = now()
  where id = p_account_id;

  insert into public.wallet_ledger_entries(account_id, asset_code, entry_type, amount, balance_after, reference_type, reference_id, idempotency_key, metadata)
  values (p_account_id, v_account.asset_code, 'credit', p_amount, v_new_balance, p_reference_type, p_reference_id, p_idempotency_key, coalesce(p_metadata, '{}'::jsonb));

  return v_new_balance;
end;
$$;

-- Sub-Wallet operation: reserve funds for a P2P order without moving them on-chain.
create or replace function public.wallet_create_p2p_hold(
  p_account_id uuid,
  p_order_id uuid,
  p_amount numeric
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_account public.wallet_accounts%rowtype;
  v_hold uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '28000'; end if;
  if p_amount is null or p_amount <= 0 then raise exception 'Hold amount must be positive' using errcode = '22023'; end if;

  select * into v_account from public.wallet_accounts where id = p_account_id for update;
  if not found or v_account.owner_id <> auth.uid() then raise exception 'Wallet access denied' using errcode = '42501'; end if;
  if v_account.available_balance < p_amount then raise exception 'Insufficient available balance' using errcode = '22023'; end if;
  if exists (select 1 from public.wallet_holds where order_id = p_order_id and account_id = p_account_id and status = 'active') then
    raise exception 'Active hold already exists' using errcode = '23505';
  end if;

  update public.wallet_accounts
  set available_balance = available_balance - p_amount,
      held_balance = held_balance + p_amount,
      version = version + 1,
      updated_at = now()
  where id = p_account_id;

  insert into public.wallet_holds(account_id, order_id, amount)
  values (p_account_id, p_order_id, p_amount)
  returning id into v_hold;

  insert into public.wallet_ledger_entries(account_id, asset_code, entry_type, amount, balance_after, reference_type, reference_id, idempotency_key, metadata)
  values (p_account_id, v_account.asset_code, 'hold', p_amount, v_account.available_balance - p_amount, 'p2p_order', p_order_id,
          'hold:' || p_order_id::text || ':' || p_account_id::text,
          jsonb_build_object('hold_id', v_hold));

  return v_hold;
end;
$$;

revoke all on function public.ensure_user_wallet(text) from public, anon;
grant execute on function public.ensure_user_wallet(text) to authenticated;
revoke all on function public.get_or_create_wallet(text) from public, anon;
grant execute on function public.get_or_create_wallet(text) to authenticated;
revoke all on function public.wallet_credit_sandbox(uuid,numeric,text,uuid,text,jsonb) from public, anon, authenticated;
revoke all on function public.wallet_create_p2p_hold(uuid,uuid,numeric) from public, anon;
grant execute on function public.wallet_create_p2p_hold(uuid,uuid,numeric) to authenticated;

-- Explicitly prevent direct balance mutation even for authenticated users.
revoke insert, update, delete on public.wallet_accounts from authenticated;
revoke insert, update, delete on public.wallet_ledger_entries from authenticated;
revoke insert, update, delete on public.wallet_holds from authenticated;
revoke insert, update, delete on public.wallet_jobs from authenticated;
revoke insert, update, delete on public.wallet_audit_log from authenticated;
