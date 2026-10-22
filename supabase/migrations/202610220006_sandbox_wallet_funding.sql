-- Capped sandbox funding for the redesigned wallet layer.
-- This creates simulated test credits only; it is not a deposit or real asset balance.

create or replace function public.wallet_fund_sandbox(
  p_asset_code text,
  p_amount numeric,
  p_idempotency_key text
)
returns table (
  wallet_id uuid,
  available_balance numeric,
  ledger_entry_id bigint
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_asset text := upper(trim(p_asset_code));
  v_account public.wallet_accounts%rowtype;
  v_entry public.wallet_ledger_entries%rowtype;
  v_key text;
  v_balance numeric;
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

  if v_asset is null or v_asset !~ '^[A-Z0-9]{2,12}$'
     or not exists (
       select 1 from public.p2p_supported_assets sa
       where sa.code = v_asset and sa.enabled = true
     ) then
    raise exception 'Asset is invalid or not enabled for sandbox trading' using errcode = '22023';
  end if;

  if p_amount is null or p_amount <= 0 or p_amount > 1000 then
    raise exception 'Sandbox funding must be greater than zero and no more than 1000 units per request'
      using errcode = '22023';
  end if;

  if p_idempotency_key is null
     or p_idempotency_key !~ '^[A-Za-z0-9_-]{8,60}$' then
    raise exception 'Idempotency key must be 8-60 letters, numbers, underscores, or hyphens'
      using errcode = '22023';
  end if;

  v_key := 'sandbox-fund:' || v_user::text || ':' || p_idempotency_key;

  insert into public.wallet_accounts(owner_id, asset_code, scope, is_sandbox)
  values (v_user, v_asset, 'user_available', true)
  on conflict (owner_id, asset_code, scope) do nothing;

  select * into v_account
  from public.wallet_accounts
  where owner_id = v_user
    and asset_code = v_asset
    and scope = 'user_available'
  for update;

  select * into v_entry
  from public.wallet_ledger_entries
  where idempotency_key = v_key;

  if found then
    if v_entry.account_id <> v_account.id
       or v_entry.entry_type <> 'credit'
       or v_entry.amount <> p_amount
       or v_entry.reference_type <> 'sandbox_funding' then
      raise exception 'Idempotency key was already used with different parameters'
        using errcode = '22023';
    end if;

    return query select v_account.id, v_account.available_balance, v_entry.id;
    return;
  end if;

  if v_account.available_balance + p_amount > 100000 then
    raise exception 'Sandbox wallet balance cap of 100000 units would be exceeded'
      using errcode = '22023';
  end if;

  v_balance := v_account.available_balance + p_amount;

  update public.wallet_accounts
  set available_balance = v_balance,
      version = version + 1,
      updated_at = now()
  where id = v_account.id;

  insert into public.wallet_ledger_entries(
    account_id, asset_code, entry_type, amount, balance_after,
    reference_type, reference_id, idempotency_key, metadata
  )
  values (
    v_account.id, v_account.asset_code, 'credit', p_amount, v_balance,
    'sandbox_funding', null, v_key,
    jsonb_build_object('sandbox', true, 'funded_by_user', v_user, 'request_key', p_idempotency_key)
  )
  returning * into v_entry;

  insert into public.wallet_audit_log(
    actor_id, action, wallet_account_id, reference_type, reference_id, details
  )
  values (
    v_user, 'sandbox_wallet_funded', v_account.id, 'sandbox_funding', null,
    jsonb_build_object('amount', p_amount, 'asset_code', v_asset, 'ledger_entry_id', v_entry.id)
  );

  return query select v_account.id, v_balance, v_entry.id;
end;
$$;

revoke all on function public.wallet_fund_sandbox(text, numeric, text) from public, anon;
grant execute on function public.wallet_fund_sandbox(text, numeric, text) to authenticated;
