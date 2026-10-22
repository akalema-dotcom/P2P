-- Atomically reserve the seller's sandbox asset balance when an order is created.
-- If the seller has no funded sandbox wallet, the whole order transaction fails
-- and the advertisement inventory reservation rolls back.

create or replace function private.reserve_sandbox_order_hold(p_order_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_order public.p2p_orders%rowtype;
  v_account public.wallet_accounts%rowtype;
  v_hold_id uuid;
  v_new_available numeric;
  v_new_held numeric;
begin
  select * into v_order
  from public.p2p_orders
  where id = p_order_id
  for update;

  if not found then
    raise exception 'Order not found' using errcode = 'P0002';
  end if;
  if v_order.is_sandbox is not true
     or v_order.status <> 'awaiting_payment' then
    raise exception 'Only new sandbox orders can reserve a wallet hold' using errcode = '55000';
  end if;

  insert into public.wallet_accounts(owner_id, asset_code, scope, is_sandbox)
  values (v_order.seller_id, v_order.asset_code, 'user_available', true)
  on conflict (owner_id, asset_code, scope) do nothing;

  select * into v_account
  from public.wallet_accounts
  where owner_id = v_order.seller_id
    and asset_code = v_order.asset_code
    and scope = 'user_available'
  for update;

  if not found then
    raise exception 'Seller sandbox wallet could not be created' using errcode = 'P0002';
  end if;
  if v_account.available_balance < v_order.asset_quantity then
    raise exception 'Seller has insufficient sandbox asset balance' using errcode = '22023';
  end if;

  -- One hold per order/account; this helper runs inside order creation's transaction.
  insert into public.wallet_holds(account_id, order_id, amount, reason)
  values (v_account.id, v_order.id, v_order.asset_quantity, 'p2p_order')
  returning id into v_hold_id;

  v_new_available := v_account.available_balance - v_order.asset_quantity;
  v_new_held := v_account.held_balance + v_order.asset_quantity;

  update public.wallet_accounts
  set available_balance = v_new_available,
      held_balance = v_new_held,
      version = version + 1,
      updated_at = now()
  where id = v_account.id;

  insert into public.wallet_ledger_entries(
    account_id, asset_code, entry_type, amount, balance_after,
    reference_type, reference_id, idempotency_key, metadata
  )
  values (
    v_account.id, v_account.asset_code, 'hold', v_order.asset_quantity,
    v_new_available, 'p2p_order', v_order.id,
    'hold:' || v_order.id::text || ':' || v_account.id::text,
    jsonb_build_object('hold_id', v_hold_id, 'sandbox', true, 'created_by', 'order_rpc')
  );

  insert into public.wallet_audit_log(
    actor_id, action, wallet_account_id, reference_type, reference_id, details
  )
  values (
    null, 'sandbox_order_hold_created', v_account.id, 'p2p_order', v_order.id,
    jsonb_build_object('hold_id', v_hold_id, 'amount', v_order.asset_quantity, 'asset_code', v_order.asset_code)
  );

  return v_hold_id;
end;
$$;

revoke all on function private.reserve_sandbox_order_hold(uuid) from public, anon, authenticated;

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
    raise exception 'Insufficient available advertisement quantity' using errcode = '22023';
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
    where p.id = v_seller_id and p.account_status = 'active'
  ) then
    raise exception 'Seller account is not eligible to trade' using errcode = '42501';
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
  values (v_order_id, null, 'awaiting_payment', v_user, 'Sandbox order created');

  -- If the seller cannot cover the amount, this raises an exception and rolls
  -- back the order and the advertisement quantity update atomically.
  perform private.reserve_sandbox_order_hold(v_order_id);

  return v_order_id;
end;
$$;

revoke all on function public.create_p2p_order(uuid, numeric) from public, anon;
grant execute on function public.create_p2p_order(uuid, numeric) to authenticated;
