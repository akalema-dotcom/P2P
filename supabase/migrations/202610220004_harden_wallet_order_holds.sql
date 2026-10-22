-- Harden sandbox P2P wallet holds and automatically release them on cancellation.
-- No real payments, custody, or blockchain transfers are performed here.

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
  v_user uuid := auth.uid();
  v_account public.wallet_accounts%rowtype;
  v_order public.p2p_orders%rowtype;
  v_hold uuid;
  v_existing uuid;
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if p_amount is null or p_amount <= 0 then
    raise exception 'Hold amount must be positive' using errcode = '22023';
  end if;

  select * into v_order
  from public.p2p_orders
  where id = p_order_id
  for update;

  if not found then
    raise exception 'Order not found' using errcode = 'P0002';
  end if;
  if v_order.is_sandbox is not true
     or v_order.status not in ('awaiting_payment', 'payment_marked')
     or v_order.seller_id <> v_user then
    raise exception 'Only the order seller can reserve sandbox funds for an active order' using errcode = '42501';
  end if;
  if p_amount <> v_order.asset_quantity then
    raise exception 'Hold amount must match the order asset quantity' using errcode = '22023';
  end if;

  select * into v_account
  from public.wallet_accounts
  where id = p_account_id
  for update;

  if not found
     or v_account.owner_id <> v_user
     or v_account.scope <> 'user_available'
     or v_account.asset_code <> v_order.asset_code
     or v_account.is_sandbox is not true then
    raise exception 'Wallet account does not match the order seller and asset' using errcode = '42501';
  end if;

  select id into v_existing
  from public.wallet_holds
  where order_id = p_order_id and account_id = p_account_id;

  if v_existing is not null then
    if exists (
      select 1 from public.wallet_holds
      where id = v_existing and status = 'active' and amount = p_amount
    ) then
      return v_existing;
    end if;
    raise exception 'A hold already exists for this order and wallet' using errcode = '23505';
  end if;

  if v_account.available_balance < p_amount then
    raise exception 'Insufficient available sandbox balance' using errcode = '22023';
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

  insert into public.wallet_ledger_entries(
    account_id, asset_code, entry_type, amount, balance_after,
    reference_type, reference_id, idempotency_key, metadata
  )
  values (
    p_account_id, v_account.asset_code, 'hold', p_amount,
    v_account.available_balance - p_amount, 'p2p_order', p_order_id,
    'hold:' || p_order_id::text || ':' || p_account_id::text,
    jsonb_build_object('hold_id', v_hold, 'sandbox', true)
  );

  insert into public.wallet_audit_log(
    actor_id, action, wallet_account_id, reference_type, reference_id, details
  )
  values (
    v_user, 'sandbox_order_hold_created', p_account_id, 'p2p_order', p_order_id,
    jsonb_build_object('hold_id', v_hold, 'amount', p_amount, 'asset_code', v_account.asset_code)
  );

  return v_hold;
end;
$$;

-- This trigger-side helper is intentionally in the private schema and is not
-- executable by anon/authenticated clients. It only releases sandbox holds.
create or replace function private.release_sandbox_order_holds(p_order_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hold record;
  v_account public.wallet_accounts%rowtype;
  v_new_available numeric;
  v_new_held numeric;
begin
  for v_hold in
    select h.id, h.account_id, h.amount, a.asset_code
    from public.wallet_holds h
    join public.wallet_accounts a on a.id = h.account_id
    where h.order_id = p_order_id and h.status = 'active'
    for update of h, a
  loop
    select * into v_account
    from public.wallet_accounts
    where id = v_hold.account_id
    for update;

    if v_account.held_balance < v_hold.amount then
      raise exception 'Wallet held balance invariant failed for hold %', v_hold.id
        using errcode = '23514';
    end if;

    v_new_available := v_account.available_balance + v_hold.amount;
    v_new_held := v_account.held_balance - v_hold.amount;

    update public.wallet_accounts
    set available_balance = v_new_available,
        held_balance = v_new_held,
        version = version + 1,
        updated_at = now()
    where id = v_hold.account_id;

    update public.wallet_holds
    set status = 'released', released_at = now()
    where id = v_hold.id and status = 'active';

    insert into public.wallet_ledger_entries(
      account_id, asset_code, entry_type, amount, balance_after,
      reference_type, reference_id, idempotency_key, metadata
    )
    values (
      v_hold.account_id, v_hold.asset_code, 'release', v_hold.amount,
      v_new_available, 'p2p_order', p_order_id,
      'release:' || p_order_id::text || ':' || v_hold.account_id::text,
      jsonb_build_object('hold_id', v_hold.id, 'sandbox', true)
    )
    on conflict (idempotency_key) do nothing;

    insert into public.wallet_audit_log(
      actor_id, action, wallet_account_id, reference_type, reference_id, details
    )
    values (
      null, 'sandbox_order_hold_released', v_hold.account_id, 'p2p_order', p_order_id,
      jsonb_build_object('hold_id', v_hold.id, 'amount', v_hold.amount)
    );
  end loop;
end;
$$;

revoke all on function private.release_sandbox_order_holds(uuid) from public, anon, authenticated;
revoke all on function public.wallet_create_p2p_hold(uuid, uuid, numeric) from public, anon;
grant execute on function public.wallet_create_p2p_hold(uuid, uuid, numeric) to authenticated;

create or replace function private.release_sandbox_holds_after_cancel()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.status = 'cancelled' and old.status is distinct from new.status then
    perform private.release_sandbox_order_holds(new.id);
  end if;
  return new;
end;
$$;

revoke all on function private.release_sandbox_holds_after_cancel() from public, anon, authenticated;

drop trigger if exists release_sandbox_holds_after_order_cancel on public.p2p_orders;
create trigger release_sandbox_holds_after_order_cancel
after update of status on public.p2p_orders
for each row
when (new.status = 'cancelled' and old.status is distinct from new.status)
execute function private.release_sandbox_holds_after_cancel();
