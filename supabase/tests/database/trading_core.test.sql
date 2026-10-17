create extension if not exists pgtap with schema extensions;

begin;
select plan(12);

select has_table('public', 'p2p_supported_assets', 'supported assets table exists');
select has_table('public', 'p2p_payment_methods', 'payment methods table exists');
select has_table('public', 'p2p_order_state_history', 'order state history table exists');
select ok(
  not has_table_privilege('authenticated', 'public.p2p_order_state_history', 'INSERT'),
  'clients cannot directly insert state history'
);
select ok(
  not has_table_privilege('authenticated', 'public.p2p_order_state_history', 'UPDATE'),
  'clients cannot update state history'
);
select ok(
  not has_table_privilege('authenticated', 'public.p2p_order_state_history', 'DELETE'),
  'clients cannot delete state history'
);
select ok(
  has_function_privilege('authenticated', 'public.transition_p2p_order(uuid,text,text)', 'EXECUTE'),
  'authenticated users can invoke the state transition RPC'
);
select ok(
  not has_function_privilege('anon', 'public.transition_p2p_order(uuid,text,text)', 'EXECUTE'),
  'anonymous users cannot invoke the state transition RPC'
);
select ok(
  exists (select 1 from public.p2p_supported_assets where code = 'USDT' and enabled = false),
  'USDT starts disabled for production safety'
);
select ok(
  exists (select 1 from public.p2p_supported_assets where code = 'BTC' and enabled = false),
  'BTC starts disabled for production safety'
);
select ok(
  exists (select 1 from public.p2p_payment_methods where code = 'mobile_money' and enabled = false),
  'mobile money starts disabled for production safety'
);
select ok(
  exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'p2p_order_state_history'),
  'order state history has RLS policies'
);

select * from finish();
rollback;
