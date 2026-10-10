create extension if not exists pgtap with schema extensions;

begin;

select plan(8);

select ok(
  has_column_privilege('anon', 'public.profiles', 'display_name', 'SELECT'),
  'anonymous users can read public display names'
);
select ok(
  not has_column_privilege('anon', 'public.profiles', 'verification_status', 'SELECT'),
  'anonymous users cannot read verification status'
);
select ok(
  not has_column_privilege('authenticated', 'public.profiles', 'account_status', 'SELECT'),
  'signed-in users cannot read account status'
);
select ok(
  not has_table_privilege('authenticated', 'public.p2p_orders', 'UPDATE'),
  'users cannot directly update orders'
);
select ok(
  not has_table_privilege('authenticated', 'public.p2p_orders', 'INSERT'),
  'users cannot directly insert orders'
);
select ok(
  not has_function_privilege('anon', 'public.create_p2p_order(uuid,numeric)', 'EXECUTE'),
  'anonymous users cannot create orders'
);
select ok(
  has_function_privilege('authenticated', 'public.create_p2p_order(uuid,numeric)', 'EXECUTE'),
  'authenticated users can call the server-side order function'
);
select ok(
  exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'p2p_orders'
      and policyname = 'Order participants can read orders'
  ),
  'orders have a participant-only read policy'
);

select * from finish();
rollback();
