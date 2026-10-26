-- TOM AUTHENTIQUE 074 — schéma de base Supabase
-- Exécuter dans Supabase Dashboard > SQL Editor.
-- À vérifier avant une mise en production réelle.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text not null default 'customer' check (role in ('customer','admin')),
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.profiles(id,email,role)
  values (new.id,new.email,'customer')
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;
revoke all on function public.handle_new_user() from public, anon, authenticated;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(name) between 1 and 120),
  description text not null default '',
  price bigint not null check (price > 0),
  category text not null default 'Numérique',
  -- Use a Storage object path, never a public URL for paid content.
  private_file_path text,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);
alter table public.products enable row level security;

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  status text not null default 'pending_payment'
    check (status in ('pending_payment','paid','delivered','cancelled','refunded')),
  payment_method text not null check (payment_method in ('mobile_money_manual','chariow')),
  total_amount bigint not null check (total_amount > 0),
  provider_reference text unique,
  created_at timestamptz not null default now(),
  paid_at timestamptz,
  delivered_at timestamptz
);
alter table public.orders enable row level security;

create table if not exists public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid references public.products(id),
  product_name text not null,
  unit_price bigint not null check (unit_price > 0),
  quantity integer not null check (quantity between 1 and 50),
  created_at timestamptz not null default now()
);
alter table public.order_items enable row level security;

create table if not exists public.payment_events (
  id uuid primary key default gen_random_uuid(),
  provider text not null check (provider in ('chariow','mobile_money_manual')),
  provider_event_id text unique,
  order_id uuid references public.orders(id),
  event_type text not null,
  verified boolean not null default false,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.payment_events enable row level security;

-- Fonction privée pour vérifier le rôle sans provoquer de récursion RLS sur profiles.
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create or replace function private.is_ta074_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'admin'
  )
$$;
revoke all on function private.is_ta074_admin() from public, anon;
grant execute on function private.is_ta074_admin() to authenticated;

-- Public may read active products; only admin may manage catalogue.
drop policy if exists "Public read active products" on public.products;
create policy "Public read active products" on public.products for select to anon, authenticated
using (is_active = true or private.is_ta074_admin());
drop policy if exists "Admin insert products" on public.products;
create policy "Admin insert products" on public.products for insert to authenticated
with check (private.is_ta074_admin());
drop policy if exists "Admin update products" on public.products;
create policy "Admin update products" on public.products for update to authenticated
using (private.is_ta074_admin()) with check (private.is_ta074_admin());
drop policy if exists "Admin delete products" on public.products;
create policy "Admin delete products" on public.products for delete to authenticated
using (private.is_ta074_admin());

drop policy if exists "Read own profile or admin" on public.profiles;
create policy "Read own profile or admin" on public.profiles for select to authenticated
using ((select auth.uid()) = id or private.is_ta074_admin());
-- No client INSERT/UPDATE policy for role: customers cannot promote themselves.

drop policy if exists "Read own orders or admin" on public.orders;
create policy "Read own orders or admin" on public.orders for select to authenticated
using ((select auth.uid()) = user_id or private.is_ta074_admin());
-- Orders are created/updated only through trusted Edge Functions using server credentials.
drop policy if exists "Read own order items or admin" on public.order_items;
create policy "Read own order items or admin" on public.order_items for select to authenticated
using (exists(select 1 from public.orders o where o.id=order_id and (o.user_id=(select auth.uid()) or private.is_ta074_admin())));
-- No direct client write policies for order_items or payment_events.

-- Expose only necessary operations via Data API. RLS remains mandatory.
grant select on public.products to anon, authenticated;
grant select on public.profiles, public.orders, public.order_items to authenticated;
grant insert, update, delete on public.products to authenticated;

-- === Extension parrainage, vendeurs/revendeurs et catégories illustrées ===
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check check (role in ('customer','admin','seller','reseller'));

create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  name text not null unique check (length(name) between 1 and 60),
  description text not null default '',
  image_url text,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);
alter table public.categories enable row level security;
drop policy if exists "Public read active categories" on public.categories;
create policy "Public read active categories" on public.categories for select to anon, authenticated using (is_active or private.is_ta074_admin());
drop policy if exists "Admin manage categories" on public.categories;
create policy "Admin manage categories" on public.categories for all to authenticated using (private.is_ta074_admin()) with check (private.is_ta074_admin());
grant select on public.categories to anon, authenticated;
grant insert, update, delete on public.categories to authenticated;

alter table public.products add column if not exists image_url text;
alter table public.products add column if not exists seller_id uuid references auth.users(id) on delete set null;
alter table public.products add column if not exists approval_status text not null default 'approved' check (approval_status in ('pending','approved','rejected'));
alter table public.products add column if not exists reseller_allowed boolean not null default false;

create table if not exists public.seller_applications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  account_type text not null check (account_type in ('seller','reseller')),
  shop_name text not null check (length(shop_name) between 1 and 100),
  contact text not null check (length(contact) between 1 and 120),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz,
  unique(user_id, account_type)
);
alter table public.seller_applications enable row level security;
drop policy if exists "Users read own seller applications" on public.seller_applications;
create policy "Users read own seller applications" on public.seller_applications for select to authenticated using (user_id=(select auth.uid()) or private.is_ta074_admin());
drop policy if exists "Users submit own seller application" on public.seller_applications;
create policy "Users submit own seller application" on public.seller_applications for insert to authenticated with check (user_id=(select auth.uid()));
drop policy if exists "Admin review seller applications" on public.seller_applications;
create policy "Admin review seller applications" on public.seller_applications for update to authenticated using (private.is_ta074_admin()) with check (private.is_ta074_admin());
grant select, insert on public.seller_applications to authenticated;
grant update on public.seller_applications to authenticated;

create table if not exists public.referral_codes (
  user_id uuid primary key references auth.users(id) on delete cascade,
  code text not null unique,
  created_at timestamptz not null default now()
);
create table if not exists public.referral_events (
  id uuid primary key default gen_random_uuid(),
  referrer_id uuid not null references auth.users(id) on delete cascade,
  referred_user_id uuid not null unique references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  check (referrer_id <> referred_user_id)
);
alter table public.referral_codes enable row level security;
alter table public.referral_events enable row level security;
drop policy if exists "Read own referral code" on public.referral_codes;
create policy "Read own referral code" on public.referral_codes for select to authenticated using (user_id=(select auth.uid()) or private.is_ta074_admin());
drop policy if exists "Read own referral stats" on public.referral_events;
create policy "Read own referral stats" on public.referral_events for select to authenticated using (referrer_id=(select auth.uid()) or private.is_ta074_admin());
grant select on public.referral_codes, public.referral_events to authenticated;

create or replace function public.make_referral_code()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.referral_codes(user_id,code)
  values(new.id, upper(substr(encode(gen_random_bytes(8),'hex'),1,10)))
  on conflict (user_id) do nothing;
  if (new.raw_user_meta_data ? 'referral_code') then
    insert into public.referral_events(referrer_id,referred_user_id)
    select rc.user_id,new.id from public.referral_codes rc
    where rc.code=upper(new.raw_user_meta_data->>'referral_code') and rc.user_id<>new.id
    on conflict (referred_user_id) do nothing;
  end if;
  return new;
end;
$$;
revoke all on function public.make_referral_code() from public, anon, authenticated;
drop trigger if exists on_auth_user_referral_code on auth.users;
create trigger on_auth_user_referral_code after insert on auth.users for each row execute procedure public.make_referral_code();

-- Products can be read publicly only when approved and active; sellers may submit their own listings.
drop policy if exists "Public read active products" on public.products;
create policy "Public read active products" on public.products for select to anon, authenticated
using ((is_active = true and approval_status='approved') or private.is_ta074_admin() or seller_id=(select auth.uid()));
drop policy if exists "Seller submit own product" on public.products;
create policy "Seller submit own product" on public.products for insert to authenticated
with check (seller_id=(select auth.uid()) and private.is_ta074_admin() = false and exists(select 1 from public.profiles p where p.id=(select auth.uid()) and p.role='seller') and approval_status='pending' and is_active=false);
drop policy if exists "Seller update own pending product" on public.products;
create policy "Seller update own pending product" on public.products for update to authenticated
using (seller_id=(select auth.uid()) and approval_status='pending')
with check (seller_id=(select auth.uid()) and approval_status='pending' and is_active=false);


create table if not exists public.reseller_listings (
  id uuid primary key default gen_random_uuid(),
  reseller_id uuid not null references auth.users(id) on delete cascade,
  product_id uuid not null references public.products(id) on delete cascade,
  resale_price bigint not null check (resale_price > 0),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  unique(reseller_id,product_id)
);
alter table public.reseller_listings enable row level security;
drop policy if exists "Read own reseller listings or admin" on public.reseller_listings;
create policy "Read own reseller listings or admin" on public.reseller_listings for select to authenticated using (reseller_id=(select auth.uid()) or private.is_ta074_admin());
drop policy if exists "Reseller submit own listing" on public.reseller_listings;
create policy "Reseller submit own listing" on public.reseller_listings for insert to authenticated with check (reseller_id=(select auth.uid()) and exists(select 1 from public.profiles p where p.id=(select auth.uid()) and p.role='reseller') and status='pending');
drop policy if exists "Admin review reseller listings" on public.reseller_listings;
create policy "Admin review reseller listings" on public.reseller_listings for update to authenticated using (private.is_ta074_admin()) with check (private.is_ta074_admin());
grant select, insert on public.reseller_listings to authenticated;
grant update on public.reseller_listings to authenticated;


-- Générer aussi un code de parrainage pour les comptes déjà existants.
insert into public.referral_codes(user_id,code)
select u.id, upper(substr(encode(gen_random_bytes(8),'hex'),1,10))
from auth.users u
on conflict (user_id) do nothing;

create or replace function public.apply_seller_role_after_review()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.status='approved' and old.status is distinct from new.status then
    update public.profiles set role=new.account_type where id=new.user_id and role <> 'admin';
    update public.seller_applications set reviewed_at=now() where id=new.id;
  elsif new.status='rejected' and old.status is distinct from new.status then
    update public.seller_applications set reviewed_at=now() where id=new.id;
  end if;
  return new;
end;
$$;
revoke all on function public.apply_seller_role_after_review() from public, anon, authenticated;
drop trigger if exists seller_application_reviewed on public.seller_applications;
create trigger seller_application_reviewed after update of status on public.seller_applications
for each row execute procedure public.apply_seller_role_after_review();


-- ============================================================
-- TOM AUTHENTIQUE 074 : CODES PROMO ET CADEAUX
-- À exécuter après le schéma de base ci-dessus.
-- Montants en FCFA. Les validations/consommations doivent passer
-- par une Edge Function sécurisée (pas depuis le navigateur).
-- ============================================================

create table if not exists public.promo_codes (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  description text not null default '',
  discount_type text not null check (discount_type in ('percent','fixed')),
  discount_value integer not null check (discount_value > 0),
  min_order_amount bigint not null default 0 check (min_order_amount >= 0),
  max_discount_amount bigint check (max_discount_amount is null or max_discount_amount > 0),
  max_uses integer check (max_uses is null or max_uses > 0),
  uses_count integer not null default 0 check (uses_count >= 0),
  per_user_limit integer not null default 1 check (per_user_limit > 0),
  starts_at timestamptz not null default now(),
  expires_at timestamptz,
  is_active boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  check (expires_at is null or expires_at > starts_at),
  check (discount_type <> 'percent' or discount_value <= 100)
);
alter table public.promo_codes enable row level security;

drop policy if exists "Admin manage promo codes" on public.promo_codes;
create policy "Admin manage promo codes" on public.promo_codes
  for all to authenticated
  using (private.is_ta074_admin())
  with check (private.is_ta074_admin());
-- Les clients ne peuvent pas modifier les codes ni leur compteur.
grant select, insert, update, delete on public.promo_codes to authenticated;

create table if not exists public.promo_redemptions (
  id uuid primary key default gen_random_uuid(),
  promo_code_id uuid not null references public.promo_codes(id),
  user_id uuid not null references auth.users(id) on delete cascade,
  order_id uuid not null unique references public.orders(id) on delete cascade,
  discount_amount bigint not null check (discount_amount > 0),
  redeemed_at timestamptz not null default now(),
  unique (promo_code_id, user_id, order_id)
);
alter table public.promo_redemptions enable row level security;
drop policy if exists "Read own promo redemptions or admin" on public.promo_redemptions;
create policy "Read own promo redemptions or admin" on public.promo_redemptions
  for select to authenticated
  using (user_id = (select auth.uid()) or private.is_ta074_admin());
-- Aucun INSERT/UPDATE client : l'Edge Function vérifie le code, les limites
-- et le montant, puis enregistre la réduction de façon atomique.
grant select on public.promo_redemptions to authenticated;

create table if not exists public.gift_rewards (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  reward_type text not null check (reward_type in ('store_credit','free_product','referral_bonus','loyalty_bonus')),
  title text not null check (length(title) between 1 and 120),
  description text not null default '',
  amount bigint check (amount is null or amount > 0),
  product_id uuid references public.products(id) on delete set null,
  status text not null default 'pending' check (status in ('pending','available','used','cancelled','expired')),
  expires_at timestamptz,
  source_referral_event_id uuid references public.referral_events(id) on delete set null,
  created_at timestamptz not null default now(),
  used_at timestamptz,
  check ((reward_type = 'free_product' and product_id is not null) or reward_type <> 'free_product')
);
alter table public.gift_rewards enable row level security;
drop policy if exists "Read own gifts or admin" on public.gift_rewards;
create policy "Read own gifts or admin" on public.gift_rewards
  for select to authenticated
  using (user_id = (select auth.uid()) or private.is_ta074_admin());
drop policy if exists "Admin manage gifts" on public.gift_rewards;
create policy "Admin manage gifts" on public.gift_rewards
  for all to authenticated
  using (private.is_ta074_admin())
  with check (private.is_ta074_admin());
grant select, insert, update, delete on public.gift_rewards to authenticated;

-- Exemples de codes promo désactivés par défaut : activez-les depuis l'admin
-- après avoir défini les règles de votre offre.
insert into public.promo_codes
  (code, description, discount_type, discount_value, min_order_amount, is_active)
values
  ('BIENVENUE10', 'Exemple : réduction de 10 %', 'percent', 10, 0, false),
  ('TOM500', 'Exemple : réduction de 500 FCFA', 'fixed', 500, 2000, false)
on conflict (code) do nothing;
