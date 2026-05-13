-- ============================================
-- Dove Recovery CRM — Supabase Database Setup
-- Run this in your Supabase SQL Editor
-- ============================================

-- 1. Profiles table (auto-linked to Supabase Auth)
create table public.profiles (
  id uuid references auth.users on delete cascade primary key,
  first_name text not null default '',
  last_name text not null default '',
  role text default '',
  is_admin boolean default false,
  created_at timestamptz default now()
);

-- 2. DOMAIN RESTRICTION — only @doverecovery.com and @robinrecovery.com can sign up
-- This runs BEFORE a user is created and blocks unauthorized domains
create or replace function public.check_email_domain()
returns trigger as $$
declare
  email_domain text;
begin
  email_domain := split_part(new.email, '@', 2);
  if email_domain not in ('doverecovery.com', 'robinrecovery.com') then
    raise exception 'Signups are restricted to doverecovery.com and robinrecovery.com email addresses.';
  end if;
  return new;
end;
$$ language plpgsql security definer;

create trigger check_email_before_signup
  before insert on auth.users
  for each row execute function public.check_email_domain();

-- 3. Auto-create a profile when someone signs up
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, first_name, last_name)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'first_name', ''),
    coalesce(new.raw_user_meta_data->>'last_name', '')
  );
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 3. Inbound Referrals
create table public.inbound_referrals (
  id bigint generated always as identity primary key,
  first_name text not null,
  last_name text not null,
  referral_source text not null,
  created_by uuid references public.profiles(id),
  created_at timestamptz default now()
);

-- 4. Outbound Referrals
create table public.outbound_referrals (
  id bigint generated always as identity primary key,
  first_name text not null,
  last_name text not null,
  referred_to text not null,
  reason text default '',
  created_by uuid references public.profiles(id),
  created_at timestamptz default now()
);

-- 5. Row Level Security — only logged-in users can access data
alter table public.profiles enable row level security;
alter table public.inbound_referrals enable row level security;
alter table public.outbound_referrals enable row level security;

-- Profiles: everyone can read, you can update your own
create policy "Anyone authed can view profiles"
  on public.profiles for select to authenticated using (true);
create policy "Users can update own profile"
  on public.profiles for update to authenticated using (auth.uid() = id);

-- Inbound: full CRUD for any authenticated user
create policy "View inbound" on public.inbound_referrals for select to authenticated using (true);
create policy "Add inbound"  on public.inbound_referrals for insert to authenticated with check (true);
create policy "Edit inbound" on public.inbound_referrals for update to authenticated using (true);
create policy "Del inbound"  on public.inbound_referrals for delete to authenticated using (true);

-- Outbound: full CRUD for any authenticated user
create policy "View outbound" on public.outbound_referrals for select to authenticated using (true);
create policy "Add outbound"  on public.outbound_referrals for insert to authenticated with check (true);
create policy "Edit outbound" on public.outbound_referrals for update to authenticated using (true);
create policy "Del outbound"  on public.outbound_referrals for delete to authenticated using (true);
