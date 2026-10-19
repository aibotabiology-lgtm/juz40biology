-- BIO APP: оқушылар мен олардың барысы
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  tg_id bigint unique,
  name text,
  username text,
  photo text,
  is_teacher boolean not null default false,
  created_at timestamptz not null default now(),
  last_seen timestamptz not null default now()
);

create table if not exists public.progress (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.progress enable row level security;

create or replace function public.is_teacher()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select is_teacher from public.profiles where id = auth.uid()), false)
$$;

revoke all on public.profiles from anon;
revoke all on public.progress from anon;
grant select on public.profiles to authenticated;
grant select, insert, update on public.progress to authenticated;
grant all on public.profiles to service_role;
grant all on public.progress to service_role;
grant execute on function public.is_teacher() to authenticated;

drop policy if exists profiles_read on public.profiles;
create policy profiles_read on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_teacher());

drop policy if exists progress_read on public.progress;
create policy progress_read on public.progress for select to authenticated
  using (user_id = auth.uid() or public.is_teacher());

drop policy if exists progress_ins on public.progress;
create policy progress_ins on public.progress for insert to authenticated
  with check (user_id = auth.uid());

drop policy if exists progress_upd on public.progress;
create policy progress_upd on public.progress for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
