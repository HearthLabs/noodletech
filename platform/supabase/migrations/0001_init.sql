-- Noodle marketplace: core schema.
-- Design rules:
--  * Every table has row-level security on.
--  * Browser roles (anon, authenticated) get only the column grants listed here.
--  * Status changes that matter (publishing, approving, strikes) happen only through
--    the security-definer functions at the bottom, never by direct UPDATE.
--  * Scan results are written by the server (service_role), never by a developer.

create type developer_status as enum ('pending', 'active', 'suspended', 'banned');
create type app_status       as enum ('draft', 'in_review', 'published', 'delisted');
create type release_status   as enum ('uploaded', 'scanning', 'scan_failed', 'in_review', 'approved', 'rejected', 'delisted');
create type report_status    as enum ('open', 'reviewing', 'actioned', 'dismissed');

-- ---------------------------------------------------------------- admins
create table public.admins (
  user_id    uuid primary key references auth.users on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.admins enable row level security;
revoke all on public.admins from anon, authenticated;

create function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid())
$$;

create function public.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

-- ------------------------------------------------------------ developers
create table public.developers (
  id                uuid primary key references auth.users on delete cascade,
  display_name      text not null check (char_length(display_name) between 2 and 80),
  contact_email     text not null check (contact_email like '%_@_%'),
  status            developer_status not null default 'pending',
  terms_version     text,
  terms_accepted_at timestamptz,
  created_at        timestamptz not null default now()
);
alter table public.developers enable row level security;
revoke all on public.developers from anon, authenticated;
grant select on public.developers to authenticated;
grant insert (id, display_name, contact_email) on public.developers to authenticated;
grant update (display_name, contact_email)     on public.developers to authenticated;

create policy developers_select on public.developers for select to authenticated
  using (id = auth.uid() or public.is_admin());
create policy developers_insert on public.developers for insert to authenticated
  with check (id = auth.uid());
create policy developers_update on public.developers for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

-- ------------------------------------------------------------------ apps
create table public.apps (
  id            uuid primary key default gen_random_uuid(),
  developer_id  uuid not null references public.developers on delete cascade,
  slug          text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,47}$'),
  name          text not null check (char_length(name) between 2 and 80),
  summary       text not null check (char_length(summary) between 1 and 160),
  description   text not null default '' check (char_length(description) <= 10000),
  category      text,
  license_name  text not null default '',
  homepage_url  text check (homepage_url is null or homepage_url ~ '^https://'),
  support_url   text check (support_url  is null or support_url  ~ '^https://'),
  -- Paid apps are deferred (merchant of record not chosen yet). Relax this later.
  price_cents   integer not null default 0 check (price_cents = 0),
  status        app_status not null default 'draft',
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index apps_developer_idx on public.apps (developer_id);
create index apps_status_idx    on public.apps (status);
create trigger apps_touch before update on public.apps
  for each row execute function public.touch_updated_at();

alter table public.apps enable row level security;
revoke all on public.apps from anon, authenticated;
grant select on public.apps to anon, authenticated;
grant insert (developer_id, slug, name, summary, description, category, license_name, homepage_url, support_url)
  on public.apps to authenticated;
grant update (name, summary, description, category, license_name, homepage_url, support_url)
  on public.apps to authenticated;
grant delete on public.apps to authenticated;

create policy apps_select on public.apps for select to anon, authenticated
  using (status = 'published' or developer_id = auth.uid() or public.is_admin());
create policy apps_insert on public.apps for insert to authenticated
  with check (
    developer_id = auth.uid()
    and exists (select 1 from public.developers d where d.id = auth.uid() and d.status = 'active')
  );
create policy apps_update on public.apps for update to authenticated
  using (developer_id = auth.uid() and status in ('draft', 'in_review'))
  with check (developer_id = auth.uid());
create policy apps_delete on public.apps for delete to authenticated
  using (developer_id = auth.uid() and status = 'draft');

-- -------------------------------------------------------------- releases
create table public.releases (
  id             uuid primary key default gen_random_uuid(),
  app_id         uuid not null references public.apps on delete cascade,
  version        text not null check (version ~ '^[0-9A-Za-z][0-9A-Za-z.+-]{0,31}$'),
  release_notes  text not null default '' check (char_length(release_notes) <= 5000),
  min_windows    text not null default '10',
  status         release_status not null default 'uploaded',
  review_note    text,
  reviewed_by    uuid references auth.users,
  reviewed_at    timestamptz,
  published_at   timestamptz,
  created_at     timestamptz not null default now(),
  unique (app_id, version)
);
create index releases_app_idx    on public.releases (app_id);
create index releases_status_idx on public.releases (status);

alter table public.releases enable row level security;
revoke all on public.releases from anon, authenticated;
grant select on public.releases to authenticated;
grant insert (app_id, version, release_notes, min_windows)
  on public.releases to authenticated;

-- Developers see their own releases; admins see all. The public reads the view below.
create policy releases_select on public.releases for select to authenticated
  using (
    public.is_admin()
    or exists (select 1 from public.apps a where a.id = app_id and a.developer_id = auth.uid())
  );
-- A developer may add a release only to their own app.
create policy releases_insert on public.releases for insert to authenticated
  with check (
    exists (select 1 from public.apps a
            where a.id = app_id and a.developer_id = auth.uid() and a.status <> 'delisted')
  );

-- ---------------------------------------------------------- release files
-- A release is a standalone executable plus related documents. Files are read-only:
-- once a row is written, its name, path, size and checksum can never change.
create type file_kind as enum ('executable', 'document');

create table public.release_files (
  id           uuid primary key default gen_random_uuid(),
  release_id   uuid not null references public.releases on delete cascade,
  kind         file_kind not null,
  file_name    text not null
    check (file_name ~ '^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$' and file_name !~ '\.\.'),
  storage_path text not null,
  size_bytes   bigint not null check (size_bytes > 0 and size_bytes <= 5368709120),
  sha256       text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  created_at   timestamptz not null default now(),
  unique (release_id, file_name),
  -- Allowed types: .exe for the app; .pdf, .txt, .md for documents. Nothing else.
  constraint file_kind_matches_extension check (
    (kind = 'executable' and lower(file_name) ~ '\.exe$')
    or (kind = 'document' and lower(file_name) ~ '\.(pdf|txt|md)$')
  )
);
create index release_files_release_idx on public.release_files (release_id);

alter table public.release_files enable row level security;
revoke all on public.release_files from anon, authenticated;
grant select, delete on public.release_files to authenticated;
grant insert (release_id, kind, file_name, storage_path, size_bytes, sha256)
  on public.release_files to authenticated;

-- Read-only: no update, ever, by anyone (the trigger also stops the server).
create function public.release_files_readonly() returns trigger language plpgsql as $$
begin raise exception 'release files are read-only'; end $$;
create trigger release_files_no_update before update on public.release_files
  for each row execute function public.release_files_readonly();

create policy release_files_select on public.release_files for select to authenticated
  using (
    public.is_admin()
    or exists (select 1 from public.releases r join public.apps a on a.id = r.app_id
               where r.id = release_id and a.developer_id = auth.uid())
  );
-- Counted in a function so the insert policy does not reference its own table.
create function public.release_file_count(p_release uuid) returns integer
language sql stable security definer set search_path = public as $$
  select count(*)::integer from public.release_files where release_id = p_release
$$;

-- Files may be added to your own release while it is still a fresh upload (max 20 files),
-- into your own storage folder.
create policy release_files_insert on public.release_files for insert to authenticated
  with check (
    storage_path like (auth.uid()::text || '/%')
    and exists (select 1 from public.releases r join public.apps a on a.id = r.app_id
                where r.id = release_id and a.developer_id = auth.uid() and r.status = 'uploaded')
    and public.release_file_count(release_id) < 20
  );
-- A mistaken upload can be removed only before it has been scanned or published.
create policy release_files_delete on public.release_files for delete to authenticated
  using (
    exists (select 1 from public.releases r join public.apps a on a.id = r.app_id
            where r.id = release_id and a.developer_id = auth.uid()
              and r.status in ('uploaded', 'scan_failed', 'rejected'))
  );

-- A release cannot reach review without at least one executable.
create function public.require_executable() returns trigger language plpgsql as $$
begin
  if new.status = 'in_review' and old.status is distinct from 'in_review'
     and not exists (select 1 from public.release_files where release_id = new.id and kind = 'executable') then
    raise exception 'a release needs an executable before review';
  end if;
  return new;
end $$;
create trigger releases_require_executable before update of status on public.releases
  for each row execute function public.require_executable();

-- Public views: only approved releases of published apps, without storage paths or notes
-- about review. They run with the view owner's rights on purpose.
create view public.published_releases as
  select r.id, r.app_id, r.version, r.release_notes, r.min_windows, r.published_at,
         (select coalesce(sum(f.size_bytes), 0)::bigint from public.release_files f where f.release_id = r.id) as total_size_bytes
  from public.releases r
  join public.apps a on a.id = r.app_id
  where r.status = 'approved' and a.status = 'published';
grant select on public.published_releases to anon, authenticated;

-- Public file list per release: name, type, size and checksum. No storage paths.
create view public.published_release_files as
  select f.id, f.release_id, f.kind, f.file_name, f.size_bytes, f.sha256
  from public.release_files f
  join public.releases r on r.id = f.release_id
  join public.apps a on a.id = r.app_id
  where r.status = 'approved' and a.status = 'published';
grant select on public.published_release_files to anon, authenticated;

-- ----------------------------------------------------------------- scans
create table public.scans (
  id          uuid primary key default gen_random_uuid(),
  release_id  uuid not null references public.releases on delete cascade,
  engine      text not null,
  verdict     text not null check (verdict in ('clean', 'suspicious', 'malicious', 'error')),
  detections  integer not null default 0 check (detections >= 0),
  report      jsonb,
  created_at  timestamptz not null default now()
);
create index scans_release_idx on public.scans (release_id);
alter table public.scans enable row level security;
revoke all on public.scans from anon, authenticated;
grant select on public.scans to authenticated;
create policy scans_select on public.scans for select to authenticated
  using (
    public.is_admin()
    or exists (select 1 from public.releases r join public.apps a on a.id = r.app_id
               where r.id = release_id and a.developer_id = auth.uid())
  );

-- --------------------------------------------------------------- reports
create table public.reports (
  id             uuid primary key default gen_random_uuid(),
  app_id         uuid not null references public.apps on delete cascade,
  release_id     uuid references public.releases on delete set null,
  category       text not null check (category in ('malware', 'copyright', 'misleading', 'illegal', 'privacy', 'other')),
  details        text not null check (char_length(details) between 1 and 4000),
  reporter_email text check (reporter_email is null or reporter_email like '%_@_%'),
  status         report_status not null default 'open',
  resolution     text,
  created_at     timestamptz not null default now()
);
create index reports_status_idx on public.reports (status);
alter table public.reports enable row level security;
revoke all on public.reports from anon, authenticated;
grant insert (app_id, release_id, category, details, reporter_email) on public.reports to anon, authenticated;
grant select on public.reports to authenticated;
create policy reports_insert on public.reports for insert to anon, authenticated
  with check (exists (select 1 from public.apps a where a.id = app_id and a.status = 'published'));
create policy reports_select on public.reports for select to authenticated
  using (public.is_admin());

-- ------------------------------------------------------------- downloads
create table public.download_events (
  id          bigint generated always as identity primary key,
  release_id  uuid not null references public.releases on delete cascade,
  created_at  timestamptz not null default now()
);
create index download_events_release_idx on public.download_events (release_id);
alter table public.download_events enable row level security;
revoke all on public.download_events from anon, authenticated;

-- Counts only; no per-person data is stored.
create view public.app_download_counts as
  select a.id as app_id, count(e.id)::bigint as downloads
  from public.apps a
  left join public.releases r on r.app_id = a.id
  left join public.download_events e on e.release_id = r.id
  where a.status = 'published'
  group by a.id;
grant select on public.app_download_counts to anon, authenticated;

create function public.log_download(p_release uuid) returns void
language sql security definer set search_path = public as $$
  insert into public.download_events (release_id)
  select r.id from public.releases r join public.apps a on a.id = r.app_id
  where r.id = p_release and r.status = 'approved' and a.status = 'published'
$$;
revoke all on function public.log_download(uuid) from public;
grant execute on function public.log_download(uuid) to anon, authenticated;

-- --------------------------------------------------------------- strikes
create table public.strikes (
  id            uuid primary key default gen_random_uuid(),
  developer_id  uuid not null references public.developers on delete cascade,
  reason        text not null,
  created_by    uuid references auth.users,
  created_at    timestamptz not null default now()
);
alter table public.strikes enable row level security;
revoke all on public.strikes from anon, authenticated;
grant select on public.strikes to authenticated;
create policy strikes_select on public.strikes for select to authenticated
  using (developer_id = auth.uid() or public.is_admin());

-- ------------------------------------------------------------- functions
-- Developer accepts the current Developer Agreement + Content Policy.
create function public.accept_terms(p_version text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  update public.developers
     set terms_version = p_version,
         terms_accepted_at = now(),
         status = case when status = 'pending' then 'active' else status end
   where id = auth.uid();
  if not found then raise exception 'create a developer profile first'; end if;
end $$;

-- Developer submits a draft app. It needs at least one release that passed scanning.
create function public.submit_app_for_review(p_app uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.apps a join public.developers d on d.id = a.developer_id
                 where a.id = p_app and a.developer_id = auth.uid() and a.status = 'draft'
                   and d.status = 'active') then
    raise exception 'app not found, not a draft, or developer not active';
  end if;
  if not exists (select 1 from public.releases where app_id = p_app and status = 'in_review') then
    raise exception 'upload a release that has passed scanning first';
  end if;
  update public.apps set status = 'in_review' where id = p_app;
end $$;

-- Admin approves or rejects a release that passed scanning.
create function public.admin_review_release(p_release uuid, p_approve boolean, p_note text)
returns void language plpgsql security definer set search_path = public as $$
declare v_app uuid;
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  select app_id into v_app from public.releases where id = p_release and status = 'in_review';
  if v_app is null then raise exception 'release is not awaiting review'; end if;
  if p_approve then
    update public.releases
       set status = 'approved', review_note = p_note, reviewed_by = auth.uid(),
           reviewed_at = now(), published_at = now()
     where id = p_release;
    update public.apps set status = 'published' where id = v_app and status in ('draft', 'in_review');
  else
    update public.releases
       set status = 'rejected', review_note = p_note, reviewed_by = auth.uid(), reviewed_at = now()
     where id = p_release;
  end if;
end $$;

-- Admin delists an app (or restores it). Releases stay as they are.
create function public.admin_set_app_status(p_app uuid, p_status app_status)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  update public.apps set status = p_status where id = p_app;
end $$;

-- Admin delists a single release (for example after a later re-scan fails).
create function public.admin_delist_release(p_release uuid, p_note text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  update public.releases
     set status = 'delisted', review_note = p_note, reviewed_by = auth.uid(), reviewed_at = now()
   where id = p_release;
end $$;

-- Admin resolves a report.
create function public.admin_resolve_report(p_report uuid, p_status report_status, p_resolution text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  update public.reports set status = p_status, resolution = p_resolution where id = p_report;
end $$;

-- Admin records a strike. Two strikes in 12 months suspend the developer and delist their apps.
create function public.admin_add_strike(p_developer uuid, p_reason text)
returns integer language plpgsql security definer set search_path = public as $$
declare v_count integer;
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  insert into public.strikes (developer_id, reason, created_by) values (p_developer, p_reason, auth.uid());
  select count(*) into v_count from public.strikes
   where developer_id = p_developer and created_at > now() - interval '12 months';
  if v_count >= 2 then
    update public.developers set status = 'suspended' where id = p_developer and status <> 'banned';
    update public.apps set status = 'delisted' where developer_id = p_developer and status in ('published', 'in_review');
  end if;
  return v_count;
end $$;

-- Admin bans a developer outright (malware, fraud, illegal content).
create function public.admin_ban_developer(p_developer uuid, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  update public.developers set status = 'banned' where id = p_developer;
  update public.apps set status = 'delisted' where developer_id = p_developer;
  insert into public.strikes (developer_id, reason, created_by) values (p_developer, 'BAN: ' || p_reason, auth.uid());
end $$;

-- Only signed-in users may call the functions above (they check admin themselves).
revoke all on function
  public.accept_terms(text), public.submit_app_for_review(uuid),
  public.admin_review_release(uuid, boolean, text), public.admin_set_app_status(uuid, app_status),
  public.admin_delist_release(uuid, text), public.admin_resolve_report(uuid, report_status, text),
  public.admin_add_strike(uuid, text), public.admin_ban_developer(uuid, text)
  from public;
grant execute on function
  public.accept_terms(text), public.submit_app_for_review(uuid),
  public.admin_review_release(uuid, boolean, text), public.admin_set_app_status(uuid, app_status),
  public.admin_delist_release(uuid, text), public.admin_resolve_report(uuid, report_status, text),
  public.admin_add_strike(uuid, text), public.admin_ban_developer(uuid, text)
  to authenticated;
