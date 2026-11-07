-- Automated review: trust levels, holds, an append-only decision log, and the single
-- function the scan pipeline calls when scanning is finished.
--
-- Rules (matches the Content and Malware Policy):
--   red    -> release rejected, strike recorded
--   yellow -> goes to the human queue
--   green  -> new developer (trust 0): 24-hour hold plus human look
--             otherwise: ~5% random spot check, else auto-approved and published

alter table public.developers
  add column trust_level smallint not null default 0 check (trust_level between 0 and 2);
alter table public.releases
  add column hold_until  timestamptz,
  add column review_flag text check (review_flag in ('hold', 'spot_check', 'attention'));
alter table public.scans
  add column stage text not null default 'malware_scan'
    check (stage in ('file_checks', 'malware_scan', 'static_analysis', 'sandbox', 'listing_check')),
  add column score integer check (score between 0 and 100);

-- ----------------------------------------------------------- decision log
create type decision_kind as enum
  ('auto_approved', 'auto_rejected', 'held', 'needs_human', 'spot_check', 'human_approved', 'human_rejected');

create table public.release_decisions (
  id          uuid primary key default gen_random_uuid(),
  release_id  uuid not null references public.releases on delete cascade,
  decision    decision_kind not null,
  risk_score  integer,
  reason      text not null,
  decided_by  uuid references auth.users,     -- null = automated
  created_at  timestamptz not null default now()
);
create index release_decisions_release_idx on public.release_decisions (release_id);
alter table public.release_decisions enable row level security;
revoke all on public.release_decisions from anon, authenticated;
grant select on public.release_decisions to authenticated;
create policy release_decisions_select on public.release_decisions for select to authenticated
  using (
    public.is_admin()
    or exists (select 1 from public.releases r join public.apps a on a.id = r.app_id
               where r.id = release_id and a.developer_id = auth.uid())
  );
create function public.decisions_append_only() returns trigger language plpgsql as $$
begin raise exception 'the decision log is append-only'; end $$;
create trigger release_decisions_no_update before update on public.release_decisions
  for each row execute function public.decisions_append_only();

-- --------------------------------------------------------------- helpers
-- Internal: not callable from the browser.
create function public._add_strike(p_dev uuid, p_reason text, p_by uuid) returns integer
language plpgsql security definer set search_path = public as $$
declare v_count integer;
begin
  insert into public.strikes (developer_id, reason, created_by) values (p_dev, p_reason, p_by);
  select count(*) into v_count from public.strikes
   where developer_id = p_dev and created_at > now() - interval '12 months';
  if v_count >= 2 then
    update public.developers set status = 'suspended' where id = p_dev and status <> 'banned';
    update public.apps set status = 'delisted' where developer_id = p_dev and status in ('published', 'in_review');
  end if;
  return v_count;
end $$;

-- Two approved releases and no strikes in 12 months move a new developer to trust level 1.
create function public._maybe_promote(p_dev uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if (select trust_level from public.developers where id = p_dev) = 0
     and (select count(*) from public.releases r join public.apps a on a.id = r.app_id
          where a.developer_id = p_dev and r.status = 'approved') >= 2
     and not exists (select 1 from public.strikes
                     where developer_id = p_dev and created_at > now() - interval '12 months') then
    update public.developers set trust_level = 1 where id = p_dev;
  end if;
end $$;

create or replace function public.admin_add_strike(p_developer uuid, p_reason text)
returns integer language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  return public._add_strike(p_developer, p_reason, auth.uid());
end $$;

create function public.admin_set_trust(p_developer uuid, p_level smallint) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  update public.developers set trust_level = p_level where id = p_developer;
end $$;

-- ------------------------------------------------- pipeline entry point
-- Called by the server (service_role) after all scan stages have run.
create function public.record_scan_decision(
  p_release uuid, p_outcome text, p_score integer, p_reason text, p_spot_rate numeric default 0.05
) returns decision_kind
language plpgsql security definer set search_path = public as $$
declare
  v record;
  v_trust smallint;
  v_decision decision_kind;
begin
  if p_outcome not in ('green', 'yellow', 'red') then raise exception 'outcome must be green, yellow or red'; end if;
  select r.id, r.status, r.app_id, a.developer_id, a.status as app_status
    into v
    from public.releases r join public.apps a on a.id = r.app_id
   where r.id = p_release for update of r;
  if not found or v.status not in ('uploaded', 'scanning') then
    raise exception 'release is not waiting for a scan decision';
  end if;
  select trust_level into v_trust from public.developers where id = v.developer_id;

  if p_outcome = 'red' then
    update public.releases set status = 'rejected', review_note = p_reason, reviewed_at = now() where id = p_release;
    perform public._add_strike(v.developer_id, 'Automated scan: ' || p_reason, null);
    v_decision := 'auto_rejected';
  elsif p_outcome = 'yellow' then
    update public.releases set status = 'in_review', review_flag = 'attention' where id = p_release;
    v_decision := 'needs_human';
  elsif v_trust = 0 then
    update public.releases
       set status = 'in_review', review_flag = 'hold', hold_until = now() + interval '24 hours'
     where id = p_release;
    v_decision := 'held';
  elsif random() < p_spot_rate then
    update public.releases set status = 'in_review', review_flag = 'spot_check' where id = p_release;
    v_decision := 'spot_check';
  else
    update public.releases set status = 'in_review' where id = p_release;   -- passes the executable check
    update public.releases
       set status = 'approved', reviewed_at = now(), published_at = now()
     where id = p_release;
    update public.apps set status = 'published' where id = v.app_id and status = 'in_review';
    perform public._maybe_promote(v.developer_id);
    v_decision := 'auto_approved';
  end if;

  insert into public.release_decisions (release_id, decision, risk_score, reason)
  values (p_release, v_decision, p_score, p_reason);
  return v_decision;
end $$;

-- Human review now logs its decision, respects the hold, and counts toward trust.
create or replace function public.admin_review_release(p_release uuid, p_approve boolean, p_note text)
returns void language plpgsql security definer set search_path = public as $$
declare v record;
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  select r.app_id, r.hold_until, a.developer_id into v
    from public.releases r join public.apps a on a.id = r.app_id
   where r.id = p_release and r.status = 'in_review';
  if not found then raise exception 'release is not awaiting review'; end if;
  if p_approve and v.hold_until is not null and v.hold_until > now() then
    raise exception 'release is on hold until %', v.hold_until;
  end if;
  if p_approve then
    update public.releases
       set status = 'approved', review_note = p_note, reviewed_by = auth.uid(),
           reviewed_at = now(), published_at = now(), review_flag = null
     where id = p_release;
    update public.apps set status = 'published' where id = v.app_id and status in ('draft', 'in_review');
    perform public._maybe_promote(v.developer_id);
  else
    update public.releases
       set status = 'rejected', review_note = p_note, reviewed_by = auth.uid(),
           reviewed_at = now(), review_flag = null
     where id = p_release;
  end if;
  insert into public.release_decisions (release_id, decision, reason, decided_by)
  values (p_release, case when p_approve then 'human_approved' else 'human_rejected' end::decision_kind,
          coalesce(p_note, ''), auth.uid());
end $$;

-- Submitting works whether the release finished scanning before or after the submit.
create or replace function public.submit_app_for_review(p_app uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.apps a join public.developers d on d.id = a.developer_id
                 where a.id = p_app and a.developer_id = auth.uid() and a.status = 'draft'
                   and d.status = 'active') then
    raise exception 'app not found, not a draft, or developer not active';
  end if;
  if not exists (select 1 from public.releases where app_id = p_app and status in ('in_review', 'approved')) then
    raise exception 'upload a release that has passed scanning first';
  end if;
  update public.apps set status = 'in_review' where id = p_app;
  -- A release that was already auto-approved publishes the app straight away.
  if exists (select 1 from public.releases where app_id = p_app and status = 'approved') then
    update public.apps set status = 'published' where id = p_app;
  end if;
end $$;

-- ---------------------------------------------------------------- grants
-- Supabase grants execute on new functions to anon/authenticated/service_role by default,
-- so say who may call what explicitly.
revoke all on function public._add_strike(uuid, text, uuid), public._maybe_promote(uuid),
  public.record_scan_decision(uuid, text, integer, text, numeric)
  from public, anon, authenticated;
grant execute on function public.record_scan_decision(uuid, text, integer, text, numeric) to service_role;

revoke all on function
  public.accept_terms(text), public.submit_app_for_review(uuid),
  public.admin_review_release(uuid, boolean, text), public.admin_set_app_status(uuid, app_status),
  public.admin_delist_release(uuid, text), public.admin_resolve_report(uuid, report_status, text),
  public.admin_add_strike(uuid, text), public.admin_ban_developer(uuid, text),
  public.admin_set_trust(uuid, smallint)
  from public, anon;
grant execute on function
  public.accept_terms(text), public.submit_app_for_review(uuid),
  public.admin_review_release(uuid, boolean, text), public.admin_set_app_status(uuid, app_status),
  public.admin_delist_release(uuid, text), public.admin_resolve_report(uuid, report_status, text),
  public.admin_add_strike(uuid, text), public.admin_ban_developer(uuid, text),
  public.admin_set_trust(uuid, smallint)
  to authenticated;
