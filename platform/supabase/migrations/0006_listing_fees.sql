-- Listing fees and developer-set prices.
--
-- Every app pays a registration fee before it goes live. One fee covers listing_term()
-- (3 years), and is set by the size of its releases (the total of the files in one release,
-- using the largest release that is live or waiting):
--   tier 1  up to 250 MB   $15
--   tier 2  up to 1 GB     $25
--   over 1 GB is not accepted.
-- A release in a bigger tier than the one paid for needs an upgrade (the difference in price,
-- same end date) before it can go live. When the term runs out the app returns to draft and
-- leaves the store; renewing puts it straight back.
--
-- Admins can also remove an app (admin_set_app_status 'delisted'), or ask its developer for an
-- extra fee to cover costs such as heavy downloads (admin_request_fee). An extra fee left unpaid
-- past its due date takes the app out of the store until it is paid.
--
-- Payments are taken by Stripe Checkout in the `listing-fee` function and recorded only by the
-- `stripe-webhook` function (service role) through record_listing_payment.
--
-- Developers set their app's price (free, or US$1 to US$1,000) and can change it at any time,
-- including after the app is live, through set_app_price.

-- ----------------------------------------------------------------- tiers
create function public.listing_tier(p_bytes bigint) returns smallint
language sql immutable as $$
  select case
    when p_bytes <= 250::bigint * 1024 * 1024  then 1
    when p_bytes <= 1024::bigint * 1024 * 1024 then 2
    else null end::smallint
$$;

create function public.listing_tier_price(p_tier smallint) returns integer
language sql immutable as $$
  select case p_tier when 1 then 1500 when 2 then 2500 end
$$;

-- How long one registration fee keeps an app listed. Change it here only.
create function public.listing_term() returns interval
language sql immutable as $$ select interval '3 years' $$;

create function public.release_size(p_release uuid) returns bigint
language sql stable security definer set search_path = public as $$
  select coalesce(sum(size_bytes), 0)::bigint from public.release_files where release_id = p_release
$$;

-- One release may not hold more than 1 GB in total.
create function public.release_size_limit() returns trigger language plpgsql as $$
begin
  if public.release_size(new.release_id) + new.size_bytes > 1024::bigint * 1024 * 1024 then
    raise exception 'a release can hold at most 1 GB of files';
  end if;
  return new;
end $$;
create trigger release_files_size_limit before insert on public.release_files
  for each row execute function public.release_size_limit();

-- -------------------------------------------------------------- app columns
alter table public.apps
  add column listed_until timestamptz,
  add column paid_tier    smallint check (paid_tier between 1 and 2);

-- Prices: free, or US$1 to US$1,000.
alter table public.apps drop constraint apps_price_cents_check;
alter table public.apps add constraint apps_price_cents_check
  check (price_cents = 0 or price_cents between 100 and 100000);

-- A green release whose size is past the paid tier waits here until the fee is paid.
alter table public.releases drop constraint releases_review_flag_check;
alter table public.releases add constraint releases_review_flag_check
  check (review_flag in ('hold', 'spot_check', 'attention', 'fee_due'));

-- ----------------------------------------------------------------- payments
create table public.listing_payments (
  id                 uuid primary key default gen_random_uuid(),
  app_id             uuid not null references public.apps on delete cascade,
  developer_id       uuid not null references public.developers on delete cascade,
  kind               text not null check (kind in ('new', 'renewal', 'upgrade', 'extra')),
  tier               smallint check (tier between 1 and 2),
  amount_cents       integer not null check (amount_cents > 0),
  stripe_session_id  text not null unique,
  listed_until       timestamptz not null,
  created_at         timestamptz not null default now()
);
create index listing_payments_app_idx on public.listing_payments (app_id);
alter table public.listing_payments enable row level security;
revoke all on public.listing_payments from anon, authenticated;
grant select on public.listing_payments to authenticated;
create policy listing_payments_select on public.listing_payments for select to authenticated
  using (developer_id = auth.uid() or public.is_admin());

-- ------------------------------------------------------------ extra fees
-- An admin asks a developer for an extra fee, for example when an app's downloads cost more
-- than its registration fee covers. The developer sees it in the portal and pays by card.
create table public.fee_requests (
  id            uuid primary key default gen_random_uuid(),
  app_id        uuid not null references public.apps on delete cascade,
  developer_id  uuid not null references public.developers on delete cascade,
  amount_cents  integer not null check (amount_cents between 100 and 100000),
  reason        text not null check (char_length(reason) between 1 and 1000),
  due_at        timestamptz not null,
  status        text not null default 'open' check (status in ('open', 'paid', 'cancelled')),
  stripe_session_id text unique,
  created_by    uuid references auth.users,
  created_at    timestamptz not null default now(),
  paid_at       timestamptz
);
create index fee_requests_app_idx on public.fee_requests (app_id);
alter table public.fee_requests enable row level security;
revoke all on public.fee_requests from anon, authenticated;
grant select on public.fee_requests to authenticated;
create policy fee_requests_select on public.fee_requests for select to authenticated
  using (developer_id = auth.uid() or public.is_admin());

create function public.admin_request_fee(p_app uuid, p_amount_cents integer, p_reason text, p_days integer default 30)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_dev uuid; v_id uuid;
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  if p_days is null or p_days < 7 then raise exception 'give the developer at least 7 days'; end if;
  select developer_id into v_dev from public.apps where id = p_app;
  if v_dev is null then raise exception 'app not found'; end if;
  insert into public.fee_requests (app_id, developer_id, amount_cents, reason, due_at, created_by)
  values (p_app, v_dev, p_amount_cents, p_reason, now() + make_interval(days => p_days), auth.uid())
  returning id into v_id;
  return v_id;
end $$;

create function public.admin_cancel_fee_request(p_request uuid) returns void
language plpgsql security definer set search_path = public as $$
declare v_app uuid;
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  update public.fee_requests set status = 'cancelled' where id = p_request and status = 'open'
  returning app_id into v_app;
  if v_app is null then raise exception 'no open request with that id'; end if;
  perform public._relist_if_clear(v_app);
end $$;

-- An app with an unpaid extra fee past its due date stays out of the store.
create function public._has_overdue_fee(p_app uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.fee_requests where app_id = p_app and status = 'open' and due_at <= now())
$$;

-- Puts an app that was taken out back in the store once nothing is owed.
create function public._relist_if_clear(p_app uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.apps a set status = 'published'
   where a.id = p_app and a.status = 'draft'
     and a.listed_until is not null and a.listed_until > now()
     and not public._has_overdue_fee(p_app)
     and exists (select 1 from public.releases where app_id = p_app and status = 'approved');
end $$;

-- Called by the stripe-webhook function. Safe to call twice.
create function public.record_fee_request_payment(p_request uuid, p_amount_cents integer, p_session text)
returns void language plpgsql security definer set search_path = public as $$
declare q record;
begin
  select * into q from public.fee_requests where id = p_request for update;
  if not found then raise exception 'fee request not found'; end if;
  if exists (select 1 from public.listing_payments where stripe_session_id = p_session) then return; end if;
  if p_amount_cents <> q.amount_cents then raise exception 'paid amount does not match the request'; end if;
  update public.fee_requests set status = 'paid', paid_at = now(), stripe_session_id = p_session where id = p_request;
  insert into public.listing_payments (app_id, developer_id, kind, tier, amount_cents, stripe_session_id, listed_until)
  select q.app_id, q.developer_id, 'extra', null, p_amount_cents, p_session, coalesce(a.listed_until, now())
    from public.apps a where a.id = q.app_id;
  perform public._relist_if_clear(q.app_id);
end $$;

-- ------------------------------------------------------------------ quotes
-- Tier the app needs: its largest release that is waiting for review or live.
create function public._app_needed_tier(p_app uuid) returns smallint
language sql stable security definer set search_path = public as $$
  select max(public.listing_tier(public.release_size(r.id)))
    from public.releases r
   where r.app_id = p_app and r.status in ('in_review', 'approved')
$$;

-- True when the app's paid listing is current and covers the given tier.
create function public._fee_covers(p_app uuid, p_tier smallint) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(a.listed_until > now() and a.paid_tier >= coalesce(p_tier, 1), false)
    from public.apps a where a.id = p_app
$$;

-- What the developer owes now. kind is 'none' when nothing is due.
-- With p_renew, a current listing is extended by one term at the larger of the paid and needed tier.
create function public._listing_fee_quote(p_app uuid, p_renew boolean default false)
returns table (kind text, tier smallint, amount_cents integer, needed_tier smallint,
               paid_tier smallint, listed_until timestamptz, largest_release_bytes bigint)
language plpgsql stable security definer set search_path = public as $$
declare
  a record;
  v_bytes bigint;
  v_need smallint;
  v_active boolean;
begin
  select * into a from public.apps where id = p_app;
  if not found then raise exception 'app not found'; end if;
  select max(public.release_size(r.id)) into v_bytes
    from public.releases r where r.app_id = p_app and r.status in ('in_review', 'approved');
  v_bytes := coalesce(v_bytes, 0);
  v_need := coalesce(public.listing_tier(v_bytes), 0);
  if v_need = 0 and v_bytes > 0 then raise exception 'releases over 1 GB are not accepted'; end if;
  v_need := greatest(v_need, 1);
  v_active := a.listed_until is not null and a.listed_until > now();

  if v_active and p_renew then
    return query select 'renewal'::text, greatest(v_need, a.paid_tier), public.listing_tier_price(greatest(v_need, a.paid_tier)),
                        v_need, a.paid_tier, a.listed_until, v_bytes;
  elsif v_active and a.paid_tier >= v_need then
    return query select 'none'::text, a.paid_tier, 0, v_need, a.paid_tier, a.listed_until, v_bytes;
  elsif v_active then
    return query select 'upgrade'::text, v_need,
                        public.listing_tier_price(v_need) - public.listing_tier_price(a.paid_tier),
                        v_need, a.paid_tier, a.listed_until, v_bytes;
  else
    return query select (case when a.listed_until is null then 'new' else 'renewal' end)::text, v_need,
                        public.listing_tier_price(v_need), v_need, a.paid_tier, a.listed_until, v_bytes;
  end if;
end $$;

-- Browser version: only for your own app (admins may look at any).
create function public.listing_fee_quote(p_app uuid, p_renew boolean default false)
returns table (kind text, tier smallint, amount_cents integer, needed_tier smallint,
               paid_tier smallint, listed_until timestamptz, largest_release_bytes bigint)
language plpgsql stable security definer set search_path = public as $$
begin
  if not exists (select 1 from public.apps where id = p_app and (developer_id = auth.uid() or public.is_admin())) then
    raise exception 'app not found';
  end if;
  return query select * from public._listing_fee_quote(p_app, p_renew);
end $$;

-- ------------------------------------------------------- recording a payment
-- Called by the stripe-webhook function after Stripe confirms the payment. Safe to call twice.
create function public.record_listing_payment(
  p_app uuid, p_kind text, p_tier smallint, p_amount_cents integer, p_session text
) returns timestamptz
language plpgsql security definer set search_path = public as $$
declare
  a record;
  v_until timestamptz;
  r record;
begin
  if p_kind not in ('new', 'renewal', 'upgrade') then raise exception 'unknown payment kind'; end if;
  if p_tier not between 1 and 2 then raise exception 'unknown tier'; end if;
  select * into a from public.apps where id = p_app for update;
  if not found then raise exception 'app not found'; end if;
  if exists (select 1 from public.listing_payments where stripe_session_id = p_session) then
    return a.listed_until;
  end if;

  if p_kind = 'upgrade' and a.listed_until is not null and a.listed_until > now() then
    v_until := a.listed_until;
    update public.apps set paid_tier = greatest(coalesce(paid_tier, 1), p_tier) where id = p_app;
  else
    v_until := greatest(coalesce(a.listed_until, now()), now()) + public.listing_term();
    update public.apps
       set listed_until = v_until,
           paid_tier = case when a.listed_until > now() then greatest(coalesce(a.paid_tier, 1), p_tier) else p_tier end
     where id = p_app;
  end if;

  insert into public.listing_payments (app_id, developer_id, kind, tier, amount_cents, stripe_session_id, listed_until)
  values (p_app, a.developer_id, p_kind, p_tier, p_amount_cents, p_session, v_until);

  -- Releases that passed every check but were waiting for this fee go live now.
  for r in select id from public.releases
            where app_id = p_app and status = 'in_review' and review_flag = 'fee_due'
              and public._fee_covers(p_app, public.listing_tier(public.release_size(id))) loop
    update public.releases set status = 'approved', reviewed_at = now(), published_at = now(), review_flag = null
     where id = r.id;
    insert into public.release_decisions (release_id, decision, reason)
    values (r.id, 'auto_approved', 'Listing fee paid');
  end loop;

  -- A listing that had run out goes back into the store when it is renewed
  -- (unless an extra fee is overdue).
  if a.status = 'draft' and a.listed_until is not null then
    perform public._relist_if_clear(p_app);
  elsif a.status = 'in_review'
     and exists (select 1 from public.releases where app_id = p_app and status = 'approved') then
    update public.apps set status = 'published' where id = p_app;
  end if;
  return v_until;
end $$;

-- ------------------------------------------------------------- running out
-- Live apps whose term has ended, or with an extra fee unpaid past its due date, go back to
-- draft and leave the store. The scan-sweep
-- function calls this every few minutes.
create function public.expire_listings() returns integer
language plpgsql security definer set search_path = public as $$
declare v_count integer;
begin
  update public.apps a set status = 'draft'
   where a.status in ('published', 'in_review')
     and (a.listed_until <= now() or public._has_overdue_fee(a.id));
  get diagnostics v_count = row_count;
  return v_count;
end $$;

-- ------------------------------------------------------------------ prices
-- The developer can change the price at any time, live or not. New sales use the new price.
create function public.set_app_price(p_app uuid, p_price_cents integer) returns void
language plpgsql security definer set search_path = public as $$
begin
  if p_price_cents is null or not (p_price_cents = 0 or p_price_cents between 100 and 100000) then
    raise exception 'price must be free or between $1 and $1,000';
  end if;
  update public.apps set price_cents = p_price_cents
   where id = p_app and developer_id = auth.uid() and status <> 'delisted';
  if not found then raise exception 'app not found or removed'; end if;
end $$;

-- ------------------------------------------------------ gates on going live
-- Submitting needs a current listing fee that covers the size of the release.
create or replace function public.submit_app_for_review(p_app uuid) returns void
language plpgsql security definer set search_path = public as $$
declare q record;
begin
  if not exists (select 1 from public.apps a join public.developers d on d.id = a.developer_id
                 where a.id = p_app and a.developer_id = auth.uid() and a.status = 'draft'
                   and d.status = 'active') then
    raise exception 'app not found, not a draft, or developer not active';
  end if;
  if not exists (select 1 from public.releases where app_id = p_app and status in ('in_review', 'approved')) then
    raise exception 'upload a release that has passed scanning first';
  end if;
  select * into q from public._listing_fee_quote(p_app);
  if q.kind <> 'none' then
    raise exception 'pay the listing fee first ($% for this size)', (q.amount_cents / 100);
  end if;
  if public._has_overdue_fee(p_app) then
    raise exception 'pay the extra fee Noodle asked for first';
  end if;
  update public.apps set status = 'in_review' where id = p_app;
  if exists (select 1 from public.releases where app_id = p_app and status = 'approved') then
    update public.apps set status = 'published' where id = p_app;
  end if;
end $$;

-- Automated approval: a green release of a live (or submitted) app that is bigger than the
-- paid tier waits as 'fee_due' instead of going live.
create or replace function public.record_scan_decision(
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
  elsif v.app_status <> 'draft'
        and not public._fee_covers(v.app_id, public.listing_tier(public.release_size(p_release))) then
    update public.releases set status = 'in_review', review_flag = 'fee_due' where id = p_release;
    v_decision := 'held';
    p_reason := 'Passed the checks. Waiting for the listing fee for this size: ' || p_reason;
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

-- Human approval of a release of a live (or submitted) app also needs the fee to cover its size.
create or replace function public.admin_review_release(p_release uuid, p_approve boolean, p_note text)
returns void language plpgsql security definer set search_path = public as $$
declare v record;
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  select r.app_id, r.hold_until, a.developer_id, a.status as app_status into v
    from public.releases r join public.apps a on a.id = r.app_id
   where r.id = p_release and r.status = 'in_review';
  if not found then raise exception 'release is not awaiting review'; end if;
  if p_approve and v.hold_until is not null and v.hold_until > now() then
    raise exception 'release is on hold until %', v.hold_until;
  end if;
  if p_approve and v.app_status <> 'draft'
     and not public._fee_covers(v.app_id, public.listing_tier(public.release_size(p_release))) then
    -- Approved by a person, but it waits for the fee and goes live by itself once it is paid.
    update public.releases set review_flag = 'fee_due', review_note = p_note, reviewed_by = auth.uid(),
           reviewed_at = now(), hold_until = null
     where id = p_release;
    insert into public.release_decisions (release_id, decision, reason, decided_by)
    values (p_release, 'human_approved', 'Approved; waiting for the listing fee for this size. ' || coalesce(p_note, ''), auth.uid());
    return;
  end if;
  if p_approve then
    update public.releases
       set status = 'approved', review_note = p_note, reviewed_by = auth.uid(),
           reviewed_at = now(), published_at = now(), review_flag = null
     where id = p_release;
    update public.apps set status = 'published' where id = v.app_id and status in ('draft', 'in_review')
       and public._fee_covers(v.app_id, public._app_needed_tier(v.app_id));
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

-- ------------------------------------------------------------ public views
-- The store shows the price. Paid apps cannot be downloaded until buying is built.
create or replace view public.published_apps as
  select a.id, a.slug, a.name, a.summary, a.description, a.category, a.license_name,
         a.homepage_url, a.support_url, a.created_at, a.updated_at,
         d.display_name as developer_name,
         coalesce(c.downloads, 0)::bigint as downloads,
         a.price_cents
  from public.apps a
  join public.developers d on d.id = a.developer_id
  left join public.app_download_counts c on c.app_id = a.id
  where a.status = 'published' and d.status = 'active';
grant select on public.published_apps to anon, authenticated;

create or replace view public.published_release_files as
  select f.id, f.release_id, f.kind, f.file_name, f.size_bytes, f.sha256,
         a.price_cents as app_price_cents
  from public.release_files f
  join public.releases r on r.id = f.release_id
  join public.apps a on a.id = r.app_id
  where r.status = 'approved' and a.status = 'published';
grant select on public.published_release_files to anon, authenticated;

-- ------------------------------------------------------------------ grants
revoke all on function
  public._app_needed_tier(uuid), public._fee_covers(uuid, smallint),
  public._listing_fee_quote(uuid, boolean),
  public.record_listing_payment(uuid, text, smallint, integer, text),
  public.expire_listings(), public._has_overdue_fee(uuid), public._relist_if_clear(uuid),
  public.record_fee_request_payment(uuid, integer, text)
  from public, anon, authenticated;
grant execute on function
  public._listing_fee_quote(uuid, boolean),
  public.record_listing_payment(uuid, text, smallint, integer, text),
  public.record_fee_request_payment(uuid, integer, text),
  public.expire_listings()
  to service_role;

revoke all on function public.admin_request_fee(uuid, integer, text, integer), public.admin_cancel_fee_request(uuid)
  from public, anon;
grant execute on function public.admin_request_fee(uuid, integer, text, integer), public.admin_cancel_fee_request(uuid)
  to authenticated;

revoke all on function public.listing_fee_quote(uuid, boolean), public.set_app_price(uuid, integer),
  public.submit_app_for_review(uuid), public.admin_review_release(uuid, boolean, text)
  from public, anon;
grant execute on function public.listing_fee_quote(uuid, boolean), public.set_app_price(uuid, integer),
  public.submit_app_for_review(uuid), public.admin_review_release(uuid, boolean, text)
  to authenticated;

revoke all on function public.record_scan_decision(uuid, text, integer, text, numeric) from public, anon, authenticated;
grant execute on function public.record_scan_decision(uuid, text, integer, text, numeric) to service_role;
