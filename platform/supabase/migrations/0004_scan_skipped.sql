-- A stage that could not run (for example no sandbox is configured) is recorded as
-- 'skipped' instead of pretending it passed.
alter table public.scans drop constraint scans_verdict_check;
alter table public.scans add constraint scans_verdict_check
  check (verdict in ('clean', 'suspicious', 'malicious', 'error', 'skipped'));
