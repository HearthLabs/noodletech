# Marketplace platform

Database for the Noodle app marketplace (Supabase / Postgres).

- `supabase/migrations/0001_init.sql` — tables, row-level security, review and strike functions.
- `supabase/migrations/0002_storage.sql` — storage buckets and rules (Supabase only).
- `supabase/migrations/0003_automation.sql` — trust levels, holds, append-only decision log, and `record_scan_decision`, the one function the scan pipeline calls.
- `tests/rls.test.mjs` — runs 0001 in an in-process Postgres and checks who can read and write what. Run `npm install && npm test`.

Each release is one standalone `.exe` plus documents (`.pdf`, `.txt`, `.md`), up to 20 files. Files are read-only once uploaded: the database blocks any update, and the storage bucket blocks overwrite and delete.

Flow: developer signs up → accepts terms → creates app → adds a release and uploads its files (storage) →
server scans it and sets the release to `in_review` → developer submits the app → admin approves →
app and release become public.

Automated review: after the scan stages finish, the server calls `record_scan_decision(release, 'green'|'yellow'|'red', score, reason)`.
Red is rejected with a strike; yellow goes to a person; green from a new developer is held 24 hours for a person;
green from a trusted developer is auto-approved (5% random spot checks). Two approved releases and no strikes promote a developer to trust 1.
Every decision is written to `release_decisions`, which nobody can edit.

## Functions (`supabase/functions/`)

- `scan-release` — `POST {release_id}`. A developer can scan their own release; the server can scan any. Runs file checks, VirusTotal, executable and secret analysis, the sandbox hook and the listing check, then records one decision. Returns 200 decided, 202 pending (call again), or an error.
- `scan-sweep` — server only. Retries releases stuck in `scanning`. Schedule it every 5 minutes (see below).
- `download` — `GET ?file=<file id>`. Public. Redirects to a 60-second signed link, only for files of approved releases of published apps, and counts executable downloads.
- `_shared/` — the logic, written against small interfaces so it is tested without a network (`tests/functions.test.ts`).

Run tests: `npm install && npm test` (database rules) and `npm run test:functions` (needs Deno). `npm run check` type-checks the functions.

### Deploy

```
supabase db push
supabase secrets set --env-file supabase/functions/.env
supabase functions deploy scan-release scan-sweep download
```

Schedule the sweep in the SQL editor (needs the pg_cron and pg_net extensions; replace the project URL and key):

```sql
select cron.schedule('scan-sweep', '*/5 * * * *', $$
  select net.http_post(
    url := 'https://<project>.supabase.co/functions/v1/scan-sweep',
    headers := jsonb_build_object('Authorization', 'Bearer <service role key>'));
$$);
```

### Known limits

- **No sandbox yet.** `sandbox.ts` is a hook with no provider. Until one is plugged in, `REQUIRE_SANDBOX=true` sends every release to a person.
- **Signatures are detected, not verified.** The scan records whether an executable carries an embedded signature; it does not check the certificate chain.
- **File size.** Files over 64 MB (`MAX_AUTO_BYTES`) get hash-only checks and go to a person, because edge functions have limited memory.
- **Re-runs replace earlier scan rows** for that release.
- **Add rate limiting** in front of `download` and `scan-release` before launch.
- VirusTotal endpoints and limits are marked `[VERIFY]` in `virustotal.ts`.

Not built yet: the web pages (sign up, upload, review queue, app pages).

## Web pages

Plain ES modules, no build step (GitHub Pages serves them as is).

- `/store/` public app list and app pages; `/developers/` sign-in, upload and release status; `/admin/` review queue (admins only); `/legal/` draft policy pages.
- Setup: put the Supabase URL and anon key in `assets/config.js`. In Supabase Auth, add `https://noodletechnology.com/developers/` as a redirect URL. Set `ALLOWED_ORIGINS` for the `scan-release` function.
- Legal pages are generated from the legal drafts doc and carry a DRAFT banner. Remove it only after a lawyer signs off.

Known limits: uploads use one XHR per file (no resume, no cancel); pages are client-rendered (weak SEO); storage objects of deleted releases are not cleaned up yet; pages have been structure-checked and unit-tested but not yet exercised in a real browser against a live Supabase project.
