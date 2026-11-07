-- Storage buckets and access rules (Supabase only; needs the storage schema).
--  app-files   : private. Each release holds one .exe plus documents (.pdf, .txt, .md). Developers
--                write into their own folder (<user id>/...) and cannot overwrite or delete files,
--                so a file is read-only once uploaded and a published file never changes.
--                Downloads for the public are served by a server function that checks the
--                release is approved and returns a short-lived signed URL.
--  screenshots : public read. Developers manage their own folder.

insert into storage.buckets (id, name, public, file_size_limit)
values
  ('app-files',   'app-files',   false, 5368709120),
  ('screenshots', 'screenshots', true,  10485760)
on conflict (id) do nothing;

create policy app_files_insert on storage.objects for insert to authenticated
  with check (
    bucket_id = 'app-files'
    and lower(name) ~ '\.(exe|pdf|txt|md)$'
    and (storage.foldername(name))[1] = auth.uid()::text
    and exists (select 1 from public.developers d where d.id = auth.uid() and d.status = 'active')
  );

create policy app_files_select on storage.objects for select to authenticated
  using (
    bucket_id = 'app-files'
    and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin())
  );

create policy screenshots_insert on storage.objects for insert to authenticated
  with check (
    bucket_id = 'screenshots'
    and (storage.foldername(name))[1] = auth.uid()::text
    and exists (select 1 from public.developers d where d.id = auth.uid() and d.status = 'active')
  );

create policy screenshots_delete on storage.objects for delete to authenticated
  using (bucket_id = 'screenshots' and (storage.foldername(name))[1] = auth.uid()::text);

create policy screenshots_read on storage.objects for select to anon, authenticated
  using (bucket_id = 'screenshots');
