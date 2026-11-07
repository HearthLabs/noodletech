-- Additions the web pages need.

-- Public catalog view: published apps with the developer's display name and a download count.
-- Runs with the owner's rights on purpose (visitors cannot read the developers table).
create view public.published_apps as
  select a.id, a.slug, a.name, a.summary, a.description, a.category, a.license_name,
         a.homepage_url, a.support_url, a.created_at, a.updated_at,
         d.display_name as developer_name,
         coalesce(c.downloads, 0)::bigint as downloads
  from public.apps a
  join public.developers d on d.id = a.developer_id
  left join public.app_download_counts c on c.app_id = a.id
  where a.status = 'published' and d.status = 'active';
grant select on public.published_apps to anon, authenticated;

-- A developer can remove their own release until it has been approved, so a failed or
-- abandoned upload does not block re-using the version number. Its files and scan rows go with it.
grant delete on public.releases to authenticated;
create policy releases_delete on public.releases for delete to authenticated
  using (
    status in ('uploaded', 'scan_failed', 'rejected')
    and exists (select 1 from public.apps a where a.id = app_id and a.developer_id = auth.uid())
  );
