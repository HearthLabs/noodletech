-- Releases are capped at 1 GB in total (see 0006), so no single file can be bigger either.
update storage.buckets set file_size_limit = 1073741824 where id = 'app-files';
