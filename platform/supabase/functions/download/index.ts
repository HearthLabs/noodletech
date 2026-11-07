// GET /download?file=<file uuid>
// Public. Sends the visitor to a short-lived signed link, but only for files of approved
// releases of published apps. Add rate limiting in front of this (Cloudflare or Supabase) before launch.
import { adminClient, downloadPorts } from "../_shared/adapter.ts";
import { handleDownload, json } from "../_shared/handlers.ts";

Deno.serve(async (req) => {
  if (req.method !== "GET") return json(405, { error: "GET only" });
  try {
    return await handleDownload(new URL(req.url), downloadPorts(adminClient()));
  } catch (e) {
    console.error("download failed", (e as Error).message);
    return json(500, { error: "download failed" });
  }
});
