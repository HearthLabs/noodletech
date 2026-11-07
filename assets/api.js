// One shared connection to the backend.
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm";
import { SUPABASE_ANON_KEY, SUPABASE_URL } from "./config.js";

export const configured = !SUPABASE_URL.includes("YOUR-PROJECT") && !SUPABASE_ANON_KEY.includes("YOUR-ANON");

export const sb = configured
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true } })
  : null;

export const functionUrl = (name) => `${SUPABASE_URL}/functions/v1/${name}`;
export const downloadUrl = (fileId) => `${functionUrl("download")}?file=${encodeURIComponent(fileId)}`;

/** Throws a readable Error if a database call failed; otherwise returns its data. */
export function ok({ data, error }, what = "request") {
  if (error) throw new Error(friendly(error.message, what));
  return data;
}

function friendly(message, what) {
  if (/duplicate key.*slug/i.test(message)) return "That web address is already taken. Choose another.";
  if (/duplicate key.*version|releases_app_id_version_key/i.test(message)) return "This app already has a release with that version number.";
  if (/row-level security/i.test(message)) return "You don't have permission to do that.";
  if (/check constraint/i.test(message)) return "Some of the information isn't valid. Check the fields and try again.";
  return `${what} failed: ${message}`;
}
