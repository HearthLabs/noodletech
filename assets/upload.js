// Uploads a file straight to private storage with progress (the storage client has no progress events).
import { SUPABASE_ANON_KEY, SUPABASE_URL } from "./config.js";

export const MAX_FILE_BYTES = 5 * 1024 * 1024 * 1024; // matches the storage bucket limit
export const MAX_FILES = 20;
export const DOC_EXTENSIONS = [".pdf", ".txt", ".md"];

export function validateSelection(exe, docs) {
  const problems = [];
  if (!exe) problems.push("Choose the program file (.exe).");
  else if (!/\.exe$/i.test(exe.name)) problems.push("The program must be a .exe file.");
  const all = [exe, ...docs].filter(Boolean);
  if (all.length > MAX_FILES) problems.push(`A release can have at most ${MAX_FILES} files.`);
  const seen = new Set();
  for (const f of all) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._ -]{0,99}$/.test(f.name) || f.name.includes("..")) {
      problems.push(`"${f.name}": file names may use letters, numbers, spaces, dots, dashes and underscores only (max 100 characters).`);
    }
    if (f.size <= 0) problems.push(`"${f.name}" is empty.`);
    if (f.size > MAX_FILE_BYTES) problems.push(`"${f.name}" is larger than 5 GB.`);
    const key = f.name.toLowerCase();
    if (seen.has(key)) problems.push(`Two files are named "${f.name}".`);
    seen.add(key);
  }
  for (const d of docs) {
    if (!DOC_EXTENSIONS.some((ext) => d.name.toLowerCase().endsWith(ext))) {
      problems.push(`"${d.name}": documents must be PDF, TXT or Markdown (.pdf, .txt, .md).`);
    }
  }
  return problems;
}

export function uploadFile({ accessToken, bucket, path, file, onProgress = () => {} }) {
  return new Promise((resolve, reject) => {
    const url = `${SUPABASE_URL}/storage/v1/object/${bucket}/${path.split("/").map(encodeURIComponent).join("/")}`;
    const xhr = new XMLHttpRequest();
    xhr.open("POST", url);
    xhr.setRequestHeader("apikey", SUPABASE_ANON_KEY);
    xhr.setRequestHeader("Authorization", `Bearer ${accessToken}`);
    xhr.setRequestHeader("x-upsert", "false"); // never overwrite: uploaded files are read-only
    xhr.setRequestHeader("cache-control", "max-age=3600");
    xhr.setRequestHeader("content-type", file.type || "application/octet-stream");
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
    xhr.onerror = () => reject(new Error("Network error while uploading. Check your connection and try again."));
    xhr.onabort = () => reject(new Error("Upload cancelled."));
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) return resolve();
      let msg = `Upload failed (${xhr.status}).`;
      try { msg = JSON.parse(xhr.responseText).message ?? msg; } catch { /* keep default */ }
      reject(new Error(msg));
    };
    xhr.send(file);
  });
}
