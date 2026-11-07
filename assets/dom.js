// Tiny helpers for building pages. Text is always inserted with textContent, never as HTML,
// because app names and descriptions are written by other people.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked" || k === "disabled" || k === "selected" || k === "required" || k === "multiple" || k === "open") el[k] = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function fmtBytes(n) {
  const num = Number(n);
  if (!Number.isFinite(num)) return "";
  if (num < 1024) return `${num} B`;
  const units = ["KB", "MB", "GB"];
  let v = num / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function fmtDate(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function fmtDateTime(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

/** Only http(s) links from user-written data become clickable. */
export function safeUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch { return null; }
}

export function slugify(s) {
  return String(s).toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
}

export function notice(kind, ...children) {
  return h("div", { class: `notice ${kind}`, role: kind === "error" ? "alert" : "status" }, ...children);
}

const STATUS_TEXT = {
  uploaded: ["Uploaded", "Waiting to be scanned"],
  scanning: ["Scanning", "Checks are running"],
  in_review: ["In review", "Waiting for approval"],
  approved: ["Approved", "Live in the store"],
  rejected: ["Not approved", "See the reason below"],
  scan_failed: ["Scan failed", "Try again"],
  delisted: ["Removed", "No longer listed"],
  draft: ["Draft", "Not submitted yet"],
  published: ["Published", "Live in the store"],
};
export function statusBadge(status) {
  const [label, tip] = STATUS_TEXT[status] ?? [status, ""];
  return h("span", { class: `badge s-${status}`, title: tip }, label);
}
