import { clear, fmtBytes, fmtDateTime, h, notice, statusBadge } from "../assets/dom.js";
import { configured, ok, sb } from "../assets/api.js";
import { mountFrame } from "../assets/layout.js";

const main = mountFrame("admin");
let tab = "queue";

async function boot() {
  if (!configured) return;
  const { data } = await sb.auth.getSession();
  if (!data.session) {
    return void main.append(h("h1", {}, "Admin"), notice("info", "Sign in first on the ", h("a", { href: "/developers/" }, "developer page"), ", then come back here."));
  }
  const { data: isAdmin, error } = await sb.rpc("is_admin");
  if (error || isAdmin !== true) return void main.append(h("h1", {}, "Admin"), notice("warn", "This page is for Noodle staff."));
  show();
}

function show() {
  clear(main);
  const tabs = [["queue", "Review queue"], ["reports", "Reports"], ["developers", "Developers"]];
  main.append(h("h1", {}, "Admin"),
    h("div", { class: "tabs", role: "tablist" }, ...tabs.map(([id, label]) =>
      h("button", { role: "tab", "aria-selected": String(tab === id), onclick: () => { tab = id; show(); } }, label))));
  const body = h("div", { class: "stack" });
  main.append(body);
  const view = { queue, reports, developers }[tab];
  view(body).catch((e) => body.append(notice("error", e.message)));
}

// ------------------------------------------------------------ review queue
async function queue(body) {
  const rows = ok(await sb.from("releases")
    .select("*, apps(id,name,slug,summary,description,status,developer_id, developers(display_name,contact_email,trust_level,status)), release_files(*), scans(*), release_decisions(*)")
    .eq("status", "in_review").order("created_at"), "Loading the queue");
  if (rows.length === 0) return void body.append(notice("good", "Nothing is waiting for review."));
  body.append(h("p", { class: "muted" }, `${rows.length} release${rows.length === 1 ? "" : "s"} waiting.`));
  for (const r of rows) body.append(queueItem(r));
}

function queueItem(r) {
  const app = r.apps, d = app.developers;
  const held = r.hold_until && new Date(r.hold_until) > new Date();
  const status = h("div", { "aria-live": "polite" });
  const note = h("textarea", { placeholder: "Note (required to reject; shown to the developer)", "aria-label": "Review note" });
  const act = async (approve) => {
    if (!approve && !note.value.trim()) return void status.replaceChildren(notice("error", "Write a reason so the developer knows what to fix."));
    status.replaceChildren(notice("info", "Saving…"));
    const { error } = await sb.rpc("admin_review_release", { p_release: r.id, p_approve: approve, p_note: note.value.trim() });
    if (error) return void status.replaceChildren(notice("error", error.message));
    show();
  };
  const flags = [];
  if (r.review_flag === "hold") flags.push(held ? `New developer: on hold until ${fmtDateTime(r.hold_until)}` : "New developer: hold has ended");
  if (r.review_flag === "attention") flags.push("Automated checks found something");
  if (r.review_flag === "spot_check") flags.push("Random spot check");
  const decisions = [...(r.release_decisions ?? [])].sort((a, b) => b.created_at.localeCompare(a.created_at));
  const scans = [...(r.scans ?? [])];

  return h("div", { class: "panel" },
    h("div", { class: "row between" },
      h("h2", {}, `${app.name} · v${r.version}`),
      h("div", { class: "row" }, statusBadge(app.status), h("a", { class: "small", href: `/store/#/app/${app.slug}` }, "store page"))),
    h("p", { class: "muted small" }, `By ${d.display_name} (${d.contact_email}) · trust level ${d.trust_level} · uploaded ${fmtDateTime(r.created_at)}`),
    ...flags.map((f) => notice(f.startsWith("Automated") ? "warn" : "info", f)),
    h("p", { class: "pre" }, app.summary, app.description ? `\n\n${app.description}` : ""),
    r.release_notes && h("p", { class: "pre muted small" }, `Release notes: ${r.release_notes}`),

    h("h3", {}, "Why it's here"),
    decisions.length === 0 ? h("p", { class: "muted" }, "No automated decision recorded.") :
      h("ul", { class: "stack small", style: "gap:6px" }, ...decisions.map((x) =>
        h("li", {}, h("strong", {}, x.decision.replaceAll("_", " ")), x.risk_score != null ? ` (risk ${x.risk_score})` : "", ` · ${fmtDateTime(x.created_at)}`, h("br"), x.reason))),

    h("h3", {}, "Automated checks"),
    scans.length === 0 ? h("p", { class: "muted" }, "No stage results saved.") :
      h("table", {}, h("thead", {}, h("tr", {}, ...["Stage", "Result", "Risk", "Findings"].map((t) => h("th", {}, t)))),
        h("tbody", {}, ...scans.map((s) => h("tr", {}, h("td", {}, s.stage.replaceAll("_", " ")), h("td", {}, s.verdict), h("td", {}, s.score ?? ""),
          h("td", { class: "small" }, ((s.report?.flags) ?? []).map((f) => `${f.code}${f.file ? ` (${f.file})` : ""}`).join(", ") || "none"))))),

    h("h3", {}, "Files"),
    h("table", {}, h("thead", {}, h("tr", {}, ...["File", "Size", "SHA-256", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, ...(r.release_files ?? []).map((f) => h("tr", {}, h("td", {}, f.file_name, h("div", { class: "muted small" }, f.kind)), h("td", {}, fmtBytes(f.size_bytes)),
        h("td", { class: "mono" }, f.sha256.slice(0, 16) + "…"),
        h("td", {}, h("button", { class: "btn secondary small", onclick: () => downloadForReview(f, status) }, "Download")))))),
    h("p", { class: "muted small" }, "Test downloads in a throwaway virtual machine, never on your own PC."),

    note,
    h("div", { class: "row" },
      h("button", { class: "btn", disabled: held, onclick: () => act(true), title: held ? "Still on hold" : "" }, held ? "Approve (on hold)" : "Approve and publish"),
      h("button", { class: "btn danger", onclick: () => act(false) }, "Reject")),
    status);
}

async function downloadForReview(file, status) {
  const { data, error } = await sb.storage.from("app-files").createSignedUrl(file.storage_path, 120, { download: file.file_name });
  if (error || !data) return void status.replaceChildren(notice("error", "Couldn't create a download link."));
  location.href = data.signedUrl;
}

// ----------------------------------------------------------------- reports
async function reports(body) {
  const rows = ok(await sb.from("reports").select("*, apps(id,name,slug,status)").in("status", ["open", "reviewing"]).order("created_at"), "Loading reports");
  if (rows.length === 0) return void body.append(notice("good", "No open reports."));
  for (const r of rows) {
    const status = h("div", { "aria-live": "polite" });
    const note = h("textarea", { placeholder: "What you decided (kept for the record)", "aria-label": "Resolution" });
    const resolve = async (newStatus, delist) => {
      if (!note.value.trim()) return void status.replaceChildren(notice("error", "Write a short note first."));
      if (delist) {
        const e1 = (await sb.rpc("admin_set_app_status", { p_app: r.app_id, p_status: "delisted" })).error;
        if (e1) return void status.replaceChildren(notice("error", e1.message));
      }
      const e2 = (await sb.rpc("admin_resolve_report", { p_report: r.id, p_status: newStatus, p_resolution: note.value.trim() })).error;
      if (e2) return void status.replaceChildren(notice("error", e2.message));
      show();
    };
    body.append(h("div", { class: "panel" },
      h("div", { class: "row between" }, h("h2", {}, r.apps?.name ?? "Unknown app"), h("span", { class: "badge" }, r.category)),
      h("p", { class: "muted small" }, `${fmtDateTime(r.created_at)}${r.reporter_email ? ` · ${r.reporter_email}` : " · anonymous"}`),
      h("p", { class: "pre" }, r.details),
      r.apps && h("a", { class: "small", href: `/store/#/app/${r.apps.slug}` }, `View listing (${r.apps.status})`),
      note,
      h("div", { class: "row" },
        h("button", { class: "btn danger small", onclick: () => resolve("actioned", true) }, "Delist the app"),
        h("button", { class: "btn secondary small", onclick: () => resolve("actioned", false) }, "Handled, keep listed"),
        h("button", { class: "btn secondary small", onclick: () => resolve("dismissed", false) }, "Dismiss")),
      status));
  }
}

// -------------------------------------------------------------- developers
async function developers(body) {
  const devs = ok(await sb.from("developers").select("*").order("created_at", { ascending: false }), "Loading developers");
  const strikes = ok(await sb.from("strikes").select("developer_id,reason,created_at").order("created_at", { ascending: false }), "Loading strikes");
  if (devs.length === 0) return void body.append(notice("info", "No developers have signed up yet."));
  const status = h("div", { "aria-live": "polite" });
  const mine = (id) => strikes.filter((s) => s.developer_id === id);
  body.append(status, h("table", {},
    h("thead", {}, h("tr", {}, ...["Developer", "Status", "Trust", "Strikes", "Actions"].map((t) => h("th", {}, t)))),
    h("tbody", {}, ...devs.map((d) => {
      const trust = h("select", { "aria-label": `Trust level for ${d.display_name}` }, ...[0, 1, 2].map((n) => h("option", { value: n, selected: d.trust_level === n }, `Level ${n}`)));
      const run = async (fn, args, confirmText) => {
        if (confirmText && !confirm(confirmText)) return;
        const { error } = await sb.rpc(fn, args);
        if (error) return void status.replaceChildren(notice("error", error.message));
        show();
      };
      return h("tr", {},
        h("td", {}, d.display_name, h("div", { class: "muted small" }, d.contact_email)),
        h("td", {}, d.status), h("td", {}, trust),
        h("td", {}, mine(d.id).length, mine(d.id)[0] && h("div", { class: "muted small" }, mine(d.id)[0].reason.slice(0, 60))),
        h("td", {}, h("div", { class: "row" },
          h("button", { class: "btn secondary small", onclick: () => run("admin_set_trust", { p_developer: d.id, p_level: Number(trust.value) }) }, "Set trust"),
          h("button", { class: "btn secondary small", onclick: () => { const reason = prompt("Reason for the strike:"); if (reason) run("admin_add_strike", { p_developer: d.id, p_reason: reason }); } }, "Add strike"),
          d.status !== "banned" && h("button", { class: "btn danger small", onclick: () => { const reason = prompt("Reason for banning (this delists all their apps):"); if (reason) run("admin_ban_developer", { p_developer: d.id, p_reason: reason }, `Ban ${d.display_name}? All their apps will be removed.`); } }, "Ban"))));
    }))));
}

boot();
