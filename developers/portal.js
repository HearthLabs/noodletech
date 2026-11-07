import { clear, fmtBytes, fmtDate, fmtDateTime, h, notice, slugify, statusBadge } from "../assets/dom.js";
import { configured, functionUrl, ok, sb } from "../assets/api.js";
import { SUPABASE_ANON_KEY, TERMS_VERSION } from "../assets/config.js";
import { mountFrame } from "../assets/layout.js";
import { hashFile } from "../assets/sha256.js";
import { uploadFile, validateSelection } from "../assets/upload.js";

const main = mountFrame("developers");
const CATEGORIES = ["Productivity", "Utilities", "Developer tools", "AI and automation", "Creative", "Games", "Education", "Other"];
const VERSION_RE = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,31}$/;

let session = null;
let dev = null;
let uploading = false;

// ------------------------------------------------------------------- boot
async function boot() {
  if (!configured) return void signedOut();
  session = (await sb.auth.getSession()).data.session;
  let lastUser = session?.user?.id ?? null;
  sb.auth.onAuthStateChange((_event, s) => {
    // Token refreshes must not redraw the page, or an upload in progress would be wiped.
    const id = s?.user?.id ?? null;
    session = s;
    if (id !== lastUser) { lastUser = id; render(); }
  });
  window.addEventListener("hashchange", () => { if (session && dev && !uploading) render(); });
  window.addEventListener("beforeunload", (e) => { if (uploading) { e.preventDefault(); e.returnValue = ""; } });
  render();
}

async function render() {
  clear(main);
  try {
    if (!session) return signedOut();
    dev = ok(await sb.from("developers").select("*").eq("id", session.user.id).maybeSingle(), "Loading your profile");
    if (!dev) return profileForm();
    if (dev.status === "suspended" || dev.status === "banned") return blocked();
    if (dev.terms_version !== TERMS_VERSION || dev.status === "pending") return termsView();
    return await routeApp();
  } catch (e) {
    main.append(notice("error", e.message), h("button", { class: "btn secondary", onclick: render }, "Try again"));
  }
}

function topBar(title, sub) {
  return h("div", { class: "row between" },
    h("div", {}, h("h1", {}, title), sub && h("p", { class: "lede" }, sub)),
    h("div", { class: "row" },
      h("span", { class: "muted small" }, session.user.email),
      h("button", { class: "btn secondary small", onclick: async () => { await sb.auth.signOut(); } }, "Sign out")));
}

// -------------------------------------------------------------- signed out
function signedOut() {
  const status = h("div", { "aria-live": "polite" });
  const email = h("input", { type: "email", required: true, autocomplete: "email", placeholder: "you@example.com", "aria-label": "Email address" });
  const go = h("button", { class: "btn", type: "submit" }, "Email me a sign-in link");
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      if (!configured) return status.replaceChildren(notice("warn", "Sign-in isn't available until the marketplace is connected."));
      go.disabled = true; clear(status);
      const { error } = await sb.auth.signInWithOtp({ email: email.value.trim(), options: { emailRedirectTo: `${location.origin}/developers/` } });
      go.disabled = false;
      if (error) status.append(notice("error", "We couldn't send the link. Check the address and try again."));
      else status.append(notice("good", `Check ${email.value.trim()} for a sign-in link. It works once and expires soon.`));
    },
  }, h("label", {}, "Your email", email), go, status);

  main.append(
    h("div", {}, h("p", { class: "eyebrow" }, "For developers"),
      h("h1", {}, "Publish your Windows app. We handle the rest."),
      h("p", { class: "lede" }, "Built something with AI or by hand? Upload the finished program. You don't need a company, a certificate or a server.")),
    h("div", { class: "grid" },
      card("We host it", "Storage, bandwidth and a download page for your app."),
      card("We check every release", "Each upload is scanned before it's listed, so people can trust what they download."),
      card("You keep your rights", "Your app stays yours. We never ask for your source code, only the finished .exe and any documents."),
      card("Free apps today", "Right now Noodle lists free apps. Paid apps, with payments and tax handled for you, are planned.")),
    h("div", { class: "panel narrow" }, h("h2", {}, "Sign in or create an account"),
      h("p", { class: "muted" }, "No password. We email you a link."), form),
    h("p", { class: "muted small" }, "By continuing you'll be asked to accept the ",
      h("a", { href: "/legal/developer-agreement.html" }, "Developer Agreement"), " and ",
      h("a", { href: "/legal/content-policy.html" }, "Content and Malware Policy"), "."),
  );
}
const card = (title, text) => h("div", { class: "card" }, h("h3", {}, title), h("p", { class: "muted" }, text));

// ---------------------------------------------------------------- profile
function profileForm() {
  const status = h("div", { "aria-live": "polite" });
  const name = h("input", { type: "text", required: true, minlength: 2, maxlength: 80, autocomplete: "name" });
  const email = h("input", { type: "email", required: true, value: session.user.email ?? "" });
  main.append(topBar("Welcome", "Tell us who's publishing. Your name appears on your apps."),
    h("form", {
      class: "panel narrow",
      onsubmit: async (e) => {
        e.preventDefault(); clear(status);
        const { error } = await sb.from("developers").insert({ id: session.user.id, display_name: name.value.trim(), contact_email: email.value.trim() });
        if (error) return status.append(notice("error", "We couldn't save that. Check the fields and try again."));
        render();
      },
    }, h("label", {}, "Name shown on your apps", h("span", { class: "hint" }, "Your name or your studio's name"), name),
      h("label", {}, "Contact email", h("span", { class: "hint" }, "For us to reach you. It is not shown publicly."), email),
      h("button", { class: "btn", type: "submit" }, "Continue"), status));
}

// ------------------------------------------------------------------ terms
function termsView() {
  const status = h("div", { "aria-live": "polite" });
  const a = h("input", { type: "checkbox", id: "t-agree" });
  const b = h("input", { type: "checkbox", id: "t-policy" });
  const btn = h("button", { class: "btn", type: "submit", disabled: true }, "Accept and continue");
  const sync = () => { btn.disabled = !(a.checked && b.checked); };
  a.addEventListener("change", sync); b.addEventListener("change", sync);
  main.append(topBar("Before you publish", "Please read and accept these. They explain what you promise and what we do."),
    h("form", {
      class: "panel narrow",
      onsubmit: async (e) => {
        e.preventDefault(); btn.disabled = true; clear(status);
        const { error } = await sb.rpc("accept_terms", { p_version: TERMS_VERSION });
        if (error) { btn.disabled = false; return status.append(notice("error", "We couldn't record that. Please try again.")); }
        render();
      },
    },
      h("ul", { class: "stack muted" },
        h("li", {}, "You own the app and have the right to distribute everything in it."),
        h("li", {}, "It contains no malware, spyware or hidden behavior, and does what the listing says."),
        h("li", {}, "You give Noodle permission to host, scan and distribute it. You can remove it at any time."),
        h("li", {}, "Noodle may reject or remove a release that fails its checks. Repeated problems lead to suspension.")),
      h("label", { class: "check", for: "t-agree" }, a, h("span", {}, "I have read and agree to the ", h("a", { href: "/legal/developer-agreement.html", target: "_blank", rel: "noopener" }, "Developer Agreement"), ".")),
      h("label", { class: "check", for: "t-policy" }, b, h("span", {}, "I have read and agree to the ", h("a", { href: "/legal/content-policy.html", target: "_blank", rel: "noopener" }, "Content and Malware Policy"), ".")),
      btn, status));
}

function blocked() {
  main.append(topBar("Your account is paused"),
    notice("warn", dev.status === "banned"
      ? "This account can no longer publish on Noodle."
      : "Publishing is paused on this account, usually after repeated problems with releases. Email info@noodletechnology.com to discuss it."));
}

// ------------------------------------------------------------------ router
async function routeApp() {
  const hash = location.hash;
  let m;
  if ((m = hash.match(/^#\/app\/([0-9a-f-]{36})\/release$/))) return await releaseWizard(m[1]);
  if ((m = hash.match(/^#\/app\/([0-9a-f-]{36})$/))) return await appPage(m[1]);
  if (hash === "#/new") return newApp();
  return await dashboard();
}

// --------------------------------------------------------------- dashboard
async function dashboard() {
  const apps = ok(await sb.from("apps").select("id,slug,name,summary,status,updated_at").eq("developer_id", session.user.id).order("updated_at", { ascending: false }), "Loading your apps");
  main.append(topBar("Your apps", `Signed in as ${dev.display_name}`));
  if (dev.trust_level === 0) {
    main.append(notice("info", "New developers' first releases are checked by a person before they go live, which takes at least 24 hours. After two approved releases with no problems, most updates are approved automatically."));
  }
  main.append(h("div", {}, h("a", { class: "btn", href: "#/new" }, "Add an app")));
  if (apps.length === 0) {
    main.append(h("div", { class: "panel" }, h("h3", {}, "You haven't added an app yet"),
      h("p", { class: "muted" }, "Add your app's details first, then upload its program file.")));
    return;
  }
  main.append(h("div", { class: "grid" }, ...apps.map((a) =>
    h("a", { class: "card", href: `#/app/${a.id}` }, h("div", { class: "row between" }, h("h3", {}, a.name), statusBadge(a.status)),
      h("span", { class: "muted" }, a.summary), h("span", { class: "meta" }, `Updated ${fmtDate(a.updated_at)}`)))));
}

// ----------------------------------------------------------------- new app
function appFields(app = {}) {
  const name = h("input", { type: "text", required: true, minlength: 2, maxlength: 80, value: app.name ?? "" });
  const slug = h("input", { type: "text", required: true, pattern: "[a-z0-9][a-z0-9\\-]{1,47}", value: app.slug ?? "", readOnly: true, tabindex: -1 });
  const summary = h("input", { type: "text", required: true, maxlength: 160, value: app.summary ?? "" });
  const description = h("textarea", { maxlength: 10000, value: app.description ?? "" });
  const category = h("select", {}, h("option", { value: "" }, "Choose a category"),
    ...CATEGORIES.map((c) => h("option", { value: c, selected: app.category === c }, c)));
  const license = h("input", { type: "text", maxlength: 100, placeholder: "e.g. Freeware, MIT", value: app.license_name ?? "" });
  const homepage = h("input", { type: "url", placeholder: "https://", value: app.homepage_url ?? "" });
  const support = h("input", { type: "url", placeholder: "https:// or a contact page", value: app.support_url ?? "" });
  if (!app.slug) name.addEventListener("input", () => { slug.value = slugify(name.value); });
  const els = [
    h("label", {}, "App name", name),
    h("label", {}, "Web address", h("span", { class: "hint" }, "Made from the app name. It can't be edited or changed later."), slug),
    h("label", {}, "One-line summary", h("span", { class: "hint" }, "Up to 160 characters. Say what it does."), summary),
    h("label", {}, "Description", h("span", { class: "hint" }, "What it does, what it needs, anything people should know. Be honest about network use and data collection."), description),
    h("label", {}, "Category", category),
    h("label", {}, "License", h("span", { class: "hint" }, "How people may use your app"), license),
    h("label", {}, "Your website (optional)", homepage),
    h("label", {}, "Support link (optional)", support),
  ];
  const read = () => ({
    slug: slug.value.trim(), name: name.value.trim(), summary: summary.value.trim(), description: description.value,
    category: category.value || null, license_name: license.value.trim(),
    homepage_url: homepage.value.trim() || null, support_url: support.value.trim() || null,
  });
  return { els, read };
}

function newApp() {
  const status = h("div", { "aria-live": "polite" });
  const { els, read } = appFields();
  main.append(h("a", { href: "#/" }, "← Your apps"), topBar("Add an app", "You'll upload the program file next."),
    h("form", {
      class: "panel",
      onsubmit: async (e) => {
        e.preventDefault(); clear(status);
        try {
          const fields = read();
          let res = await sb.from("apps").insert({ developer_id: session.user.id, ...fields }).select("id").single();
          // Address already used by another app: add a short suffix instead of asking the developer to edit it.
          if (res.error && (res.error.code === "23505" || /duplicate|unique/i.test(res.error.message))) {
            const suffix = Math.random().toString(36).slice(2, 6);
            res = await sb.from("apps").insert({ developer_id: session.user.id, ...fields, slug: `${fields.slug.slice(0, 43)}-${suffix}` }).select("id").single();
          }
          const row = ok(res, "Saving");
          location.hash = `#/app/${row.id}/release`;
        } catch (err) { status.append(notice("error", err.message)); }
      },
    }, ...els, h("button", { class: "btn", type: "submit" }, "Save and continue"), status));
}

// ---------------------------------------------------------------- app page
function releaseMessage(r, app) {
  const latest = [...(r.release_decisions ?? [])].sort((x, y) => y.created_at.localeCompare(x.created_at))[0];
  switch (r.status) {
    case "uploaded": return "Uploaded but not scanned yet. Press “Run checks”.";
    case "scanning": return "The checks are still running. Press “Check progress” in a few minutes.";
    case "in_review": {
      const parts = [];
      if (r.review_flag === "hold") parts.push(`As a new developer you get a person's review first. The earliest it can be approved is ${fmtDateTime(r.hold_until)}.`);
      else if (r.review_flag === "attention") parts.push("Our checks found something a person needs to look at." + (latest ? ` Details: ${latest.reason}` : ""));
      else if (r.review_flag === "spot_check") parts.push("Selected for a routine check by a person.");
      else parts.push("Waiting for approval.");
      if (app.status === "draft") parts.push("Next, press “Submit app” above so it can go live once approved.");
      return parts.join(" ");
    }
    case "approved": return app.status === "draft" ? "Approved. Press “Submit app” above to publish it." : `Live in the store since ${fmtDate(r.published_at)}.`;
    case "rejected": return `Not approved. ${r.review_note || (latest ? latest.reason : "")}`.trim();
    case "delisted": return "Removed from the store.";
    default: return "";
  }
}

async function appPage(appId) {
  const app = ok(await sb.from("apps").select("*").eq("id", appId).maybeSingle(), "Loading the app");
  if (!app) return void main.append(h("a", { href: "#/" }, "← Your apps"), notice("warn", "That app wasn't found."));
  const releases = ok(await sb.from("releases").select("*, release_files(*), release_decisions(*)").eq("app_id", appId).order("created_at", { ascending: false }), "Loading releases");
  const canSubmit = app.status === "draft" && releases.some((r) => r.status === "in_review" || r.status === "approved");
  const status = h("div", { "aria-live": "polite" });
  const refresh = () => { clear(main); appPage(appId); };

  main.append(h("a", { href: "#/" }, "← Your apps"),
    h("div", { class: "row between" },
      h("div", {}, h("h1", {}, app.name), h("p", { class: "muted" }, app.summary)),
      statusBadge(app.status)),
    h("div", { class: "row" },
      h("a", { class: "btn", href: `#/app/${appId}/release` }, "Upload a new release"),
      canSubmit && h("button", { class: "btn secondary", onclick: async (e) => {
        e.target.disabled = true; clear(status);
        const { error } = await sb.rpc("submit_app_for_review", { p_app: appId });
        if (error) { e.target.disabled = false; return status.append(notice("error", error.message.replace(/^.*?:\s*/, ""))); }
        refresh();
      } }, "Submit app"),
      app.status === "published" && h("a", { class: "btn secondary", href: `/store/#/app/${app.slug}` }, "View in store ↗"),
      app.status === "draft" && h("button", { class: "btn danger", onclick: async () => {
        if (!confirm(`Delete “${app.name}”? This removes the app and its uploads.`)) return;
        const { error } = await sb.from("apps").delete().eq("id", appId);
        if (error) return status.append(notice("error", "Couldn't delete it."));
        location.hash = "#/";
      } }, "Delete app")),
    status);

  // Edit details
  const { els, read } = appFields(app);
  const editStatus = h("div", { "aria-live": "polite" });
  main.append(h("details", {}, h("summary", {}, "Edit app details"), h("form", {
    style: "margin-top:12px",
    onsubmit: async (e) => {
      e.preventDefault(); clear(editStatus);
      const { slug: _s, ...fields } = read();
      const { error } = await sb.from("apps").update(fields).eq("id", appId);
      editStatus.append(error ? notice("error", "Couldn't save the changes.") : notice("good", "Saved."));
    },
  }, ...els, h("button", { class: "btn", type: "submit" }, "Save changes"), editStatus)));

  main.append(h("h2", {}, "Releases"));
  if (releases.length === 0) main.append(notice("info", "No releases yet. Upload your program to get started."));
  for (const r of releases) {
    const cardStatus = h("div", { "aria-live": "polite" });
    const exe = (r.release_files ?? []).filter((f) => f.kind === "executable");
    const docs = (r.release_files ?? []).filter((f) => f.kind === "document");
    main.append(h("div", { class: "panel" },
      h("div", { class: "row between" }, h("h3", {}, `Version ${r.version}`), statusBadge(r.status)),
      h("p", { class: "muted small" }, `Uploaded ${fmtDateTime(r.created_at)} · Windows ${r.min_windows}+`),
      h("p", {}, releaseMessage(r, app)),
      h("ul", { class: "stack small muted", style: "gap:4px" },
        ...[...exe, ...docs].map((f) => h("li", {}, `${f.file_name} · ${fmtBytes(f.size_bytes)}`))),
      h("div", { class: "row" },
        (r.status === "uploaded" || r.status === "scanning") && h("button", { class: "btn secondary small", onclick: async (e) => {
          e.target.disabled = true; clear(cardStatus); cardStatus.append(notice("info", "Running checks…"));
          const out = await runScan(r.id);
          if (out.status === 200 || out.status === 202) return refresh();
          e.target.disabled = false; clear(cardStatus); cardStatus.append(notice("error", out.body.error ?? "The checks couldn't run. Try again in a moment."));
        } }, r.status === "uploaded" ? "Run checks" : "Check progress"),
        ["uploaded", "scan_failed", "rejected"].includes(r.status) && h("button", { class: "btn danger small", onclick: async () => {
          if (!confirm(`Delete version ${r.version}?`)) return;
          const { error } = await sb.from("releases").delete().eq("id", r.id);
          if (error) return cardStatus.append(notice("error", "Couldn't delete it."));
          refresh();
        } }, "Delete")),
      cardStatus));
  }
}

async function runScan(releaseId) {
  const token = (await sb.auth.getSession()).data.session?.access_token;
  try {
    const res = await fetch(functionUrl("scan-release"), {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}`, apikey: SUPABASE_ANON_KEY },
      body: JSON.stringify({ release_id: releaseId }),
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  } catch {
    return { status: 0, body: { error: "Couldn't reach the checking service. Try again in a moment." } };
  }
}

// ----------------------------------------------------------- release wizard
async function releaseWizard(appId) {
  const app = ok(await sb.from("apps").select("id,name,status").eq("id", appId).maybeSingle(), "Loading the app");
  if (!app) return void main.append(h("a", { href: "#/" }, "← Your apps"), notice("warn", "That app wasn't found."));
  if (app.status === "delisted") return void main.append(h("a", { href: "#/" }, "← Your apps"), notice("warn", "This app has been removed, so new releases can't be added."));

  const status = h("div", { "aria-live": "polite" });
  const progress = h("div", { class: "stack", "aria-live": "polite" });
  const version = h("input", { type: "text", required: true, maxlength: 32, placeholder: "1.0.0", pattern: "[0-9A-Za-z][0-9A-Za-z.+\\-]{0,31}" });
  const notes = h("textarea", { maxlength: 5000, placeholder: "What's in this version?" });
  const minWin = h("select", {}, h("option", { value: "10" }, "Windows 10 or later"), h("option", { value: "11" }, "Windows 11"));
  const exeInput = h("input", { type: "file", accept: ".exe", id: "exe" });
  const docInput = h("input", { type: "file", accept: ".pdf,.txt,.md", multiple: true, id: "docs" });
  const go = h("button", { class: "btn", type: "submit" }, "Upload and check");

  main.append(h("a", { href: `#/app/${appId}` }, `← ${app.name}`), h("h1", {}, "Upload a release"),
    h("div", { class: "notice info" }, h("strong", {}, "What to upload. "),
      "One finished program (.exe) that runs on its own, plus any documents (PDF, TXT or Markdown, such as a manual or license). Your source code is never needed. Files can't be changed after upload. To fix something, upload a new version."),
    h("form", {
      class: "panel",
      onsubmit: async (e) => {
        e.preventDefault();
        const exe = exeInput.files[0] ?? null;
        const docs = [...docInput.files];
        const problems = validateSelection(exe, docs);
        if (!VERSION_RE.test(version.value.trim())) problems.push("Version numbers use letters, numbers, dots and dashes (for example 1.0.0).");
        clear(status); clear(progress);
        if (problems.length) return status.append(notice("error", h("ul", {}, ...problems.map((p) => h("li", {}, p)))));
        go.disabled = true; uploading = true;
        try {
          await doUpload({ appId, version: version.value.trim(), notes: notes.value, minWin: minWin.value, exe, docs, progress, status });
        } catch (err) {
          status.append(notice("error", err.message), h("p", { class: "muted small" }, "Nothing was published. You can fix the problem and try again."));
        } finally { go.disabled = false; uploading = false; }
      },
    },
      h("label", {}, "Version number", h("span", { class: "hint" }, "For example 1.0.0. Each release needs its own number."), version),
      h("label", {}, "Release notes (optional)", notes),
      h("label", {}, "Works on", minWin),
      h("label", {}, "Program file (.exe)", exeInput),
      h("label", {}, "Documents (optional): PDF, TXT or Markdown, up to 19", docInput),
      go, status, progress));
}

async function doUpload({ appId, version, notes, minWin, exe, docs, progress, status }) {
  const uid = session.user.id;
  const files = [{ file: exe, kind: "executable" }, ...docs.map((file) => ({ file, kind: "document" }))];
  const rows = files.map(({ file }) => {
    const bar = h("i"); const label = h("span", { class: "small muted" }, "Waiting");
    progress.append(h("div", { class: "stack", style: "gap:4px" }, h("div", { class: "row between" }, h("span", {}, `${file.name} · ${fmtBytes(file.size)}`), label), h("div", { class: "progress" }, bar)));
    return { bar, label };
  });

  const rel = ok(await sb.from("releases").insert({ app_id: appId, version, release_notes: notes, min_windows: minWin }).select("id").single(), "Creating the release");
  const records = [];
  try {
    for (let i = 0; i < files.length; i++) {
      const { file, kind } = files[i], ui = rows[i];
      ui.label.textContent = "Calculating checksum…";
      const sha256 = await hashFile(file, (p) => { ui.bar.style.width = `${Math.round(p * 20)}%`; });
      ui.label.textContent = "Uploading…";
      const token = (await sb.auth.getSession()).data.session?.access_token;
      if (!token) throw new Error("You were signed out. Sign in again and retry.");
      const path = `${uid}/${rel.id}/${file.name}`;
      await uploadFile({ accessToken: token, bucket: "app-files", path, file, onProgress: (p) => { ui.bar.style.width = `${20 + Math.round(p * 80)}%`; ui.label.textContent = `Uploading… ${Math.round(p * 100)}%`; } });
      ui.bar.style.width = "100%"; ui.label.textContent = "Uploaded";
      records.push({ release_id: rel.id, kind, file_name: file.name, storage_path: path, size_bytes: file.size, sha256 });
    }
    ok(await sb.from("release_files").insert(records), "Recording the files");
  } catch (err) {
    // Remove the half-finished release so the version number can be used again.
    await sb.from("releases").delete().eq("id", rel.id);
    throw err;
  }

  status.append(notice("info", "Upload complete. Running checks…"));
  const out = await runScan(rel.id);
  clear(status);
  if (out.status === 200) {
    const msg = {
      auto_approved: "Checks passed and your release is approved.",
      held: "Checks passed. As a new developer, a person reviews your first releases, which takes at least 24 hours.",
      spot_check: "Checks passed. A person will take a quick look before it goes live.",
      needs_human: "The checks found something a person needs to look at. You'll see the details on the app page.",
      auto_rejected: "This release didn't pass the checks. See the app page for the reason.",
    }[out.body.decision] ?? "Checks finished.";
    status.append(notice(out.body.decision === "auto_rejected" ? "error" : "good", msg));
  } else if (out.status === 202) {
    status.append(notice("info", "Your files are uploaded and the checks are still running. You can close this page. Open the app page later and press “Check progress”."));
  } else {
    status.append(notice("warn", `Your files are uploaded, but the checks couldn't start (${out.body.error ?? "service unavailable"}). Open the app page and press “Run checks”.`));
  }
  status.append(h("p", {}, h("a", { class: "btn secondary", href: `#/app/${appId}` }, "Go to the app page")));
}

boot();
