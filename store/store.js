import { clear, fmtBytes, fmtDate, h, notice, safeUrl } from "../assets/dom.js";
import { configured, downloadUrl, ok, sb } from "../assets/api.js";
import { mountFrame } from "../assets/layout.js";

const main = mountFrame("store");

const CATEGORIES = ["Productivity", "Utilities", "Developer tools", "AI and automation", "Creative", "Games", "Education", "Other"];

function route() {
  const m = location.hash.match(/^#\/app\/([a-z0-9-]+)$/);
  return m ? { page: "app", slug: m[1] } : { page: "catalog" };
}

async function render() {
  const r = route();
  clear(main);
  try {
    if (r.page === "app") await appPage(r.slug);
    else await catalogPage();
  } catch (e) {
    main.append(notice("error", e.message));
  }
}
window.addEventListener("hashchange", () => { render(); window.scrollTo(0, 0); });
render();

// ------------------------------------------------------------------ catalog
async function catalogPage() {
  document.title = "Apps — Noodle Technology";
  main.append(
    h("div", {},
      h("p", { class: "eyebrow" }, "App marketplace"),
      h("h1", {}, "Windows apps, checked before you download."),
      h("p", { class: "lede" }, "Independent developers publish here. Every release is scanned for malware before it is listed. A scan lowers the risk but can't guarantee an app is safe.")),
    h("a", { class: "card", href: "https://noodlellm.com", target: "_blank", rel: "noopener" },
      h("span", { class: "eyebrow" }, "Featured · by Noodle Technology"),
      h("h3", {}, "Noodle LLM"),
      h("span", {}, "Run AI models privately on your own PC. Your conversations stay on your computer."),
      h("span", { class: "meta" }, "noodlellm.com ↗")),
  );
  if (!configured) return;

  const list = h("div", { class: "grid", "aria-live": "polite" });
  const search = h("input", { type: "search", placeholder: "Search apps", "aria-label": "Search apps" });
  const category = h("select", { "aria-label": "Category" },
    h("option", { value: "" }, "All categories"), ...CATEGORIES.map((c) => h("option", { value: c }, c)));
  main.append(h("div", { class: "row" }, h("div", { style: "flex:1;min-width:12rem" }, search), h("div", { style: "min-width:11rem" }, category)), list);

  const apps = ok(await sb.from("published_apps").select("*").order("updated_at", { ascending: false }), "Loading apps");
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    const shown = apps.filter((a) =>
      (!category.value || a.category === category.value) &&
      (!q || a.name.toLowerCase().includes(q) || a.summary.toLowerCase().includes(q)));
    clear(list);
    if (apps.length === 0) {
      list.append(h("div", { class: "panel", style: "grid-column:1/-1" },
        h("h3", {}, "No apps yet"),
        h("p", { class: "muted" }, "The first independent apps are on their way. Built something for Windows? "),
        h("a", { class: "btn secondary", href: "/developers/" }, "Publish your app")));
    } else if (shown.length === 0) {
      list.append(h("p", { class: "muted" }, "No apps match that search."));
    }
    for (const a of shown) {
      list.append(h("a", { class: "card", href: `#/app/${a.slug}` },
        a.category && h("span", { class: "eyebrow", style: "margin:0" }, a.category),
        h("h3", {}, a.name),
        h("span", {}, a.summary),
        h("span", { class: "meta" }, `by ${a.developer_name}`, Number(a.downloads) > 0 ? ` · ${Number(a.downloads).toLocaleString()} downloads` : "")));
    }
  };
  search.addEventListener("input", draw);
  category.addEventListener("change", draw);
  draw();
}

// ------------------------------------------------------------------ app page
async function appPage(slug) {
  if (!configured) return void main.append(notice("info", "Apps will appear here once the marketplace is connected."));
  const app = ok(await sb.from("published_apps").select("*").eq("slug", slug).maybeSingle(), "Loading the app");
  if (!app) {
    document.title = "App not found — Noodle Technology";
    main.append(h("a", { href: "#/" }, "← All apps"), notice("warn", "This app isn't available. It may have been removed."));
    return;
  }
  document.title = `${app.name} — Noodle Technology`;
  const releases = ok(await sb.from("published_releases").select("*").eq("app_id", app.id).order("published_at", { ascending: false }), "Loading releases");
  const files = releases.length
    ? ok(await sb.from("published_release_files").select("*").in("release_id", releases.map((r) => r.id)), "Loading files")
    : [];

  const home = safeUrl(app.homepage_url), support = safeUrl(app.support_url);
  main.append(
    h("a", { href: "#/" }, "← All apps"),
    h("div", {},
      app.category && h("p", { class: "eyebrow" }, app.category),
      h("h1", {}, app.name),
      h("p", { class: "lede" }, app.summary),
      h("p", { class: "muted small" }, `by ${app.developer_name}`,
        app.license_name ? ` · License: ${app.license_name}` : "",
        Number(app.downloads) > 0 ? ` · ${Number(app.downloads).toLocaleString()} downloads` : "")),
  );

  const latest = releases[0];
  if (latest) main.append(releasePanel(app, latest, files.filter((f) => f.release_id === latest.id), true));
  else main.append(notice("info", "No downloads are available for this app right now."));

  if (app.description) main.append(h("section", { class: "stack" }, h("h2", {}, "About this app"), h("p", { class: "pre" }, app.description)));

  main.append(h("section", { class: "stack" }, h("h2", {}, "Before you run it"),
    h("ul", { class: "stack muted" },
      h("li", {}, `Noodle hosts this app for ${app.developer_name}. Noodle did not write it.`),
      h("li", {}, "Each release is scanned before it is listed. A scan lowers the risk but can't guarantee an app is safe."),
      h("li", {}, "To confirm your download is the file we scanned, compare its checksum. In PowerShell: ", h("code", {}, "Get-FileHash .\\FileName.exe"), " and match it to the SHA-256 shown above."),
      h("li", {}, "Windows may show a \"Windows protected your PC\" warning for apps that aren't signed by a known publisher. Only run apps you trust."))));

  if (home || support) {
    main.append(h("div", { class: "row" },
      home && h("a", { href: home, rel: "noopener noreferrer nofollow", target: "_blank" }, "Developer website ↗"),
      support && h("a", { href: support, rel: "noopener noreferrer nofollow", target: "_blank" }, "Get support ↗")));
  }

  if (releases.length > 1) {
    main.append(h("section", { class: "stack" }, h("h2", {}, "Earlier versions"),
      ...releases.slice(1).map((r) => h("details", {}, h("summary", {}, `Version ${r.version} · ${fmtDate(r.published_at)}`),
        releasePanel(app, r, files.filter((f) => f.release_id === r.id), false)))));
  }

  main.append(reportForm(app, latest));
}

function releasePanel(app, release, files, primary) {
  const exe = files.filter((f) => f.kind === "executable");
  const docs = files.filter((f) => f.kind === "document");
  return h("section", { class: primary ? "panel" : "stack" },
    h("div", { class: "row between" },
      h("h2", {}, `Version ${release.version}`),
      h("span", { class: "muted small" }, `${fmtDate(release.published_at)} · ${fmtBytes(release.total_size_bytes)} · Windows ${release.min_windows}+`)),
    release.release_notes && h("p", { class: "pre muted" }, release.release_notes),
    ...exe.map((f) => fileRow(f, true)),
    docs.length > 0 && h("h3", {}, "Documents"),
    ...docs.map((f) => fileRow(f, false)),
  );
}

function fileRow(f, primary) {
  return h("div", { class: "stack", style: "gap:6px" },
    h("div", { class: "row between" },
      h("span", {}, h("strong", {}, f.file_name), h("span", { class: "muted small" }, `  ${fmtBytes(f.size_bytes)}`)),
      h("a", { class: primary ? "btn" : "btn secondary small", href: downloadUrl(f.id), rel: "nofollow" }, primary ? "Download" : "Open")),
    h("span", { class: "mono muted" }, `SHA-256 ${f.sha256}`));
}

function reportForm(app, latest) {
  const status = h("div", { "aria-live": "polite" });
  const category = h("select", { required: true, "aria-label": "What is wrong" },
    h("option", { value: "" }, "What's the problem?"),
    h("option", { value: "malware" }, "It looks like malware or does something harmful"),
    h("option", { value: "copyright" }, "It uses my copyrighted work"),
    h("option", { value: "misleading" }, "It isn't what the listing says"),
    h("option", { value: "illegal" }, "Illegal content"),
    h("option", { value: "privacy" }, "Privacy problem"),
    h("option", { value: "other" }, "Something else"));
  const details = h("textarea", { required: true, maxlength: 4000, "aria-label": "Details", placeholder: "Tell us what you saw. For copyright complaints, please use the DMCA process linked below." });
  const email = h("input", { type: "email", placeholder: "Your email (optional, so we can follow up)", "aria-label": "Your email (optional)" });
  const submit = h("button", { class: "btn secondary", type: "submit" }, "Send report");
  const form = h("form", {
    onsubmit: async (e) => {
      e.preventDefault();
      submit.disabled = true; clear(status);
      try {
        const body = { app_id: app.id, category: category.value, details: details.value.trim() };
        if (latest) body.release_id = latest.id;
        if (email.value.trim()) body.reporter_email = email.value.trim();
        const { error } = await sb.from("reports").insert(body);
        if (error) throw new Error("Couldn't send the report. Please try again.");
        form.reset();
        status.append(notice("good", "Thanks. We'll look at it. Reports about malware are reviewed first."));
      } catch (err) {
        status.append(notice("error", err.message));
      } finally { submit.disabled = false; }
    },
  }, category, details, email, submit, status);
  return h("details", {}, h("summary", {}, "Report a problem with this app"), h("div", { class: "stack", style: "margin-top:12px" }, form,
    h("p", { class: "muted small" }, "Copyright complaints follow a legal process. See the ", h("a", { href: "/legal/dmca.html" }, "copyright (DMCA) policy"), ".")));
}
