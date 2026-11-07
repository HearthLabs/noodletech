// The page frame shared by every marketplace page.
import { h } from "./dom.js";
import { configured } from "./api.js";

const FONTS = "https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500;12..96,700&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono:wght@400&display=swap";

export function mountFrame(current, { narrow = false } = {}) {
  const link = h("link", { rel: "stylesheet", href: FONTS });
  document.head.append(link);
  const root = document.getElementById("app");
  const nav = h("nav", { class: "main", "aria-label": "Main" },
    h("a", { href: "/store/", "aria-current": current === "store" ? "page" : false }, "Apps"),
    h("a", { href: "/developers/", "aria-current": current === "developers" ? "page" : false }, "For developers"),
    h("a", { href: "/", "aria-current": false }, "Company"),
  );
  const main = h("main", { id: "main", class: "stack" });
  const notConnected = configured ? null : h("div", { class: "notice warn", role: "status" },
    "The marketplace isn't connected to its database yet. Fill in assets/config.js, then reload.");
  root.append(
    h("div", { class: `wrap${narrow ? " narrow" : ""}` },
      h("header", { class: "top" },
        h("a", { class: "brand", href: "/" }, h("img", { src: "/logo.svg", alt: "", width: 32, height: 28 }), "Noodle Technology"),
        nav),
      notConnected,
      main,
      h("footer", { class: "site" },
        h("span", {}, "© 2026 Noodle Technology, LLC"),
        h("nav", { "aria-label": "Legal" },
          h("a", { href: "/legal/terms.html" }, "Terms"),
          h("a", { href: "/legal/privacy.html" }, "Privacy"),
          h("a", { href: "/legal/content-policy.html" }, "Content policy"),
          h("a", { href: "/legal/dmca.html" }, "Copyright (DMCA)"),
        ))));
  return main;
}
