// Mapping page: the selected session's entity table (RAM only) and "forget session".
const MappingPage = (() => {
  const { h, text, short, plural, pill } = UI;
  const main = document.getElementById("mappingMain");

  const ORIGIN = (origin) => origin === "model" ? ["security model", "model"]
    : origin === "detector:host" ? ["this machine", "dim"]
      : origin === "detector:custom" ? ["custom value", "dim"]
        : origin.startsWith("detector:") ? [`rule ${origin.slice(9)}`, "info"] : [origin, "dim"];

  function render() {
    const id = ContextPage.selectedId();
    const session = id && App.detail(id);
    const sessions = App.state.sessions;
    const picker = h("select", { "aria-label": "Session", onchange: (e) => { ContextPage.select(e.target.value); render(); } },
      sessions.length ? [...sessions].reverse().map((s) => h("option", { value: s.id, selected: s.id === id }, short(s.id))) : h("option", null, "no sessions"));
    if (!session) {
      main.replaceChildren(h("div", { class: "bar" }, h("h2", null, "Mapping"), picker),
        h("div", { class: "empty" }, sessions.length ? "Loading…" : "No sessions yet. Values appear here once a request is inspected."));
      return;
    }
    const sent = session.items.map((i) => text(i.sanitized)).join("\n");
    const occurrences = (token) => sent.split(token).length - 1 + sent.split(token.replace("<", "<$")).length - 1;
    const rows = session.entities.map((e) => {
      const [origin, cls] = ORIGIN(e.origin);
      return h("tr", { style: "cursor:pointer", title: "Show items containing this value", onclick: () => { App.showContext(session.id); ContextPage.setQuery(e.canonical); } },
        h("td", { class: "mono" }, h("mark", { class: "ph" }, e.token)),
        h("td", null, e.type),
        h("td", null, pill(e.class || "secret", e.class === "intel" ? "warn" : "bad")),
        h("td", null, pill(origin, cls, e.reason || "")),
        h("td", { class: "muted" }, String(occurrences(e.token))),
        h("td", { class: "mono" }, e.merged_into ? [h("mark", { class: "ph alias" }, e.merged_into.replace("<", "<$"))] : "—"),
        h("td", { class: "mono" }, e.canonical, e.aliases?.length ? h("div", { class: "aliases" }, "marked forms: ", e.aliases.join(", ")) : null));
    });
    main.replaceChildren(
      h("div", { class: "bar" },
        h("h2", { title: session.id }, "Mapping · ", short(session.id)), picker,
        h("div", { class: "stats" },
          pill(`${session.entities.length} ${session.entities.length === 1 ? "entity" : "entities"}`, "dim"),
          session.relinks?.length ? pill(plural(session.relinks.length, "relink"), "model") : null,
          session.remasks ? pill(`cache broken ×${session.remasks}`, "warn") : null,
          session.parent_id ? pill(`branched from ${short(session.parent_id)}`, "info") : null),
        h("span", { class: "grow" }),
        h("button", { class: "danger", onclick: () => {
          if (confirm(`Forget session ${short(session.id)}? Its items, mapping, operations and traces are dropped from RAM, and open GUIs drop their copies.`)) App.forget(session.id);
        } }, "Forget session")),
      session.entities.length
        ? h("table", { style: "margin:0" },
          h("thead", null, h("tr", null, ["Token", "Type", "Class", "Origin", "Uses", "Linked to", "Real value (RAM only)"].map((x) => h("th", null, x)))),
          h("tbody", null, rows))
        : h("div", { class: "empty" }, "No mappings in this session yet."),
      h("div", { class: "list-foot" },
        "Exact copies of a value are masked automatically unless they sit inside a longer word. Marked forms (<$…>) are masked only where the security model pointed at them. ",
        "A linked token is sent and restored as the value it ultimately links to. Uses counts occurrences in the text sent to the untrusted model. Click a row to find it in Context."));
  }

  return { render };
})();
