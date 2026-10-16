// App shell: shared state from /api/state + the live event stream, tab switching, tab counters.
// Pages: ContextPage (context.js), SecurityPage (security.js), ConfigPanel (config.js).
const App = (() => {
  const $ = (id) => document.getElementById(id);
  const state = { sessions: [], traces: [] };
  let tab = "context";

  const renderContext = UI.throttle(() => { if (tab === "context") ContextPage.render(); });
  const renderSecurity = UI.throttle(() => { if (tab === "security") SecurityPage.render(); });

  function counts() {
    $("countContext").textContent = String(state.sessions.length);
    const running = state.traces.filter((t) => t.status === "running").length;
    const blocked = state.traces.filter((t) => t.status === "blocked" || t.status === "error").length;
    const el = $("countSecurity");
    el.textContent = running ? `${running} live` : String(state.traces.length);
    el.className = "count" + (running ? " live" : blocked ? " bad" : "");
    el.title = `${state.traces.length} recent passes${blocked ? `, ${blocked} blocked` : ""}`;
  }

  async function refresh() {
    const response = await fetch("/api/state");
    const body = await response.json();
    state.sessions = body.sessions;
    state.traces = body.traces || [];
    state.config = body.config;
    ContextPage.ensureSelection();
    counts();
    renderContext();
    renderSecurity();
  }

  function connect() {
    const events = new EventSource("/api/events");
    const status = $("status");
    events.onopen = () => { status.textContent = "Live"; status.className = "live"; refresh(); };
    events.onerror = () => { status.textContent = "Reconnecting…"; status.className = "down"; };
    events.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "session" && data.session) {
        const index = state.sessions.findIndex((s) => s.id === data.session.id);
        if (index < 0) state.sessions.push(data.session);
        else state.sessions[index] = data.session;
        ContextPage.ensureSelection();
        renderContext();
      } else if (data.type === "trace" && data.trace) {
        const index = state.traces.findIndex((t) => t.id === data.trace.id);
        if (index < 0) { state.traces.push(data.trace); if (state.traces.length > 100) state.traces.shift(); }
        else state.traces[index] = data.trace;
        renderSecurity();
      }
      counts();
    };
  }

  // Tabs. The URL hash keeps the current tab across reloads (#security, #config).
  const TABS = { context: ["tabContext", "viewContext"], security: ["tabSecurity", "viewSecurity"], config: ["tabConfig", "viewConfig"] };
  function showTab(name) {
    tab = TABS[name] ? name : "context";
    for (const [key, [button, view]] of Object.entries(TABS)) {
      $(button).setAttribute("aria-selected", String(key === tab));
      $(view).hidden = key !== tab;
    }
    $("savebar").hidden = tab !== "config";
    if (tab === "config") ConfigPanel.open();
    if (tab === "context") ContextPage.render();
    if (tab === "security") SecurityPage.render();
    history.replaceState(null, "", tab === "context" ? "#" : "#" + tab);
  }
  for (const name of Object.keys(TABS)) $(TABS[name][0]).onclick = () => showTab(name);
  window.addEventListener("beforeunload", (event) => { if (ConfigPanel.isDirty()) event.preventDefault(); });

  // Relative times ("12s ago") stay current without events.
  setInterval(renderContext, 10000);

  return {
    state,
    showContext(sessionId, itemId) { showTab("context"); ContextPage.select(sessionId, itemId); },
    start() { showTab(location.hash.slice(1)); refresh(); connect(); },
  };
})();

App.start();
