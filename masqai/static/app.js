// App shell: state from the token-protected control API, the live event stream, tabs and counters.
// Pages: ContextPage (context.js), SecurityPage (security.js), MappingPage (mapping.js), ConfigPanel (config.js).
const App = (() => {
  const $ = (id) => document.getElementById(id);
  const state = { sessions: [], details: new Map(), traces: [], config: null, forwarded: 0 };
  let tab = "context";

  const renderContext = UI.throttle(() => { if (tab === "context") ContextPage.render(); });
  const renderSecurity = UI.throttle(() => { if (tab === "security") SecurityPage.render(); });
  const renderMapping = UI.throttle(() => { if (tab === "mapping") MappingPage.render(); });
  const renderAll = () => { renderContext(); renderSecurity(); renderMapping(); };

  function counts() {
    $("countContext").textContent = String(state.sessions.length);
    const running = state.traces.filter((t) => t.status === "running").length;
    const blocked = state.traces.filter((t) => t.status === "blocked" || t.status === "error").length;
    const el = $("countSecurity");
    el.textContent = running ? `${running} live` : String(state.traces.length);
    el.className = "count" + (running ? " live" : blocked ? " bad" : "");
    el.title = `${state.traces.length} recent passes${blocked ? `, ${blocked} blocked` : ""}`;
    const detail = state.details.get(ContextPage.selectedId());
    $("countMapping").textContent = detail ? String(detail.entities.length) : "0";
  }

  // ---------- data ----------
  async function refresh() {
    const [stateResponse, securityResponse] = await Promise.all([UI.api("/api/state"), UI.api("/api/security")]);
    if (!stateResponse.ok || !securityResponse.ok) return;
    const body = await stateResponse.json();
    state.sessions = body.sessions;
    state.config = body.config;
    state.traces = (await securityResponse.json()).traces || [];
    ContextPage.ensureSelection();
    await loadDetail(ContextPage.selectedId());
    counts();
    renderAll();
  }

  // Full session (items with original/sanitized, entities, ops) for the selected session only.
  const pending = new Map();
  function loadDetail(id) {
    if (!id) return Promise.resolve();
    if (pending.has(id)) return pending.get(id);
    const promise = (async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));   // coalesce bursts of session events
      pending.delete(id);
      const response = await UI.api(`/api/sessions/${encodeURIComponent(id)}`);
      if (response.ok) state.details.set(id, await response.json());
      else state.details.delete(id);
      counts();
      renderAll();
    })();
    pending.set(id, promise);
    return promise;
  }

  // ---------- live events: fetch streaming (EventSource can't send the token header) ----------
  function handle(data) {
    if (data.type === "session" && data.session) {
      const index = state.sessions.findIndex((s) => s.id === data.session.id);
      if (index < 0) state.sessions.push(data.session);
      else state.sessions[index] = data.session;
      ContextPage.ensureSelection();
      if (data.session.id === ContextPage.selectedId()) loadDetail(data.session.id);
    } else if (data.type === "trace" && data.trace) {
      const index = state.traces.findIndex((t) => t.id === data.trace.id);
      if (index < 0) { state.traces.push(data.trace); if (state.traces.length > 100) state.traces.shift(); }
      else state.traces[index] = data.trace;
    } else if (data.type === "forget") {
      state.sessions = state.sessions.filter((s) => s.id !== data.session);
      state.details.delete(data.session);
      state.traces = state.traces.filter((t) => t.session_id !== data.session);
      ContextPage.ensureSelection();
      loadDetail(ContextPage.selectedId());
    } else if (data.type === "config") {
      state.config = data.config;
    } else if (data.type === "warning") {
      notify(data.message, "warn");
    } else if (data.type === "forwarded") {
      state.forwarded += 1;
    }
    counts();
    renderAll();
  }

  async function connect() {
    const status = $("status");
    let delay = 1000;
    for (;;) {
      try {
        const response = await UI.api("/api/events");
        if (response.status === 401) { status.textContent = "No admin token"; status.className = "down"; return; }
        if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`);
        status.textContent = "Live"; status.className = "live";
        delay = 1000;
        refresh();
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let cut;
          while ((cut = buffer.indexOf("\n\n")) >= 0) {
            const frame = buffer.slice(0, cut);
            buffer = buffer.slice(cut + 2);
            const data = frame.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
            if (data) { try { handle(JSON.parse(data)); } catch { /* ignore a malformed frame */ } }
          }
        }
      } catch { /* reconnect below */ }
      status.textContent = "Reconnecting…"; status.className = "down";
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, 15000);
    }
  }

  function notify(message, kind = "warn") {
    const box = $("notice");
    box.className = "banner " + kind;
    box.textContent = message;
    box.hidden = false;
    clearTimeout(notify.timer);
    notify.timer = setTimeout(() => { box.hidden = true; }, 12000);
  }

  document.addEventListener("masqai-unauthorized", () => {
    $("tokenHelp").hidden = false;
    $("status").textContent = "No admin token";
    $("status").className = "down";
  });

  // ---------- tabs (the URL hash keeps the current tab: #security, #mapping, #config) ----------
  const TABS = {
    context: ["tabContext", "viewContext"], security: ["tabSecurity", "viewSecurity"],
    mapping: ["tabMapping", "viewMapping"], config: ["tabConfig", "viewConfig"],
  };
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
    if (tab === "mapping") MappingPage.render();
    history.replaceState(null, "", tab === "context" ? location.pathname : "#" + tab);
  }
  for (const name of Object.keys(TABS)) $(TABS[name][0]).onclick = () => showTab(name);
  window.addEventListener("beforeunload", (event) => { if (ConfigPanel.isDirty()) event.preventDefault(); });

  // Relative times ("12s ago") stay current without events.
  setInterval(renderContext, 10000);

  return {
    state,
    detail: (id) => state.details.get(id),
    loadDetail,
    notify,
    showContext(sessionId, itemId) { showTab("context"); ContextPage.select(sessionId, itemId); },
    async forget(sessionId) {
      const response = await UI.api(`/api/sessions/${encodeURIComponent(sessionId)}/forget`, { method: "POST" });
      notify(response.ok ? "Session forgotten: its items, mapping, operations and traces are gone from RAM." : "Could not forget the session.",
        response.ok ? "ok" : "bad");
    },
    start() {
      if (!UI.token()) $("tokenHelp").hidden = false;
      showTab(location.hash.slice(1));
      refresh();
      connect();
    },
  };
})();

App.start();
