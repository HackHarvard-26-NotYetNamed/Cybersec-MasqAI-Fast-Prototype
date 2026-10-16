// Security page: one entry per sanitize pass. Shows, live, what the security model is given,
// what it answered (each attempt, including the one correction round), how each operation was
// judged, and what changed in the outbound context.
const SecurityPage = (() => {
  const { h, short, plural, ago, ms, pill, fold } = UI;
  const main = document.getElementById("securityMain");
  const list = document.getElementById("traces");
  const follow = document.getElementById("followLatest");
  const sessionFilter = document.getElementById("traceSession");
  const hideSkipped = document.getElementById("hideSkipped");

  let selected = null;
  let timer = null;
  const openFolds = new Set();   // keeps <details> state across live re-renders

  const STATUS = {
    running: ["running", "run"], passed: ["passed", "ok"], skipped: ["skipped", "dim"],
    blocked: ["blocked", "bad"], error: ["error", "bad"],
  };
  const KIND = { message: "message", tool_result: "tool result", tool_arguments: "tool call args", system: "system", tool_definition: "tool description", reasoning: "reasoning" };
  const OP_CLS = { mask: "ok", collapse: "warn", relink: "info", unmask: "bad" };

  const traces = () => App.state.traces || [];
  const visible = () => traces().filter((t) =>
    (!sessionFilter.value || t.session_id === sessionFilter.value) && (!hideSkipped.checked || t.status !== "skipped"));
  const attempts = (t) => t.security?.attempts || [];
  const current = (t) => attempts(t).at(-1) || {};

  function summary(t) {
    if (t.status === "running") {
      const a = current(t);
      if (t.stage === "security" && a.sent_at) return a.attempt > 1 ? "waiting for the correction…" : `waiting for ${t.security?.model || "model"}…`;
      return `${t.stage}…`;
    }
    if (t.status === "skipped") return t.reason?.startsWith("security model disabled") ? "model off · detectors only" : "nothing new to inspect";
    if (t.status === "blocked" || t.status === "error") return t.error || "failed";
    const ops = t.applied?.operations || [];
    const count = (op) => ops.filter((r) => r.op?.op === op).length;
    const parts = [];
    if (t.applied?.new_entities?.length) parts.push(`${t.applied.new_entities.length} new ${t.applied.new_entities.length === 1 ? "value" : "values"}`);
    for (const op of ["mask", "collapse", "relink", "unmask"]) if (count(op)) parts.push(`${count(op)} ${op}`);
    if (t.validation?.corrected) parts.push("corrected once");
    return parts.length ? parts.join(" · ") : "no change needed";
  }

  // ---------- list ----------
  function renderList() {
    const ids = [...new Set(traces().map((t) => t.session_id))];
    const chosen = sessionFilter.value;
    sessionFilter.replaceChildren(h("option", { value: "" }, "All sessions"), ...ids.map((id) => h("option", { value: id, selected: id === chosen }, short(id))));
    const shown = visible();
    list.replaceChildren();
    if (!shown.length) {
      list.append(h("div", { class: "empty" }, traces().length ? "No calls match." : "No calls yet."));
      return;
    }
    for (const t of [...shown].reverse()) {
      const [label, cls] = STATUS[t.status] || [t.status, "dim"];
      const duration = t.status === "running" ? ms(Math.round(Date.now() - t.started_at * 1000)) : ms(t.duration_ms);
      list.append(h("button", { class: "entry" + (t.id === selected ? " active" : ""), onclick: () => { selected = t.id; follow.checked = false; render(); } },
        h("div", { class: "l1" }, pill(label, cls), h("b", null, `${short(t.session_id)} · req ${t.request_index ?? "?"}`), h("small", { class: "muted" }, duration)),
        h("div", { class: "l2", title: summary(t) }, summary(t))));
    }
  }

  // ---------- detail ----------
  function flow(t) {
    const all = attempts(t);
    const disabled = t.status === "skipped";
    const failedAt = t.status === "blocked" || t.status === "error"
      ? (t.validation && !t.validation.ok ? "validation" : all.length ? "security" : t.stage === "detectors" ? "detectors" : "security")
      : null;
    const order = ["detectors", "security", "validation", "done"];
    const state = (step) => {
      if (failedAt === step) return "fail";
      if (failedAt && order.indexOf(step) > order.indexOf(failedAt)) return "skip";
      if (disabled && step !== "detectors") return "skip";
      if (t.status === "running") return order.indexOf(step) < order.indexOf(t.stage) ? "done" : step === t.stage ? "run" : "skip";
      return "done";
    };
    const d = t.detectors, c = t.security?.counts;
    const results = all.flatMap((a) => a.results || []);
    const rejected = results.filter((r) => !r.ok).length;
    const total = all.reduce((n, a) => n + (a.duration_ms || 0), 0);
    return h("div", { class: "flow" },
      h("div", { class: "step " + state("detectors") }, h("div", { class: "n" }, "1 · Detectors"),
        h("div", { class: "d" }, d ? `${plural(d.found.length, "new value")} · known values applied to ${t.known?.changed.length ?? 0} items` : "patterns, this machine, custom values")),
      h("div", { class: "step " + state("security") }, h("div", { class: "n" }, "2 · Security model"),
        h("div", { class: "d" }, disabled ? (t.reason || "not called") : all.length
          ? `${c?.new_items ?? 0} new items · ${plural(all.length, "call")} · ${total ? ms(total) : "waiting"}`
          : "not called yet")),
      h("div", { class: "step " + state("validation") }, h("div", { class: "n" }, "3 · Each operation checked"),
        h("div", { class: "d" }, results.length
          ? `${results.length - rejected} accepted · ${rejected} rejected${t.validation?.corrected ? " · corrected" : ""}`
          : disabled ? "–" : "exact text at line, overlaps, tokens")),
      h("div", { class: "step " + state("done") }, h("div", { class: "n" }, "4 · Applied"),
        h("div", { class: "d" }, t.status === "passed" ? `${t.applied?.changed_items?.length ?? 0} items changed · forwarded` : t.status === "skipped" ? "forwarded" : failedAt ? "blocked (fail closed)" : "–")));
  }

  function banner(t) {
    if (t.status === "running") {
      const a = current(t), s = t.security || {};
      if (t.stage === "security" && a.sent_at && a.duration_ms === undefined) {
        const elapsed = Date.now() / 1000 - a.sent_at;
        const pct = Math.min(100, (elapsed / (s.timeout_seconds || 1)) * 100);
        return h("div", { class: "banner warn" }, h("b", null, a.attempt > 1 ? "Waiting for the correction. " : "Waiting for the security model. "),
          `The agent's request is held until it answers. ${elapsed.toFixed(1)} s of the ${s.timeout_seconds} s timeout used; on timeout the request is blocked.`,
          h("div", { class: "meter" }, h("div", { style: `width:${pct}%` })));
      }
      return h("div", { class: "banner warn" }, h("b", null, "In progress: "), t.stage === "queued" ? "waiting for an earlier request of this session to finish" : t.stage);
    }
    if (t.status === "blocked" || t.status === "error")
      return h("div", { class: "banner bad" }, h("b", null, "Blocked. Nothing was sent upstream; the agent got HTTP 502. "), t.error);
    if (t.status === "skipped") return h("div", { class: "banner dim" }, h("b", null, "Security model not called. "), t.reason, ". The request was forwarded with detector masking and known values.");
    return h("div", { class: "banner ok" }, h("b", null, "Passed. "), summary(t) + ". The request was forwarded.");
  }

  // Remember which <details> are open, so live updates don't collapse them.
  function keep(id, el) {
    el.open = openFolds.has(id) || (el.open && !openFolds.has("!" + id));
    el.addEventListener("toggle", () => { if (el.open) { openFolds.add(id); openFolds.delete("!" + id); } else { openFolds.delete(id); openFolds.add("!" + id); } });
    return el;
  }

  // "#3" refs in the model's input map to item ids through the session's current items.
  function itemId(t, ref) {
    const session = App.state.sessions.find((s) => s.id === t.session_id);
    const n = Number(String(ref).replace("#", ""));
    return session && n ? session.items[n - 1]?.id : null;
  }
  const jump = (t, ref) => {
    const id = itemId(t, ref);
    return id ? h("button", { class: "link", title: "Open in Context", onclick: () => App.showContext(t.session_id, id) }, ref) : h("code", null, String(ref));
  };

  // Numbered raw lines with the parts already masked / left as-is outlined.
  function numberedLines(lines, masked = [], kept = []) {
    const pre = h("pre", { class: "numbered" });
    for (const { n, raw } of lines) {
      const marks = [...masked.map((m) => ({ ...m, cls: "secret", title: `${m.placeholder} · ${m.by}` })), ...kept.map((k) => ({ ...k, cls: "kept", title: `${k.token} left as-is: ${k.reason}` }))]
        .filter((m) => m.line === n);
      const parts = [];
      let cursor = 0;
      for (const m of marks.sort((a, b) => raw.indexOf(a.text) - raw.indexOf(b.text))) {
        let at = -1;
        for (let i = 0; i < (m.nth || 1); i++) at = raw.indexOf(m.text.split("\n")[0], at + 1);
        if (at < cursor) continue;
        const len = m.text.split("\n")[0].length;
        parts.push(raw.slice(cursor, at), h("mark", { class: m.cls, title: m.title }, raw.slice(at, at + len)));
        cursor = at + len;
      }
      parts.push(raw.slice(cursor));
      pre.append(h("span", { class: "ln" }, h("i", null, String(n)), ...parts, "\n"));
    }
    return pre;
  }

  function inputCard(t) {
    const s = t.security;
    if (!s || !s.input) return null;
    const input = s.input, c = s.counts || {};
    const newItems = input.new_items.map((item) => keep(`${t.id}:in:${item.item}`, fold(
      [jump(t, item.item), pill(item.role, "dim"), h("span", null, KIND[item.kind] || item.kind), h("span", { class: "muted" }, `${item.lines.length} lines`),
        item.masked ? pill(`${item.masked.length} already masked`, "info") : null,
        item.known_values_left_as_is ? pill(`${item.known_values_left_as_is.length} left as-is`, "dim") : null,
        item.collapsed ? pill(`${item.collapsed.length} collapsed`, "warn") : null],
      h("div", { class: "inner" }, numberedLines(item.lines, item.masked, item.known_values_left_as_is)))));
    const existing = input.existing_operations.map((op, i) => h("div", { class: "op" },
      h("div", { class: "what" }, pill(op.op, OP_CLS[op.op]), " ", jump(t, op.item), " ",
        op.op === "mask" ? [`line ${op.line} `, h("code", null, op.text), " → ", h("mark", { class: "ph" + (op.placeholder.startsWith("<$") ? " alias" : "") }, op.placeholder)]
          : [`lines ${op.start}–${op.end} → `, h("mark", { class: "block" }, `…[MASQ_BLOCK: ${op.summary}]…`)]),
      numberedLines(op.context, op.op === "mask" ? [{ ...op, by: "earlier operation" }] : [])));
    const mapping = input.mapping.length
      ? h("table", null, h("thead", null, h("tr", null, h("th", null, "Placeholder"), h("th", null, "Value"), h("th", null, "Origin"))),
        h("tbody", null, input.mapping.map((e) => h("tr", null,
          h("td", { class: "mono" }, e.token, e.linked_to ? h("div", { class: "aliases" }, "→ ", e.linked_to) : null),
          h("td", { class: "mono" }, e.value, e.alias_texts ? h("div", { class: "aliases" }, "marked forms: ", e.alias_texts.join(", ")) : null),
          h("td", { class: "muted" }, e.origin)))))
      : h("div", { class: "empty", style: "padding:10px" }, "Empty: no mappings yet.");
    const readOnly = (entries) => entries.length
      ? entries.map((r) => h("div", { class: "op" }, h("div", { class: "what" }, jump(t, r.item), " ", pill(r.role, "dim"), " ", KIND[r.kind] || "message"), h("pre", null, r.text)))
      : h("div", { class: "empty", style: "padding:10px" }, "None.");
    const limits = s.context_mode === "full" ? "Full mode: all operations, whole items as context, all tool context."
      : `Recent mode: ${App.state.config?.security?.nearest_ops === -1 ? "all" : "the nearest " + (App.state.config?.security?.nearest_ops ?? "N")} earlier operations with ±${App.state.config?.security?.op_context_lines ?? "k"} lines each; the last ${App.state.config?.security?.recent_items ?? "N"} tool results/calls/reasoning.`;
    return h("div", { class: "card" },
      h("h3", null, "What the model receives", h("span", { class: "sub" }, `${s.model} at ${s.provider} · ${s.api_format} format · ${s.endpoint}`)),
      h("div", { class: "body" }, h("dl", { class: "kv" },
        h("dt", null, "To inspect"), h("dd", null, `${c.new_items} new items, never inspected before, with numbered raw lines. Outlined: what is already masked (red) and known values left as-is (dashed).`),
        h("dt", null, "Earlier operations"), h("dd", null, `${c.existing_operations}, with the raw lines around each. ${limits}`),
        h("dt", null, "Task intent"), h("dd", null, `${c.conversation} user/assistant messages (all of them) and ${c.recent} recent tool calls, results and reasoning, read-only.`),
        h("dt", null, "Mapping"), h("dd", null, `${c.mapping} known values with their real values, so the model can mark partial forms and links.`))),
      keep(`${t.id}:prompt`, fold([h("b", null, "Instructions"), h("span", { class: "muted" }, s.custom_prompt ? "custom (from Configuration)" : "built-in")], h("pre", null, s.system_prompt))),
      keep(`${t.id}:items`, fold([h("b", null, "New items"), h("span", { class: "muted" }, String(input.new_items.length))], h("div", { class: "inner" }, newItems), { open: true })),
      keep(`${t.id}:existing`, fold([h("b", null, "Earlier operations nearby"), h("span", { class: "muted" }, String(input.existing_operations.length))],
        h("div", { class: "inner" }, existing.length ? existing : h("div", { class: "empty", style: "padding:10px" }, "None.")))),
      keep(`${t.id}:mapping`, fold([h("b", null, "Mapping table"), h("span", { class: "muted" }, String(input.mapping.length))], h("div", { class: "inner" }, mapping))),
      keep(`${t.id}:conv`, fold([h("b", null, "Conversation"), h("span", { class: "muted" }, String(input.conversation.length))], h("div", { class: "inner" }, readOnly(input.conversation)))),
      keep(`${t.id}:recent`, fold([h("b", null, "Recent tool context"), h("span", { class: "muted" }, String(input.recent_tool_context.length))], h("div", { class: "inner" }, readOnly(input.recent_tool_context)))),
      keep(`${t.id}:json`, fold([h("b", null, "Exact input JSON"), h("span", { class: "muted" }, "the first user message, verbatim")], h("pre", null, JSON.stringify(input, null, 2)))));
  }

  function describeOp(t, op) {
    if (!op || typeof op !== "object") return h("code", null, JSON.stringify(op));
    const where = op.item ? [jump(t, op.item), op.line ? ` line ${op.line}` : ""] : [];
    switch (op.op) {
      case "mask":
        return [where, " ", h("code", null, op.text ?? "?"), op.nth > 1 ? ` (#${op.nth})` : "", " → ",
          op.token ? [op.alias ? "partial form of " : "", h("code", null, op.token)] : ["new ", h("b", null, op.type || "SECRET"), op.label ? ` "${op.label}"` : ""]];
      case "collapse":
        return [where, ` lines ${op.start}–${op.end} → `, h("mark", { class: "block" }, `…[MASQ_BLOCK: ${op.summary ?? ""}]…`)];
      case "relink":
        return [h("code", null, op.token), " becomes a partial form of ", h("code", null, op.to)];
      case "unmask":
        return [where, " keep ", h("code", null, op.text ?? "?"), " as-is"];
      default:
        return h("code", null, JSON.stringify(op));
    }
  }

  function attemptCard(t, a) {
    if (a.raw_output === undefined) {
      return h("div", { class: "card" }, h("h3", null, a.attempt > 1 ? "Correction" : "What the model answered", pill(t.status === "running" ? "waiting" : "no answer", t.status === "running" ? "run" : "bad")),
        a.correction ? keep(`${t.id}:corr${a.attempt}`, fold([h("b", null, "Errors sent back")], h("pre", null, a.correction), { open: true })) : null,
        h("div", { class: "body muted" }, t.status === "running" ? "No answer yet." : "The call failed before a response arrived (timeout or connection error)."));
    }
    let pretty = a.raw_output;
    try { pretty = JSON.stringify(JSON.parse(a.raw_output), null, 2); } catch { /* show as-is */ }
    const results = a.results || [];
    const rejected = results.filter((r) => !r.ok).length;
    const rows = results.map((r) => h("div", { class: "op" + (r.ok ? "" : " rejected") },
      h("div", { class: "what" }, pill(r.op?.op || "?", r.ok ? OP_CLS[r.op?.op] || "dim" : "bad"), " ", describeOp(t, r.op)),
      h("div", { class: r.ok ? "muted" : "error", style: "font-size:11.5px" }, r.ok ? "✓ " + r.effect : "✕ " + r.error)));
    return h("div", { class: "card" },
      h("h3", null, a.attempt > 1 ? "Correction" : "What the model answered",
        a.http_status >= 400 ? pill(`HTTP ${a.http_status}`, "bad") : !a.parsed ? pill("not valid JSON", "bad") : rejected ? pill(`${rejected} rejected`, "bad") : pill("all accepted", "ok"),
        h("span", { class: "sub" }, [ms(a.duration_ms), a.usage ? `${a.usage.prompt_tokens ?? a.usage.input_tokens ?? "?"} in / ${a.usage.completion_tokens ?? a.usage.output_tokens ?? "?"} out tokens` : ""].filter(Boolean).join(" · "))),
      a.correction ? keep(`${t.id}:corr${a.attempt}`, fold([h("b", null, "Errors sent back"), h("span", { class: "muted" }, "only the rejected operations")], h("pre", null, a.correction))) : null,
      a.parsed ? (rows.length ? h("div", null, rows) : h("div", { class: "body muted" }, "No operations: the model found nothing new to mask or collapse.")) : null,
      keep(`${t.id}:raw${a.attempt}`, fold([h("b", null, "Raw output"), h("span", { class: "muted" }, "shown here only, never logged")], h("pre", null, pretty), { open: !a.parsed })));
  }

  function resultCard(t) {
    const d = t.detectors || { found: [] };
    if (t.status !== "passed" && !d.found.length) return null;
    const a = t.applied || {};
    const changed = a.changed_items || [];
    const session = App.state.sessions.find((s) => s.id === t.session_id);
    const ref = (id) => { const n = session ? session.items.findIndex((i) => i.id === id) : -1; return n >= 0 ? `#${n + 1}` : id.slice(0, 8); };
    return h("div", { class: "card" },
      h("h3", null, "Effect on the outbound context"),
      h("div", { class: "body" }, h("dl", { class: "kv" },
        h("dt", null, "Detectors found"), h("dd", null, d.found.length ? d.found.map((e) => h("div", null, h("code", null, e.token), " ", h("span", { class: "muted" }, `${e.source}:`), " ", h("code", null, e.canonical))) : "nothing new"),
        a.new_entities?.length ? [h("dt", null, "New values"), h("dd", null, a.new_entities.map((e) => h("div", null, h("code", null, e.token), " ", h("code", null, e.canonical))))] : null,
        t.status === "passed" ? [h("dt", null, "Items changed"), h("dd", null, changed.length
          ? changed.map((c) => h("div", null, h("button", { class: "link", onclick: () => App.showContext(t.session_id, c.id) }, ref(c.id)), ` ${c.role} ${KIND[c.kind] || c.kind} `,
            c.remasked ? pill("earlier item re-masked", "warn", "Not new in this request, but changed because a newly found value also appears here. The upstream prompt cache for this prefix is lost.") : null))
          : "none")] : null)));
  }

  function render() {
    clearInterval(timer);
    timer = null;
    if (document.getElementById("viewSecurity").hidden) return;
    renderList();
    const all = traces();
    if (follow.checked && all.length) selected = visible().at(-1)?.id ?? selected;
    const t = all.find((x) => x.id === selected);
    if (!t) {
      main.replaceChildren(h("div", { class: "empty" }, "Each request passes through the detectors and, when enabled, the security model. Calls appear here live: what the model is given, what it answers, how each operation was judged, and what was applied."));
      return;
    }
    if (t.status === "running") timer = setInterval(render, 250);
    const scroll = main.scrollTop;
    main.replaceChildren(
      h("div", { class: "bar" },
        h("h2", null, `${short(t.session_id)} · request ${t.request_index ?? "?"}`),
        pill(...(STATUS[t.status] || [t.status, "dim"]).slice(0, 2)),
        h("span", { class: "muted", style: "font-size:12px" }, [t.endpoint, t.model ? `model ${t.model}` : "", t.request_id, ago(t.started_at), t.duration_ms !== null ? `took ${ms(t.duration_ms)}` : ""].filter(Boolean).join(" · ")),
        h("span", { class: "grow" }),
        h("button", { class: "small", onclick: () => App.showContext(t.session_id) }, "Open in Context")),
      h("div", { class: "sec" }, banner(t), flow(t), inputCard(t), ...attempts(t).map((a) => attemptCard(t, a)), resultCard(t)));
    main.scrollTop = scroll;
  }

  follow.onchange = () => { if (follow.checked) render(); };
  sessionFilter.onchange = render;
  hideSkipped.onchange = render;

  return { render };
})();
