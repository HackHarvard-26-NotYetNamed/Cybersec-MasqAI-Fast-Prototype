// Context page, the dual-reality inspector: per session, what the agent sent (raw, stays on this machine)
// next to what went to the untrusted model.
const ContextPage = (() => {
  const { h, text, short, plural, ago, align, marker, lines, pill } = UI;
  const main = document.getElementById("contextMain");
  const list = document.getElementById("sessions");
  const seenRevision = new Map();   // item id -> last rendered revision, to flash rewritten items

  let selected = null;
  const filters = { changedOnly: false, kind: "all", query: "" };
  const expanded = new Set();      // item ids shown in full / gap keys opened
  let focusItem = null;            // scroll target after a jump from the Security page
  const cache = new Map();         // diff cache: key -> blocks

  const KIND = {
    message: "message", tool_result: "tool result", tool_arguments: "tool call arguments",
    system: "system prompt", tool_definition: "tool description", reasoning: "reasoning", opaque: "opaque content",
  };
  const KIND_FILTERS = [
    ["all", "All items"], ["message", "Messages"], ["tool_result", "Tool results"], ["tool_arguments", "Tool call arguments"],
    ["system", "System prompt + tool descriptions"], ["reasoning", "Reasoning"],
  ];
  const PREVIEW_LINES = 14;   // unchanged items longer than this are clipped until expanded
  const CONTEXT_LINES = 3;    // unchanged lines kept around a change

  const isResponse = (item) => item.id.startsWith("response-");
  const TOKEN = /<\$?[A-Z][A-Z0-9_]*_[a-f0-9]{8}>/;
  let textMarker = (line) => [line];   // value-based marks, for reasoning/response items only

  // ---------- session list ----------
  function renderList(sessions) {
    document.getElementById("sessionCount").textContent = sessions.length ? String(sessions.length) : "";
    list.replaceChildren();
    if (!sessions.length) {
      list.append(h("div", { class: "empty" }, "No sessions yet."));
      return;
    }
    for (const s of [...sessions].reverse()) {
      list.append(h("button", {
        class: "entry" + (s.id === selected ? " active" : ""),
        title: s.id + (s.hint ? `\nhint: ${s.hint}` : ""),
        onclick: () => select(s.id),
      },
        h("div", { class: "l1" }, h("b", null, short(s.id)),
          s.rollbacks ? pill(`↶${s.rollbacks}`, "warn", `${plural(s.rollbacks, "rollback")}: the agent's history diverged (compaction, edit or retry) and the stored items were replaced`) : null,
          s.parent_id ? pill("branch", "info", `Branched from ${s.parent_id}; inherits its mappings and pseudonym`) : null,
          s.in_flight ? pill("busy", "run", "A request or stream is in flight") : null),
        h("div", { class: "l2" }, `${plural(s.request_count, "request")} · ${s.items} items · ${plural(s.entities, "mapping")} · ${ago(s.last_seen)}`)));
    }
  }

  // ---------- item rendering ----------
  function diffBlocks(item, raw, out) {
    const key = `${item.id}:${item.revision}:${raw.length}:${out.length}`;
    let blocks = cache.get(key);
    if (!blocks) {
      blocks = align(raw, out);
      if (cache.size > 2000) cache.clear();
      cache.set(key, blocks);
    }
    return blocks;
  }

  // Unchanged item: one full-width column. Long ones are clipped until expanded.
  function sameBody(item, raw, markRaw) {
    const all = raw.split("\n");
    const open = expanded.has(item.id) || all.length <= PREVIEW_LINES + 2;
    const shown = open ? all : all.slice(0, PREVIEW_LINES);
    const pre = h("pre");
    let offset = 0;
    for (const line of shown) {
      pre.append(h("span", { class: "ln" }, ...markRaw(line, offset), "\n"));
      offset += line.length + 1;
    }
    const body = h("div", { class: "same" }, h("span", { class: "tag" }, isResponse(item) ? "as received" : "identical upstream"), pre);
    if (!open) body.append(h("button", { class: "gap", onclick: () => { expanded.add(item.id); render(); } }, `show all ${all.length} lines`));
    else if (all.length > PREVIEW_LINES + 2) body.append(h("button", { class: "gap", onclick: () => { expanded.delete(item.id); render(); } }, "show less"));
    return body;
  }

  // Changed item: one grid row per line pair, so wrapped lines stay aligned left/right.
  // Long unchanged runs fold into an expandable gap.
  function diffBody(item, raw, out, markRaw, markOut) {
    const blocks = diffBlocks(item, raw, out);
    const grid = h("div", { class: "dgrid" });
    const left = (pair, cls) => pair === null
      ? h("div", { class: "ln fill l" }, " ")
      : h("div", { class: "ln l" + (cls ? " " + cls : "") }, ...markRaw(pair[0], pair[1]));
    const right = (line, cls) => line === null
      ? h("div", { class: "ln fill" }, " ")
      : h("div", { class: "ln" + (cls ? " " + cls : "") }, ...markOut(line));
    const row = (a, b, changed) => grid.append(left(a, changed && a !== null ? "del" : ""), right(b, changed && b !== null ? "ins" : ""));
    blocks.forEach((block, bi) => {
      if (block.chg) {
        const n = Math.max(block.chg.a.length, block.chg.b.length);
        for (let k = 0; k < n; k++) row(block.chg.a[k] ?? null, block.chg.b[k] ?? null, true);
        return;
      }
      const eq = block.eq;
      const keepHead = bi === 0 ? 0 : CONTEXT_LINES, keepTail = bi === blocks.length - 1 ? 0 : CONTEXT_LINES;
      const gapKey = `${item.id}#${bi}`;
      const eqRow = ([a, b, offset]) => row([a, offset], b, false);
      if (eq.length > keepHead + keepTail + 2 && !expanded.has(gapKey)) {
        eq.slice(0, keepHead).forEach(eqRow);
        grid.append(h("button", { class: "gap span2", onclick: () => { expanded.add(gapKey); render(); } }, `${eq.length - keepHead - keepTail} unchanged lines · show`));
        eq.slice(eq.length - keepTail).forEach(eqRow);
      } else {
        eq.forEach(eqRow);
      }
    });
    return grid;
  }

  function itemPills(item, raw, out) {
    const pills = [];
    if (item.opaque) pills.push(pill("opaque", "dim", "Whitelisted content MasqAI can't read (an image, a base64 document): forwarded unread, shown only as a description."));
    else if (item.reasoning) pills.push(pill("protected", "warn", "Reasoning is passed through untouched: editing it would break its signature or encrypted content. Known values are highlighted if present."));
    else if (isResponse(item)) pills.push(pill("from upstream", "info", "Observed in the untrusted model's response. Its text is passed through unmodified; placeholders in tool-call arguments are restored before the agent receives them."));
    else if (item.kind === "system" || item.kind === "tool_definition") pills.push(pill("mask only", "dim", "Inspected once per distinct content, then reused so the prompt cache stays stable. Never hidden or replaced."));
    if (item.changed) {
      if (TOKEN.test(out)) pills.push(pill("masked", "ok", "Contains placeholders"));
      if ((item.spans || []).some((s) => s.origin === "model")) pills.push(pill("found by security model", "model", "At least one value here was missed by the rules and masked by the security model"));
      if ((item.hides || []).length) pills.push(pill(`${item.hides.length} hidden`, "warn", "Lines of intel hidden by the security model (lossy)"));
      if ((item.replaces || []).length) pills.push(pill(`${item.replaces.length} replaced`, "warn", "Intel replaced with neutral words by the security model (lossy, never restored)"));
    } else if (!item.reasoning && !isResponse(item) && !item.opaque) pills.push(pill("unchanged", "dim"));
    const vetoed = (item.unmasked || []).filter((u) => u.reason.startsWith("vetoed")).length;
    if (vetoed) pills.push(pill(`${vetoed} vetoed`, "model", "Automatic masks the security model undid"));
    if (item.revision > 0 && !isResponse(item)) pills.push(pill(`re-sanitized ×${item.revision}`, "warn", "This already-sent item changed after a later discovery (retroactive re-mask or relink). The upstream prompt cache for this prefix is broken, on purpose."));
    return pills;
  }

  function itemCard(item, index, sessionMarkOut) {
    const raw = text(item.original), out = text(item.sanitized);
    const markOut = UI.outMarker(sessionMarkOut, item.replaces || []);
    // Flash an already-sent item whose outbound text was rewritten (re-mask or relink), not streamed responses.
    const flash = !isResponse(item) && seenRevision.has(item.id) && item.revision > seenRevision.get(item.id);
    seenRevision.set(item.id, item.revision);
    const changed = raw !== out;
    // Raw-side marks come from the exact spans the gateway applied, not from re-searching values.
    // Reasoning has no spans; known values in it are marked by text so the user can see them.
    const markRaw = item.reasoning || isResponse(item) ? textMarker : UI.spanMarker(item.spans || [], item.unmasked || [], item.replaces || []);
    const removed = changed ? raw.split("\n").length - out.split("\n").length : 0;
    const kept = (item.unmasked || []).length;
    const note = (changed ? `${raw.length} → ${out.length} chars${removed > 0 ? ` · ${removed} lines fewer` : ""}` : `${raw.split("\n").length} lines · ${raw.length} chars`)
      + (kept ? ` · ${kept} known ${kept === 1 ? "copy" : "copies"} left as-is` : "");
    return h("section", { class: "item" + (changed ? " changed" : "") + (flash ? " flash" : ""), id: "item-" + item.id, dataset: { item: item.id } },
      h("header", null,
        h("span", { class: "idx" }, `#${index + 1}`),
        h("span", { class: "role" }, item.role),
        h("span", { class: "kind" }, KIND[item.kind] || item.kind),
        itemPills(item, raw, out),
        h("span", { class: "note", title: item.id }, note)),
      changed ? diffBody(item, raw, out, markRaw, markOut) : sameBody(item, raw, markRaw));
  }

  function matches(item) {
    if (filters.changedOnly && !item.changed) return false;
    if (filters.kind !== "all") {
      const kinds = filters.kind === "system" ? ["system", "tool_definition"] : [filters.kind];
      if (!kinds.includes(item.kind)) return false;
    }
    if (filters.query) {
      const q = filters.query.toLowerCase();
      if (!text(item.original).toLowerCase().includes(q) && !text(item.sanitized).toLowerCase().includes(q)) return false;
    }
    return true;
  }

  // ---------- main ----------
  function toolbar(session, shown, total) {
    const changed = session.items.filter((i) => i.changed).length;
    const rawChars = session.items.filter((i) => !isResponse(i)).reduce((n, i) => n + text(i.original).length, 0);
    const outChars = session.items.filter((i) => !isResponse(i)).reduce((n, i) => n + text(i.sanitized).length, 0);
    const search = h("input", {
      type: "search", placeholder: "Search raw or sent text", value: filters.query,
      oninput: (e) => { filters.query = e.target.value; render(); },
    });
    return h("div", { class: "bar" },
      h("h2", { title: session.id }, short(session.id)),
      h("div", { class: "stats" },
        pill(plural(session.request_count, "request"), "dim"),
        pill(`${changed}/${session.items.length} items changed`, changed ? "ok" : "dim"),
        pill(plural(session.entities.length, "mapping"), "dim"),
        outChars < rawChars ? pill(`${Math.round((1 - outChars / rawChars) * 100)}% fewer chars sent`, "info", `${rawChars} raw → ${outChars} sent (request items)`) : null,
        session.rollbacks ? pill(plural(session.rollbacks, "rollback"), "warn", "History diverged and the stored items were replaced") : null,
        session.remasks ? pill(`cache broken ×${session.remasks}`, "warn", "Already-sent items re-sanitized after a later discovery or relink. Each one breaks the upstream prompt cache; accepted for privacy.") : null,
        (session.relinks || []).length ? pill(plural(session.relinks.length, "relink"), "model", "An earlier masked fragment was linked to a newly found full value; its earlier occurrences are now sent as <$…>") : null,
        session.parent_id ? pill(`branched from ${short(session.parent_id)}`, "info", session.parent_id) : null),
      h("span", { class: "grow" }),
      h("select", { onchange: (e) => { filters.kind = e.target.value; render(); } },
        KIND_FILTERS.map(([value, label]) => h("option", { value, selected: filters.kind === value }, label))),
      h("label", null, h("input", { type: "checkbox", checked: filters.changedOnly, onchange: (e) => { filters.changedOnly = e.target.checked; render(); } }), "changed only"),
      search,
      shown !== total ? h("span", { class: "muted", style: "font-size:12px" }, `${shown} of ${total} shown`) : null);
  }

  const legend = () => h("div", { class: "legend" },
    h("span", null, h("span", { class: "sw del" }, "red line"), " raw line that did not go out as-is"),
    h("span", null, h("span", { class: "sw ins" }, "green line"), " what went out instead"),
    h("span", null, h("mark", { class: "secret" }, "value"), " masked by a detector or auto copy"),
    h("span", null, h("mark", { class: "secret model" }, "value"), " found by the security model"),
    h("span", null, h("mark", { class: "kept" }, "value"), " known value left as-is (inside a word, or vetoed)"),
    h("span", null, h("mark", { class: "ph" }, "<TYPE_id>"), " placeholder"),
    h("span", null, h("mark", { class: "ph alias" }, "<$TYPE_id>"), " alias (partial form)"),
    h("span", null, h("mark", { class: "block" }, "…[hidden: …]…"), " intel hidden"),
    h("span", null, h("mark", { class: "intel" }, "neutral words"), " intel replaced"),
    h("span", null, "Hover a mark for its meaning."));

  function render() {
    const sessions = App.state.sessions;
    renderList(sessions);
    const summary = sessions.find((s) => s.id === selected);
    if (!summary) {
      main.replaceChildren(h("div", { class: "empty" }, "Route an agent request through MasqAI to inspect its context.",
        h("br"), h("small", null, "Point the agent at ", h("code", null, location.origin + "/v1"), " (OpenAI style) or ", h("code", null, location.origin), " (Anthropic style).")));
      return;
    }
    const session = App.detail(selected);
    if (!session) {
      main.replaceChildren(h("div", { class: "empty" }, "Loading session…"));
      App.loadDetail(selected);
      return;
    }
    textMarker = marker(session.entities, "raw");
    const markOut = marker(session.entities, "out");
    // Live updates re-render: keep scroll position and the search box's focus/caret.
    const scroll = main.scrollTop;
    const searching = document.activeElement?.matches?.("#contextMain input[type=search]");
    const caret = searching ? document.activeElement.selectionStart : null;
    const visible = session.items.map((item, index) => [item, index]).filter(([item]) => matches(item));
    const content = [];
    let inResponse = false;
    let toolGroup = [];
    const flushTools = () => {
      if (!toolGroup.length) return;
      const group = toolGroup;
      toolGroup = [];
      if (group.length < 3 || group.some(([i]) => i.changed) || filters.kind === "system" || filters.query) {
        group.forEach(([item, index]) => content.push(itemCard(item, index, markOut)));
        return;
      }
      const key = "tools#" + group[0][0].id;
      if (expanded.has(key)) {
        content.push(h("button", { class: "gap", style: "margin:6px 14px;width:calc(100% - 28px)", onclick: () => { expanded.delete(key); render(); } }, `hide ${group.length} unchanged tool descriptions`));
        group.forEach(([item, index]) => content.push(itemCard(item, index, markOut)));
      } else {
        content.push(h("button", { class: "gap", style: "margin:6px 14px;width:calc(100% - 28px)", onclick: () => { expanded.add(key); render(); } },
          `#${group[0][1] + 1}–${group.at(-1)[1] + 1}: ${group.length} tool descriptions, unchanged (known mappings only) · show`));
      }
    };
    content.push(h("div", { class: "divider" }, "Request context · the agent's history as sent on the latest request"));
    for (const [item, index] of visible) {
      if (isResponse(item) && !inResponse) {
        flushTools();
        inResponse = true;
        content.push(h("div", { class: "divider" }, "Upstream response · observed as it streams in"));
      }
      if (item.kind === "tool_definition") { toolGroup.push([item, index]); continue; }
      flushTools();
      content.push(itemCard(item, index, markOut));
    }
    flushTools();
    if (!visible.length) content.push(h("div", { class: "empty" }, "No items match the filters."));
    main.replaceChildren(
      toolbar(session, visible.length, session.items.length),
      legend(),
      h("div", { class: "cols head" }, h("div", null, "Agent sent · raw, never leaves this machine"), h("div", null, "Sent to the untrusted model · what its operator sees")),
      ...content);
    main.scrollTop = scroll;
    if (searching) { const el = main.querySelector("input[type=search]"); el.focus(); el.setSelectionRange(caret, caret); }
    if (focusItem) {
      const target = document.getElementById("item-" + focusItem);
      focusItem = null;
      if (target) { target.scrollIntoView({ block: "center" }); target.animate([{ outline: "2px solid #6be5c0" }, { outline: "2px solid transparent" }], 1600); }
    }
  }

  function select(id, itemId) {
    selected = id;
    if (itemId) { focusItem = itemId; filters.changedOnly = false; filters.kind = "all"; filters.query = ""; }
    App.loadDetail(id);
    render();
  }

  return {
    render,
    select,
    selectedId: () => selected,
    setQuery: (q) => { filters.query = q; render(); },
    ensureSelection: () => { if (!App.state.sessions.some((s) => s.id === selected)) selected = App.state.sessions.at(-1)?.id ?? null; },
  };
})();
