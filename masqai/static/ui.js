// Shared DOM helpers for the pages (config.js keeps its own copy of h()), plus the admin-token API helper.
const UI = (() => {
  // The admin token arrives once in the URL fragment (#token=…), printed by the gateway at startup.
  // It moves to sessionStorage and leaves the URL, so it isn't kept in history or shared screenshots.
  const TOKEN_KEY = "masqai-admin-token";
  (() => {
    const match = location.hash.match(/(?:^#|&)token=([^&]+)/);
    if (match) {
      sessionStorage.setItem(TOKEN_KEY, decodeURIComponent(match[1]));
      history.replaceState(null, "", location.pathname + location.search);
    }
  })();
  const token = () => sessionStorage.getItem(TOKEN_KEY) || "";

  // Every control-API call carries x-masqai-token. A 401 means the token is missing or from an earlier start.
  async function api(path, options = {}) {
    const response = await fetch(path, { ...options, headers: { ...(options.headers || {}), "x-masqai-token": token() } });
    if (response.status === 401) document.dispatchEvent(new CustomEvent("masqai-unauthorized"));
    return response;
  }

  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") el.className = value;
      else if (key === "dataset") Object.assign(el.dataset, value);
      else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
      else if (key in el) el[key] = value;
      else el.setAttribute(key, value === true ? "" : value);
    }
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : String(child));
    }
    return el;
  }

  const text = (value) => (typeof value === "string" ? value : JSON.stringify(value, null, 2));
  const short = (id) => (id || "").replace(/^session-/, "").slice(0, 8);
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

  function ago(seconds) {
    const s = Math.max(0, Date.now() / 1000 - seconds);
    if (s < 5) return "now";
    if (s < 60) return `${Math.round(s)}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    return `${Math.round(s / 3600)}h ago`;
  }

  const ms = (value) => (value === null || value === undefined ? "" : value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(1)} s`);

  // Line diff (LCS). Falls back to whole-item highlighting for very large pairs.
  function diff(a, b) {
    const x = a.split("\n"), y = b.split("\n");
    if (x.length * y.length > 250000) return [x.map((t) => [t, a !== b]), y.map((t) => [t, a !== b])];
    const table = Array.from({ length: x.length + 1 }, () => new Uint32Array(y.length + 1));
    for (let i = x.length - 1; i >= 0; i--)
      for (let j = y.length - 1; j >= 0; j--)
        table[i][j] = x[i] === y[j] ? 1 + table[i + 1][j + 1] : Math.max(table[i + 1][j], table[i][j + 1]);
    let i = 0, j = 0;
    const left = [], right = [];
    while (i < x.length || j < y.length) {
      if (i < x.length && j < y.length && x[i] === y[j]) { left.push([x[i++], false]); right.push([y[j++], false]); }
      else if (j < y.length && (i === x.length || table[i][j + 1] >= table[i + 1][j])) right.push([y[j++], true]);
      else left.push([x[i++], true]);
    }
    return [left, right];
  }

  // Inline marks: placeholders (<TYPE_id>, <$TYPE_id>), hidden-intel markers, and known raw values.
  const TOKEN = /<\$?[A-Z][A-Z0-9_]*_[a-f0-9]{8}>|…\[hidden: [^\]\n]*\]…/g;
  const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // entities: [{token, type, canonical, aliases}]. Returns a marker for one side.
  function marker(entities, side) {
    const byToken = new Map(entities.map((e) => [e.token, e]));
    let raw = null;
    const values = new Map();
    if (side === "raw") {
      for (const e of entities) for (const v of [e.canonical, ...(e.aliases || [])]) if (v && v.length >= 2) values.set(v, e);
      const sorted = [...values.keys()].sort((a, b) => b.length - a.length).map(escape);
      raw = sorted.length ? new RegExp(sorted.join("|"), "g") : null;
    }
    return (line) => {
      const pattern = side === "raw" ? raw : TOKEN;
      if (!pattern || !line) return [line];
      const out = [];
      let last = 0;
      pattern.lastIndex = 0;
      for (const m of line.matchAll(pattern)) {
        if (m.index > last) out.push(line.slice(last, m.index));
        const s = m[0];
        if (side === "raw") {
          const e = values.get(s);
          out.push(h("mark", { class: "secret", title: `${e.type} → ${e.token}${s === e.canonical ? "" : " (alias)"}` }, s));
        } else if (s.startsWith("…[hidden")) {
          out.push(h("mark", { class: "block", title: "Intel hidden by the security model (lossy). The original lines stay in RAM." }, s));
        } else {
          const e = byToken.get(s.replace("<$", "<"));
          out.push(h("mark", { class: "ph" + (s.startsWith("<$") ? " alias" : ""), title: e ? `${e.type}: ${e.canonical}${s.startsWith("<$") ? " (alias form)" : ""}` : "unknown placeholder" }, s));
        }
        last = m.index + s.length;
      }
      if (last < line.length) out.push(line.slice(last));
      return out;
    };
  }

  // A <pre> from [[line, changed]] pairs. cls: "del" | "ins" for changed lines.
  function lines(pairs, cls, mark, { numbers = false } = {}) {
    const pre = h("pre", { class: numbers ? "numbered" : "" });
    pairs.forEach(([line, changed], index) => {
      const row = h("span", { class: "ln" + (changed ? " " + cls : "") });
      if (numbers) row.append(h("i", null, String(index + 1)));
      row.append(...(mark ? mark(line) : [line]), "\n");
      pre.append(row);
    });
    return pre;
  }

  const pill = (label, cls, title) => h("span", { class: "pill " + (cls || ""), title }, label);

  // Collapsible block with a header. open: initial state.
  function fold(summary, body, { open = false, cls = "" } = {}) {
    return h("details", { class: "fold " + cls, open }, h("summary", null, summary), body);
  }

  // Render-throttle: at most once per animation frame.
  function throttle(fn) {
    let queued = false;
    return () => {
      if (queued) return;
      queued = true;
      requestAnimationFrame(() => { queued = false; fn(); });
    };
  }

  // Side-by-side diff as aligned blocks: {eq: [[a, b, aOffset], ...]} or {chg: {a: [[line, offset]...], b: [...]}}.
  // aOffset is the character offset of the raw line, for span-based marks.
  function align(a, b) {
    const x = a.split("\n"), y = b.split("\n");
    const offs = [];
    let o = 0;
    for (const line of x) { offs.push(o); o += line.length + 1; }
    if (x.length * y.length > 250000) return a === b ? [{ eq: x.map((t, i) => [t, t, offs[i]]) }] : [{ chg: { a: x.map((t, i) => [t, offs[i]]), b: y } }];
    const table = Array.from({ length: x.length + 1 }, () => new Uint32Array(y.length + 1));
    for (let i = x.length - 1; i >= 0; i--)
      for (let j = y.length - 1; j >= 0; j--)
        table[i][j] = x[i] === y[j] ? 1 + table[i + 1][j + 1] : Math.max(table[i + 1][j], table[i][j + 1]);
    const blocks = [];
    const push = (type, ai, bi) => {
      let last = blocks.at(-1);
      if (type === "eq") {
        if (!last?.eq) blocks.push((last = { eq: [] }));
        last.eq.push([x[ai], y[bi], offs[ai]]);
      } else {
        if (!last?.chg) blocks.push((last = { chg: { a: [], b: [] } }));
        if (ai !== null) last.chg.a.push([x[ai], offs[ai]]);
        if (bi !== null) last.chg.b.push(y[bi]);
      }
    };
    let i = 0, j = 0;
    while (i < x.length || j < y.length) {
      if (i < x.length && j < y.length && x[i] === y[j]) push("eq", i++, j++);
      else if (j < y.length && (i === x.length || table[i][j + 1] >= table[i + 1][j])) push("chg", null, j++);
      else push("chg", i++, null);
    }
    return blocks;
  }

  // Raw-side marks from exact spans. spans: [{start, end, placeholder, origin}] masked here;
  // unmasked: [{start, end, token, reason}] known values deliberately left as-is. Returns a function
  // that marks one line given its character offset in the item text.
  function spanMarker(spans, unmasked, replaces = []) {
    const marks = [
      ...spans.map((s) => ({ ...s, cls: "secret" + (s.origin === "model" ? " model" : ""),
        title: `sent as ${s.placeholder} · ${s.origin === "model" ? "found by the security model" : "detector or automatic copy of a known value"}` })),
      ...unmasked.map((u) => ({ ...u, cls: "kept", title: `matches ${u.token} but left as-is: ${u.reason}` })),
      ...replaces.map((r) => ({ ...r, cls: "intel", title: `intel replaced with “${r.with}”${r.reason ? ": " + r.reason : ""}` })),
    ].sort((a, b) => a.start - b.start);
    return (line, offset) => {
      const end = offset + line.length;
      const out = [];
      let cursor = offset;
      for (const m of marks) {
        if (m.end <= offset || m.start >= end) continue;
        const a = Math.max(m.start, offset), b = Math.min(m.end, end);
        if (a < cursor) continue;
        if (a > cursor) out.push(line.slice(cursor - offset, a - offset));
        out.push(h("mark", { class: m.cls, title: m.title }, line.slice(a - offset, b - offset)));
        cursor = b;
      }
      if (cursor < end) out.push(line.slice(cursor - offset));
      return out.length ? out : [line];
    };
  }

  // Sent-side marks for one item: the session marker, plus each replace's neutral substitute.
  function outMarker(base, replaces = []) {
    const subs = [...new Set(replaces.map((r) => r.with))].filter(Boolean).sort((a, b) => b.length - a.length);
    if (!subs.length) return base;
    const pattern = new RegExp(subs.map(escape).join("|"), "g");
    return (line) => base(line).flatMap((part) => {
      if (typeof part !== "string") return [part];
      const out = [];
      let last = 0;
      for (const m of part.matchAll(pattern)) {
        if (m.index > last) out.push(part.slice(last, m.index));
        out.push(h("mark", { class: "intel", title: "Intel replaced by the security model (lossy, never restored)" }, m[0]));
        last = m.index + m[0].length;
      }
      if (last < part.length) out.push(part.slice(last));
      return out;
    });
  }

  return { h, text, short, plural, ago, ms, diff, align, marker, spanMarker, outMarker, lines, pill, fold, throttle, api, token };
})();
