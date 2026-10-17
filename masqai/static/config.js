// Configuration panel: a form over GET/POST /api/config with inline help for every field.
// Changes are applied in memory by the gateway; "Export JSON" produces a masqai.json to persist them.
const ConfigPanel = (() => {
  const form = document.getElementById("configForm");
  const nav = document.getElementById("configNav");
  const saveState = document.getElementById("saveState");
  const applyButton = document.getElementById("applyConfig");

  let saved = null;      // last config returned by the server
  let ui = null;         // editable draft (routes/headers as row arrays)
  let meta = { features: {} };
  let errors = [];       // [{loc: [...], msg}] from the last failed apply
  let notice = "";
  const envStatus = new Map();  // env var name -> true/false/undefined(pending)
  let uid = 0;

  // ---------- small DOM helpers ----------
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
  const c = (s) => h("code", null, s);
  const b = (s) => h("b", null, s);
  const help = (...parts) => h("div", { class: "help" }, ...parts);
  const errorSlot = (loc) => h("div", { class: "error", dataset: { errorFor: loc } });

  // ---------- draft model <-> config ----------
  function fromConfig(cfg) {
    const draft = structuredClone(cfg);
    draft.providers = cfg.providers.map((p) => ({
      ...p,
      api_key_env: p.api_key_env ?? "",
      headers: Object.entries(p.headers || {}).map(([name, value]) => ({ name, value })),
    }));
    draft.routes = Object.entries(cfg.routes || {}).map(([alias, r]) => ({ alias, provider: r.provider, model: r.model ?? "" }));
    draft.default_route = cfg.default_route
      ? { provider: cfg.default_route.provider, model: cfg.default_route.model ?? "" }
      : { provider: "", model: "" };
    draft.security = { ...cfg.security, provider: cfg.security.provider ?? "", model: cfg.security.model ?? "" };
    return draft;
  }

  function toConfig(draft) {
    const cfg = structuredClone(draft);
    cfg.providers = draft.providers.map((p) => ({
      name: p.name.trim(),
      base_url: p.base_url.trim(),
      api_key_env: p.api_key_env.trim() || null,
      format: p.format,
      headers: Object.fromEntries(p.headers.filter((x) => x.name.trim() || x.value).map((x) => [x.name.trim(), x.value])),
    }));
    cfg.routes = Object.fromEntries(draft.routes.map((r) => [r.alias.trim(), { provider: r.provider, model: r.model.trim() || null }]));
    cfg.default_route = draft.default_route.provider
      ? { provider: draft.default_route.provider, model: draft.default_route.model.trim() || null }
      : null;
    cfg.security = { ...draft.security, provider: draft.security.provider || null, model: draft.security.model.trim() || null };
    cfg.headers = {
      ...draft.headers,
      blocklist: draft.headers.blocklist.map((s) => s.trim()).filter(Boolean),
      allowlist: draft.headers.allowlist.map((s) => s.trim()).filter(Boolean),
    };
    cfg.detectors = {
      ...draft.detectors,
      custom_values: draft.detectors.custom_values.filter((v) => v.type.trim() || v.value).map((v) => ({ type: v.type.trim(), value: v.value })),
    };
    return cfg;
  }

  const isDirty = () => !!ui && JSON.stringify(toConfig(ui)) !== JSON.stringify(toConfig(fromConfig(saved)));
  const providerNames = () => ui.providers.map((p) => p.name).filter((n) => n.trim());

  // ---------- bound controls ----------
  // Each control writes straight into the draft; structural changes call render().
  function input(obj, key, { type = "text", placeholder, onchange, disabled, min, step } = {}) {
    return h("input", {
      type, placeholder, disabled, min, step, id: "f" + ++uid, value: obj[key] ?? "",
      spellcheck: false, autocomplete: "off",
      oninput: (e) => {
        obj[key] = type === "number" ? (e.target.value === "" ? "" : Number(e.target.value)) : e.target.value;
        edited(e.target);
      },
      onchange,
    });
  }

  function checkbox(obj, key, label, { rerender = false } = {}) {
    return h("label", { class: "check" },
      h("input", { type: "checkbox", checked: !!obj[key], onchange: (e) => { obj[key] = e.target.checked; edited(e.target); if (rerender) renderKeepingFocus(); } }),
      label);
  }

  function radios(obj, key, options) {
    const name = "r" + ++uid;
    return h("div", { class: "radio" }, options.map((o) =>
      h("label", null,
        h("input", { type: "radio", name, value: o.value, checked: obj[key] === o.value, onchange: (e) => { obj[key] = o.value; edited(e.target); renderKeepingFocus(); } }),
        h("span", null, b(o.label), o.desc ? h("span", { class: "help" }, " — ", o.desc) : null))));
  }

  function providerSelect(obj, key, { allowNone = false, noneLabel = "(none)" } = {}) {
    const names = providerNames();
    const current = obj[key] || "";
    const options = [];
    if (allowNone || !current) options.push(h("option", { value: "", selected: current === "" }, allowNone ? noneLabel : "Choose a provider…"));
    for (const name of names) options.push(h("option", { value: name, selected: name === current }, name));
    if (current && !names.includes(current)) options.push(h("option", { value: current, selected: true }, `${current} (missing)`));
    return h("select", { id: "f" + ++uid, onchange: (e) => { obj[key] = e.target.value; edited(e.target); renderKeepingFocus(); } }, options);
  }

  // A list of strings edited as rows (header block/allow lists).
  function stringList(list, { placeholder, disabled } = {}) {
    return h("div", { class: "rows" },
      list.map((value, i) => h("div", { class: "row" },
        input(list, i, { placeholder, disabled }),
        h("button", { class: "small danger", disabled, title: "Remove", onclick: () => { list.splice(i, 1); edited(); render(); } }, "Remove"))),
      h("div", null, h("button", { class: "small", disabled, onclick: () => { list.push(""); edited(); render(); focusLast(); } }, "+ Add entry")));
  }

  function field(label, loc, control, ...helpParts) {
    const forId = control instanceof HTMLElement && control.matches("input,select,textarea") ? control.id : null;
    return h("div", { class: "field", dataset: { loc } },
      h("label", { htmlFor: forId }, label),
      h("div", { class: "control" }, control, helpParts.length ? help(...helpParts) : null, errorSlot(loc)));
  }

  function section(id, title, intro, ...content) {
    return h("section", { id: "cfg-" + id, dataset: { section: id } },
      h("h2", null, title), h("p", null, intro), errorSlot(id), ...content);
  }

  // After "+ Add …", focus the new (last) text box in the same section.
  function focusLast() {
    const sectionId = document.activeElement?.closest("section")?.id;
    requestAnimationFrame(() => {
      const scope = (sectionId && document.getElementById(sectionId)) || form;
      const inputs = scope.querySelectorAll("input[type=text]:not([readonly]):not([disabled])");
      inputs[inputs.length - 1]?.focus();
    });
  }

  // ---------- sections ----------
  function providersSection() {
    const cards = ui.providers.map((p, i) => {
      const loc = `providers.${i}`;
      let oldName = p.name;
      return h("div", { class: "card" },
        h("div", { class: "card-head" },
          h("strong", null, p.name || "(unnamed provider)"),
          h("button", { class: "small danger", onclick: () => removeProvider(i) }, "Remove provider")),
        errorSlot(loc),
        field("Name", `${loc}.name`, input(p, "name", {
          placeholder: "openrouter",
          // Re-render (to refresh provider dropdowns) only after focus has settled elsewhere,
          // and keep focus on whatever the user moved to.
          onchange: () => { renameProvider(oldName, p.name); oldName = p.name; renderKeepingFocus(); },
        }), "Unique label used by the routes and the security model to refer to this provider. Never sent upstream. Renaming it here also updates every route that uses it."),
        field("Base URL", `${loc}.base_url`, input(p, "base_url", { placeholder: "https://openrouter.ai/api" }),
          "Root URL of the provider's API. A trailing ", c("/v1"), " is optional; MasqAI never adds it twice. Examples: ",
          c("https://openrouter.ai/api"), ", ", c("https://api.anthropic.com"), ", ", c("https://api.openai.com"), ", ", c("http://127.0.0.1:11434"), " (Ollama)."),
        field("Authentication style", `${loc}.format`, radios(p, "format", [
          { value: "openai", label: "OpenAI", desc: "key sent as Authorization: Bearer <key>" },
          { value: "anthropic", label: "Anthropic", desc: "key sent as x-api-key, plus anthropic-version: 2023-06-01 if the agent did not send one" },
        ]), "Only selects how the key is attached. Request bodies are forwarded in whatever API format the agent used and are ", b("never converted"),
          ", so the provider must support that format (e.g. Anthropic Messages for Claude Code)."),
        field("API key variable", `${loc}.api_key_env`, envSelect(p),
          "The ", b("name"), " of an environment variable that holds the key, never the key itself. Only names referenced in ", c("masqai.json"),
          " at startup can be chosen (they are frozen when the gateway starts); to use another variable, add it to the file and restart. Choose (none) for providers that need no key, such as local Ollama.",
          envNote(p.api_key_env.trim())),
        field("Extra headers", `${loc}.headers`, h("div", { class: "rows" },
          p.headers.map((hd, j) => h("div", { class: "row" },
            input(hd, "name", { placeholder: "HTTP-Referer" }),
            input(hd, "value", { placeholder: "https://example.com" }),
            h("button", { class: "small danger", onclick: () => { p.headers.splice(j, 1); edited(); render(); } }, "Remove"))),
          h("div", null, h("button", { class: "small", onclick: () => { p.headers.push({ name: "", value: "" }); edited(); render(); focusLast(); } }, "+ Add header"))),
          "Static headers added to every request sent to this provider, after the agent's headers (they win on a name clash). Example: ", c("HTTP-Referer"), " and ", c("X-Title"),
          " for OpenRouter app attribution. Credential headers (", c("Authorization"), ", ", c("x-api-key"), ", ", c("api-key"), ", …) are refused; use the key variable above."));
    });
    return section("providers", "Providers",
      "Upstream APIs the gateway can send requests to. Both the agent's model routes and the security model point at one of these.",
      cards.length ? cards : h("div", { class: "card muted" }, "No providers yet. Requests cannot be routed until you add one."),
      h("button", {
        onclick: () => {
          let n = ui.providers.length + 1;
          while (providerNames().includes(`provider-${n}`)) n++;
          ui.providers.push({ name: `provider-${n}`, base_url: "", format: "openai", api_key_env: "", headers: [] });
          edited(); render();
        },
      }, "+ Add provider"));
  }

  function routingSection() {
    const rows = ui.routes.map((r, i) => {
      const loc = `routes.${r.alias.trim()}`;
      return h("div", { class: "card" },
        h("div", { class: "row" },
          h("input", { type: "text", placeholder: "alias the agent sends, e.g. claude-sonnet", value: r.alias, spellcheck: false, oninput: (e) => { r.alias = e.target.value; edited(e.target); } }),
          providerSelect(r, "provider"),
          h("input", { type: "text", placeholder: "upstream model (blank = same as alias)", value: r.model, spellcheck: false, oninput: (e) => { r.model = e.target.value; edited(e.target); } }),
          h("button", { class: "small danger", onclick: () => { ui.routes.splice(i, 1); edited(); render(); } }, "Remove")),
        errorSlot(loc), errorSlot(`${loc}.provider`), errorSlot(`${loc}.model`), errorSlot(`routes.row.${i}`));
    });
    return section("routing", "Model routing",
      "Decides which provider receives a request, based on the model name the agent asks for.",
      h("div", { class: "card" },
        field("Default route", "default_route", h("div", { class: "row" },
          providerSelect(ui.default_route, "provider", { allowNone: true, noneLabel: "(none: reject unlisted models)" }),
          input(ui.default_route, "model", { placeholder: "upstream model (blank = keep the agent's model name)", disabled: !ui.default_route.provider })),
          "Used when the agent asks for a model name that is not in the alias table below, and for any other ", c("/v1/…"),
          " call such as ", c("/v1/models"), ". Leave the model blank to forward the agent's model name unchanged (typical for OpenRouter). With no default route, unlisted model names are rejected with an error.",
          errorSlot("default_route.provider"))),
      h("div", { class: "card" },
        h("div", { class: "card-head" }, h("strong", null, "Model aliases")),
        help(b("Alias"), " is the exact model name your agent sends (e.g. the model ID configured in OpenCode). Matching requests go to the chosen ", b("provider"),
          " with the model renamed to ", b("upstream model"), "; leave it blank to keep the alias. Exact, case-sensitive match."),
        errorSlot("routes"),
        rows.length ? rows : h("p", { class: "muted" }, "No aliases. Every request uses the default route."),
        h("button", { onclick: () => { ui.routes.push({ alias: "", provider: providerNames()[0] || "", model: "" }); edited(); render(); focusLast(); } }, "+ Add alias")));
  }

  function envSelect(p) {
    const names = meta.env_names || [];
    const current = p.api_key_env || "";
    const options = [h("option", { value: "", selected: current === "" }, "(none)")];
    for (const name of names) options.push(h("option", { value: name, selected: name === current }, name));
    if (current && !names.includes(current)) options.push(h("option", { value: current, selected: true }, `${current} (not allowed: not in masqai.json at startup)`));
    return h("select", { id: "f" + ++uid, onchange: (e) => { p.api_key_env = e.target.value; edited(e.target); renderKeepingFocus(); } }, options);
  }

  function securitySection() {
    const s = ui.security;
    const provider = ui.providers.find((p) => p.name === s.provider);
    const notes = [];
    if (s.enabled && (!s.provider || !s.model.trim()))
      notes.push(h("div", { class: "warn" }, "The security model is on but has no provider or model: every proxied request will fail with a 502 until both are set."));
    let host = null;
    try { host = provider ? new URL(provider.base_url).hostname : null; } catch { host = null; }
    const loopback = host && (host === "localhost" || host === "::1" || host === "[::1]" || /^127\./.test(host));
    if (provider && host && !loopback) {
      notes.push(h("div", { class: "warn" }, `Raw context and the full mapping table (real values of every placeholder) would be sent to ${host}.`,
        !s.allow_remote_security_model ? " Remote security models are not allowed below, so these calls are refused and requests fail closed." : ""));
    }
    if (provider && provider.format !== s.api_format)
      notes.push(h("div", { class: "help" }, `Note: provider "${provider.name}" uses ${provider.format} authentication, but the security call uses the API format chosen here (${s.api_format}) for both its endpoint and its key header.`));
    const remote = field("Allow remote security model", "security.allow_remote_security_model",
      checkbox(s, "allow_remote_security_model", "Allow a security provider that is not on this machine", { rerender: true }),
      "Off by default. The security model sees ", b("raw"), " context and the mapping table. When unchecked, a security provider whose base URL is not literally loopback (",
      c("127.0.0.0/8"), ", ", c("::1"), ", ", c("localhost"), "; no DNS lookup) is refused before anything is sent, and requests fail closed.");
    return section("security", "Security model",
      "The trusted model that inspects context inline, after the deterministic detectors and before anything reaches the untrusted model. It masks secrets the rules missed, vetoes wrong automatic masks, links partial forms, and hides or replaces intel in tool results.",
      h("div", { class: "card" },
        field("Enabled", "security.enabled", checkbox(s, "enabled", "Inspect requests with the security model", { rerender: true }),
          "When on, a request waits for the security model before it is forwarded. Each operation it returns is checked on its own; rejected ones are sent back once for correction. If the model fails, times out, or a correction is still invalid, the request is ",
          b("blocked"), " (fail closed, HTTP 502). When off, only the detectors below run: a deterministic baseline."),
        notes.length ? h("div", { class: "rows" }, notes) : null,
        field("Provider", "security.provider", providerSelect(s, "provider", { allowNone: true }),
          "Which provider hosts the security model. Its base URL, key variable and extra headers are used. A local model (e.g. Ollama) keeps raw data on this machine."),
        field("Model", "security.model", input(s, "model", { placeholder: "qwen2.5:7b" }),
          "Model ID at that provider. It must reliably return JSON and copy text exactly; an operation whose text is not at the line it names is rejected."),
        field("API format", "security.api_format", radios(s, "api_format", [
          { value: "openai", label: "OpenAI Chat Completions", desc: "POST /v1/chat/completions with JSON mode; Ollama, vLLM, OpenRouter, OpenAI" },
          { value: "anthropic", label: "Anthropic Messages", desc: "POST /v1/messages with x-api-key" },
        ]), "The API the security call uses, independent of what your agent uses. It decides both the endpoint and how the provider's key is attached. Most local servers only offer the OpenAI format."),
        field("Timeout (seconds)", "security.timeout_s", input(s, "timeout_s", { type: "number", min: 1, step: 1 }),
          "Maximum wait for one security call. Exceeding it blocks the request (fail closed). Local models on CPU can need 30 to 120 seconds for long contexts."),
        field("Context window (tokens)", "security.context_tokens", input(s, "context_tokens", { type: "number", min: 0, step: 1 }),
          "The security model's context size (Ollama's default is 4096). A reply that fills it may have lost its instructions to truncation, so the request is blocked (fail closed). ", c("0"), " turns the check off."),
        field("Context mode", "security.context_mode", radios(s, "context_mode", [
          { value: "recent", label: "Recent", desc: "use the three limits below; fast, fits small models" },
          { value: "full", label: "Full", desc: "the same input with every limit removed: all earlier operations, whole items around them, all tool context; most thorough, slowest, can exceed a small model's context window and then fail closed" },
        ]), "Either way the model inspects only items it has not inspected before, sees every user and assistant message for the task intent, and values it finds are masked across the whole history."),
        field("Earlier operations (N)", "security.nearest_ops", input(s, "nearest_ops", { type: "number", min: -1, step: 1, disabled: s.context_mode !== "recent" }),
          "How many of the model's earlier operations (masks, hides, replaces) to show it, nearest to the new items first. ", c("-1"), " shows all. They let it keep placeholders consistent and mark partial forms of known values. Ignored in Full mode."),
        field("Lines around each (k)", "security.op_context_lines", input(s, "op_context_lines", { type: "number", min: 0, step: 1, disabled: s.context_mode !== "recent" }),
          "Raw lines shown above and below each earlier operation. Ignored in Full mode (whole items)."),
        field("Recent tool context", "security.recent_items", input(s, "recent_items", { type: "number", min: 0, step: 1, disabled: s.context_mode !== "recent" }),
          "How many of the latest tool calls, tool results and reasoning items are shown read-only, for the current sub-task. User and assistant messages are always all shown. Ignored in Full mode."),
        field("Exact copies of known values", "security.auto_mask", radios(s, "auto_mask", [
          { value: "auto", label: "Mask automatically", desc: "every exact copy of a known value is masked unless it sits inside a longer word (ANDY in HANDY stays)" },
          { value: "auto_veto", label: "Mask automatically, model may veto", desc: "the same, and the security model may keep one automatic copy as-is with an unmask operation (e.g. a project name that is also an ordinary word). A wrong veto leaks that copy; each one is shown on the Security page." },
        ]), "Partial or changed forms (", c("<$…>"), ") are never copied automatically: the model marks each occurrence."),
        field("Rejected tool calls", "security.tool_rejection", radios(s, "tool_rejection", [
          { value: "rewrite", label: "Rewrite and continue", desc: "the call is kept, but its arguments become a harmless echo of \"MasqAI: the user's security profile rejected this execution\". The untrusted model reads that as the tool result and the session goes on." },
          { value: "error", label: "Reject with an error", desc: "the call is wiped and the agent gets HTTP 400 masqai_tool_rejected (or an error event that ends the stream, if text was already sent)." },
        ]), "Applies to tool calls carrying placeholders that the security model judges to send a secret off the machine."),
        field("Instructions", "security.system_prompt", h("div", { class: "rows" },
          h("textarea", { id: "f" + ++uid, value: s.system_prompt, spellcheck: false, placeholder: "(blank: use the built-in instructions)", oninput: (e) => { s.system_prompt = e.target.value; edited(e.target); } }),
          h("div", { class: "row" },
            h("button", { class: "small", onclick: () => { s.system_prompt = meta.default_security_prompt || ""; edited(); render(); } }, "Load built-in instructions to edit"),
            h("button", { class: "small", onclick: () => { s.system_prompt = ""; edited(); render(); } }, "Clear (use built-in)"))),
          "Sets the security model's sensitivity. Leave blank to use the built-in one (", c("masqai/prompts/security.md"), "). A custom prompt must keep the JSON contract (",
          c('{"operations": [...]}'), " with ", c("mask"), ", ", c("hide"), ", ", c("replace"), ", ", c("relink"), " and, if enabled, ", c("unmask"),
          "). A prompt written for the prototype (", c("collapse"), ") is rejected when applied, instead of failing every request."),
        remote));
  }

  function detectorsSection() {
    const d = ui.detectors;
    const matching = "";
    return section("detectors", "Detectors",
      "Deterministic masking that runs on every request, with or without the security model. Found values are replaced by placeholders such as <EMAIL_3fa9c2d1> (not inside longer words: ANDY in HANDY stays), and tool calls coming back are restored to the real values.",
      h("div", { class: "card" },
        field("Rules", "detectors.rules_dir", h("div", { class: "rows" },
          input(d, "rules_dir", { placeholder: "masqai/rules" }),
          h("div", { class: "chips" }, (meta.detector_rules || []).map((p) => h("span", { class: "chip" }, p)))),
          "Detector rules are data: ", c("*.toml"), " tables in this folder (patterns, and a dictionary of secret-like key names whose ", b("values"),
          " are masked). Detectors only ever mask; they are fast and can't be prompt-injected. The chips are the rules loaded now."),
        field("This machine", "detectors.detect_host_identifiers",
          h("div", { class: "rows" },
            checkbox(d, "detect_host_identifiers", "Mask this machine's host name, user name and home directory", { rerender: true }),
            h("div", { class: "chips" }, (meta.host_identifiers || []).map((v) => h("span", { class: "chip", title: v.type }, `${v.type}: ${v.value}`)))),
          "Agents put the working directory and platform into their prompts and tool output. These values are read from the gateway's own environment and shown here only to you."),
        field("Custom values", "detectors.custom_values", h("div", { class: "rows" },
          d.custom_values.map((v, i) => h("div", null,
            h("div", { class: "row" },
              input(v, "type", { placeholder: "TYPE, e.g. CLIENT" }),
              input(v, "value", { placeholder: "exact text, e.g. Hollowbrook Capital" }),
              h("button", { class: "small danger", onclick: () => { d.custom_values.splice(i, 1); edited(); render(); } }, "Remove")),
            errorSlot(`detectors.custom_values.${i}.type`), errorSlot(`detectors.custom_values.${i}.value`))),
          h("div", null, h("button", { class: "small", onclick: () => { d.custom_values.push({ type: "CUSTOM", value: "" }); edited(); render(); focusLast(); } }, "+ Add value"))),
          "Literal values to always mask: client names, internal host names, project code names. ", b("Type"), " becomes the placeholder prefix (letters, digits, underscores; ",
          c("CLIENT"), " gives ", c("<CLIENT_3fa9c2d1>"), "). ", b("Value"), " must be at least 3 characters. Exact copies are masked wherever they appear, except inside a longer word.", matching)));
  }

  function headersSection() {
    const policy = ui.headers;
    const block = policy.mode === "blocklist";
    const resetButton = (key, defaults) => h("button", { class: "small", onclick: () => { policy[key] = [...defaults]; edited(); render(); } }, "Reset to defaults");
    return section("headers", "Request headers",
      "Which of the agent's HTTP headers are passed on to the provider.",
      h("div", { class: "card" },
        field("User-Agent", "headers.user_agent", input(policy, "user_agent", { placeholder: "masqai/0.2.0" }),
          "Replaces the client's User-Agent, which names the agent, its version and often the OS. Leave empty to forward the client's own."),
        field("Mode", "headers.mode", radios(policy, "mode", [
          { value: "blocklist", label: "Blocklist (default)", desc: "forward every header except the ones listed; most transparent" },
          { value: "allowlist", label: "Allowlist", desc: "forward only the headers listed; hides client-identifying headers such as custom app tags" },
        ]), "Only one list is active at a time; the other is kept so you can switch back. The provider's key and its extra headers are added after this filter in both modes."),
        field("Always removed", "headers.always", h("div", { class: "chips" }, (meta.always_dropped_headers || []).map((x) => h("span", { class: "chip" }, x))),
          "Dropped in both modes and cannot be changed: the agent's own credentials (MasqAI adds the provider's key itself) and connection-level headers that must be recomputed. Headers named in the request's ",
          c("Connection"), " header are dropped too."),
        field(block ? "Blocklist" : "Blocklist (inactive)", "headers.blocklist",
          h("div", { class: "rows" }, stringList(policy.blocklist, { placeholder: "header name, e.g. cookie or x-internal-*", disabled: !block }), h("div", null, resetButton("blocklist", meta.default_blocklist || []))),
          "Used in Blocklist mode. Case-insensitive; a trailing ", c("*"), " matches a prefix (", c("x-forwarded-*"), "). The defaults remove other providers' key headers, cookies, client fingerprints (",
          c("x-stainless-os"), ", ", c("-arch"), ", ", c("-runtime"), ", …), client session ids, proxy and referer headers. ", c("user"), ", ", c("metadata.user_id"), ", ",
          c("safety_identifier"), " and ", c("prompt_cache_key"), " are always replaced with a per-session pseudonym."),
        field(block ? "Allowlist (inactive)" : "Allowlist", "headers.allowlist",
          h("div", { class: "rows" }, stringList(policy.allowlist, { placeholder: "header name, e.g. user-agent or x-stainless-*", disabled: block }), h("div", null, resetButton("allowlist", meta.default_allowlist || []))),
          "Used in Allowlist mode. Same matching rules. Keep ", c("content-type"), ", ", c("accept"), " and any ", c("anthropic-beta"), "/", c("openai-beta"),
          " headers your agent relies on, or provider features may stop working.")));
  }

  function sessionsSection() {
    return section("sessions", "Sessions",
      "Sessions, their raw content and mapping tables live only in RAM; nothing is written to disk. These limits bound memory use and how long raw context is kept.",
      h("div", { class: "card" },
        field("Maximum sessions", "retention.max_sessions", input(ui.retention, "max_sessions", { type: "number", min: 1, step: 1 }),
          "Past this, the least recently used session is forgotten. A session with a request in flight or an open stream is never evicted; the next-oldest goes instead."),
        field("Forget after idle (hours)", "retention.idle_ttl_h", input(ui.retention, "idle_ttl_h", { type: "number", min: 0.1, step: 1 }),
          "Sessions without a request for this long are forgotten. Checked every 60 s, after each request and after a config change.")));
  }

  function gatewaySection() {
    return section("gateway", "Gateway",
      "The local endpoint your agent talks to.",
      h("div", { class: "card" },
        field("Listening on", "port", h("input", { type: "text", value: meta.listen || `http://${ui.host}:${ui.port}`, readOnly: true }),
          "Fixed at startup. To change the port, edit ", c("port"), " in ", c("masqai.json"), " and restart. The host is always ", c("127.0.0.1"),
          ". The control API needs the admin token printed at startup; the agent endpoints don't. Point OpenAI-style agents at ", c((meta.listen || "") + "/v1"), " and Anthropic-style agents at ", c(meta.listen || ""), "."),
        field("Unknown content", "pass_unknown", checkbox(ui, "pass_unknown", "Forward content MasqAI can't inspect (images in OpenAI format, files, audio, …) raw"),
          b("Off by default"), ": such requests are refused with HTTP 422 before a session exists, saying where the content was and its type, never the content. When on, it is forwarded raw with a warning on the Security page."),
        field("Upstream timeout (seconds)", "upstream_timeout_seconds", input(ui, "upstream_timeout_seconds", { type: "number", min: 1, step: 1 }),
          "Applies to each upstream request: the longest wait to connect, or between two chunks of a response. Long streaming answers are fine as long as data keeps arriving.")));
  }

  // ---------- render ----------
  const SECTIONS = [
    ["providers", "Providers"], ["routing", "Model routing"], ["security", "Security model"],
    ["detectors", "Detectors"], ["headers", "Request headers"], ["sessions", "Sessions"], ["gateway", "Gateway"],
  ];
  const sectionOf = (loc) => ({
    providers: "providers", routes: "routing", default_route: "routing", security: "security",
    detectors: "detectors", headers: "headers", retention: "sessions",
  })[loc[0]] || "gateway";

  function render() {
    if (!ui) return;
    const scroll = window.scrollY;
    form.replaceChildren(providersSection(), routingSection(), securitySection(), detectorsSection(), headersSection(), sessionsSection(), gatewaySection());
    const unplaced = errors.filter((e) => !placeError(e));
    const counts = {};
    for (const e of errors) counts[sectionOf(e.loc)] = (counts[sectionOf(e.loc)] || 0) + 1;
    nav.replaceChildren(h("strong", null, "Settings"), ...SECTIONS
      .filter(([id]) => form.querySelector(`#cfg-${id}`))
      .map(([id, title]) => h("a", { href: `#cfg-${id}`, onclick: (e) => { e.preventDefault(); document.getElementById(`cfg-${id}`).scrollIntoView({ behavior: "smooth" }); } },
        title, counts[id] ? h("span", { class: "count" }, `${counts[id]} error${counts[id] > 1 ? "s" : ""}`) : null)));
    updateState(unplaced);
    window.scrollTo(0, scroll);
  }

  // Put an error under the most specific field that exists for its location.
  function placeError(error) {
    for (let n = error.loc.length; n >= 1; n--) {
      const key = error.loc.slice(0, n).join(".");
      const slots = form.querySelectorAll(`[data-error-for="${CSS.escape(key)}"]`);
      if (slots.length) {
        for (const slot of slots) {
          slot.textContent = slot.textContent ? `${slot.textContent}; ${error.msg}` : error.msg;
          slot.closest(".field")?.classList.add("invalid");
        }
        return true;
      }
    }
    return false;
  }

  function updateState(unplaced = []) {
    const dirty = isDirty();
    applyButton.disabled = !dirty;
    document.getElementById("revertConfig").disabled = !dirty;
    if (errors.length) {
      saveState.className = "grow bad";
      saveState.textContent = `Not applied: ${errors.length} problem${errors.length > 1 ? "s" : ""} marked in red.` + (unplaced.length ? " " + unplaced.map((e) => e.msg).join("; ") : "");
    } else if (dirty) {
      saveState.className = "grow dirty";
      saveState.textContent = "Unsaved changes. Apply to use them; they last until the gateway restarts.";
    } else {
      saveState.className = "grow";
      saveState.textContent = notice || "No changes. The running gateway uses the configuration shown.";
    }
  }

  function edited(target) {
    notice = "";
    const fieldEl = target?.closest?.(".field");
    if (fieldEl?.classList.contains("invalid")) {
      fieldEl.classList.remove("invalid");
      fieldEl.querySelectorAll(".error").forEach((slot) => (slot.textContent = ""));
    }
    updateState();
  }

  // ---------- actions ----------
  function references(name) {
    const refs = ui.routes.filter((r) => r.provider === name).map((r) => `alias "${r.alias || "(blank)"}"`);
    if (ui.default_route.provider === name) refs.push("the default route");
    if (ui.security.provider === name) refs.push("the security model");
    return refs;
  }

  function renameProvider(from, to) {
    if (!from || from === to) return;
    for (const r of ui.routes) if (r.provider === from) r.provider = to;
    if (ui.default_route.provider === from) ui.default_route.provider = to;
    if (ui.security.provider === from) ui.security.provider = to;
  }

  function removeProvider(index) {
    const name = ui.providers[index].name;
    const refs = references(name);
    if (refs.length && !confirm(`"${name}" is used by ${refs.join(", ")}. Remove it anyway? Those settings will need another provider before you can apply.`)) return;
    ui.providers.splice(index, 1);
    edited(); render();
  }

  async function checkEnv(name) {
    envStatus.set(name, undefined);
    try {
      const response = await UI.api(`/api/env/${encodeURIComponent(name)}`);
      envStatus.set(name, response.ok ? (await response.json()).set : false);
    } catch {
      envStatus.delete(name);
    }
    // Update notes in place: a full render here would steal focus from whatever is being edited.
    form.querySelectorAll(`[data-env-note="${CSS.escape(name)}"]`).forEach((note) => note.replaceWith(envNote(name)));
  }

  // Status line under an "API key variable" field. Only syntactically valid names are looked up,
  // so a key pasted by mistake is never sent to the server, even in a URL.
  const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
  function envNote(name) {
    if (!name) return h("div", { class: "help", dataset: { envNote: "" } });
    if (!ENV_NAME.test(name))
      return h("div", { class: "warn", dataset: { envNote: name } },
        /^(sk-|gh[pousr]_|xox|AIza|eyJ)/.test(name) || name.length > 40
          ? "This looks like a key value. Enter the NAME of the environment variable that holds it instead, and do not save this config."
          : "Variable names use only letters, digits and _ and do not start with a digit.");
    if (!envStatus.has(name)) checkEnv(name);
    const status = envStatus.get(name);
    return h("div", { class: status === true ? "ok" : status === false ? "warn" : "help", dataset: { envNote: name } },
      status === true ? `${name} is set in the gateway's environment.`
        : status === false ? `${name} is not set in the gateway's environment. Requests to this provider go out without a key (the provider will reject them), and security-model calls through it fail closed.`
          : `Checking ${name}…`);
  }

  function updateEnvNote(inputEl, name) {
    inputEl.closest(".control").querySelector("[data-env-note]")?.replaceWith(envNote(name));
  }

  // Re-render after a change event without losing the field the user just moved to.
  function renderKeepingFocus() {
    setTimeout(() => {
      const active = document.activeElement;
      const key = active && form.contains(active) ? [...form.querySelectorAll("input,select,textarea,button")].indexOf(active) : -1;
      const caret = active && "selectionStart" in active ? active.selectionStart : null;
      render();
      if (key >= 0) {
        const target = form.querySelectorAll("input,select,textarea,button")[key];
        target?.focus();
        if (caret !== null && target && "setSelectionRange" in target) try { target.setSelectionRange(caret, caret); } catch { /* not a text input */ }
      }
    });
  }

  function clientErrors() {
    const out = [];
    const seen = new Map();
    ui.routes.forEach((r, i) => {
      const alias = r.alias.trim();
      if (!alias) out.push({ loc: ["routes", "row", i], msg: "alias must not be empty" });
      else if (seen.has(alias)) out.push({ loc: ["routes", alias], msg: `alias "${alias}" is listed twice` });
      seen.set(alias, i);
      if (!r.provider) out.push({ loc: ["routes", "row", i], msg: "choose a provider" });
    });
    ui.providers.forEach((p, i) => {
      const names = p.headers.map((x) => x.name.trim().toLowerCase()).filter(Boolean);
      if (new Set(names).size !== names.length) out.push({ loc: ["providers", i, "headers"], msg: "a header name is listed twice" });
    });
    return out;
  }

  async function apply() {
    errors = clientErrors();
    if (errors.length) { render(); return; }
    applyButton.disabled = true;
    saveState.textContent = "Applying…";
    try {
      const response = await UI.api("/api/config", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(toConfig(ui)) });
      const body = await response.json();
      if (!response.ok) {
        errors = body.errors || [{ loc: [], msg: body.error || `HTTP ${response.status}` }];
      } else {
        saved = body; ui = fromConfig(saved); errors = [];
        notice = "Applied in memory. Use Export JSON to keep these settings after a restart.";
      }
    } catch (exc) {
      errors = [{ loc: [], msg: `Could not reach the gateway: ${exc.message}` }];
    }
    render();
  }

  function exportDialog() {
    const dialog = document.getElementById("exportDialog");
    const textArea = document.getElementById("exportText");
    textArea.value = JSON.stringify(toConfig(fromConfig(saved)), null, 2) + "\n";
    const note = dialog.querySelector(".pending");
    if (note) note.remove();
    if (isDirty()) textArea.before(h("p", { class: "warn pending" }, "You have unapplied changes. This export contains the configuration currently running; apply first to include your edits."));
    dialog.showModal();
  }

  async function load() {
    const [configResponse, metaResponse] = await Promise.all([UI.api("/api/config"), UI.api("/api/config/meta")]);
    saved = await configResponse.json();
    meta = await metaResponse.json();
    meta.features ||= {};
    ui = fromConfig(saved);
    errors = [];
    render();
  }

  applyButton.onclick = apply;
  document.getElementById("revertConfig").onclick = () => { ui = fromConfig(saved); errors = []; notice = "Changes discarded."; render(); };
  document.getElementById("exportConfig").onclick = exportDialog;
  document.getElementById("closeExport").onclick = () => document.getElementById("exportDialog").close();
  document.getElementById("copyExport").onclick = async () => {
    await navigator.clipboard.writeText(document.getElementById("exportText").value);
    document.getElementById("copyExport").textContent = "Copied";
    setTimeout(() => (document.getElementById("copyExport").textContent = "Copy"), 1500);
  };
  document.getElementById("downloadExport").onclick = () => {
    const blob = new Blob([document.getElementById("exportText").value], { type: "application/json" });
    const link = h("a", { href: URL.createObjectURL(blob), download: "masqai.json" });
    link.click();
    URL.revokeObjectURL(link.href);
  };

  return {
    open: () => { if (!ui || !isDirty()) load(); },
    isDirty,
  };
})();
