"use strict";
const $ = id => document.getElementById(id);
const store = {get(k){try{return localStorage.getItem(k)}catch(e){return null}}, set(k,v){try{localStorage.setItem(k,v)}catch(e){}}};
let data = null;           // /api/connectors
let editing = null;        // {type, id, suggestion}

async function api(path, body) {
  const opts = body === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json", "X-Guardian": "1"}, body: JSON.stringify(body)};
  const r = await fetch(path, opts);
  if (r.status === 401) { location.href = "/"; throw new Error("Sign in first"); }
  const out = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(out.detail || `Request failed (${r.status})`);
  return out;
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids) if (k != null && k !== false) e.append(k);
  return e;
}

const ago = t => { if (!t) return "never"; const s = Date.now() / 1000 - t;
  return s < 90 ? "just now" : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : new Date(t * 1000).toLocaleDateString(); };
const runLabel = id => id ? `${id.slice(6,8)}.${id.slice(4,6)}.${id.slice(0,4)} ${id.slice(9,11)}:${id.slice(11,13)}` : "";
const icon = spec => el("span", {class: "ico", style: `background:${spec.color}`}, spec.icon);

// -- sections -----------------------------------------------------------------------
function showSection() {
  const s = (location.hash || "#connectors").slice(1);
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("on", a.dataset.s === s));
  for (const id of ["connectors", "ai", "access", "scope", "schedules"]) $("s-" + id).classList.toggle("hidden", id !== s);
}
window.addEventListener("hashchange", showSection);

// -- connectors -----------------------------------------------------------------------
async function loadConnectors() {
  data = await api("/api/connectors");
  renderSuggestions(); renderConfigured(); renderCatalog();
  const n = data.suggestions.length;
  $("nav-count").textContent = n; $("nav-count").classList.toggle("hidden", !n);
}

function renderSuggestions() {
  const box = $("suggestions"), s = data.suggestions;
  $("scan-note").textContent = data.scan ? `Scan of ${runLabel(data.scan)} · ${data.devices} devices · ${s.length} suggestion${s.length === 1 ? "" : "s"}` : "";
  const fresh = s.filter(x => x.new);
  $("new-callout").replaceChildren(...fresh.map(x => el("div", {class: "callout"}, el("b", {}, "New"),
    el("span", {}, `${x.title.split(" · ")[1] || x.title} (${x.hosts.join(", ")}) appeared since the previous scan. Connect it so Guardian can check it from the inside.`))));
  box.replaceChildren();
  if (!data.scan) { box.append(el("p", {class: "note"}, "Run a scan from the console first: suggestions come from what it finds.")); }
  else if (!s.length) box.append(el("p", {class: "note"}, "Nothing to suggest: every device Guardian can connect to is set up or dismissed."));
  for (const x of s) {
    const spec = data.catalog[x.type];
    box.append(el("div", {class: "conn"},
      el("div", {class: "ctop"}, icon(spec), el("div", {}, el("b", {}, x.title), el("span", {class: "mono meta"}, x.hosts.length > 3 ? `${x.hosts.length} hosts · ${x.hosts.map(h => "." + h.split(".").pop()).join(" ")}` : x.hosts.join(", ")))),
      (x.new || x.findings) ? el("div", {class: "row"}, x.new && el("span", {class: "tag new"}, "new device"),
        x.findings ? el("span", {class: "tag"}, `${x.findings} finding${x.findings > 1 ? "s" : ""}`) : null) : null,
      el("div", {class: "note"}, x.why),
      el("div", {class: "gain"}, "Checks: " + spec.checks),
      el("div", {class: "acts"},
        el("button", {class: "btn primary sm", onclick: () => openDrawer(x.type, null, x)}, "Connect"),
        el("button", {class: "btn ghost sm", onclick: () => dismiss(x.key)}, "Not now"))));
  }
  const parts = [];
  if (data.uncovered) parts.push(`${data.uncovered} other device${data.uncovered === 1 ? " has" : "s have"} no connector (TVs, phones, appliances, the ISP router). They're still covered by the network scan.`);
  $("uncovered").replaceChildren(parts.join(" "), data.dismissed ? el("a", {href: "#connectors", style: "color:var(--accent);margin-left:6px", onclick: e => { e.preventDefault(); restore(); }}, `Show ${data.dismissed} dismissed`) : "");
}

async function dismiss(key) { try { await api("/api/suggestions/dismiss", {key}); await loadConnectors(); } catch (e) { alert(e.message); } }
async function restore() { try { await api("/api/suggestions/restore", {}); await loadConnectors(); } catch (e) { alert(e.message); } }

function target(c) {
  const f = c.fields;
  if (f.hosts) { const h = f.hosts.split(/\s+/).filter(Boolean); return h.length > 2 ? `${h.length} hosts` : h.join(", "); }
  return f.domain && f.host ? `${f.domain} (${f.host})` : f.host || f.url || f.domain || "";
}

function renderConfigured() {
  const box = $("configured");
  if (!data.connectors.length) { box.replaceChildren(el("p", {class: "note"}, "None yet. Start with a suggestion above, or pick one from the list below.")); return; }
  const rows = data.connectors.map(c => {
    const spec = data.catalog[c.type];
    return el("tr", {},
      el("td", {}, el("b", {}, c.name)),
      el("td", {}, spec.label),
      el("td", {class: "mono"}, target(c)),
      el("td", {}, el("span", {class: "stat", title: (c.details || []).join("\n")}, el("span", {class: `sd ${c.status}`}), c.message)),
      el("td", {class: "meta"}, ago(c.last_check)),
      el("td", {}, el("div", {class: "row"},
        el("button", {class: "btn sm", onclick: () => recheck(c.id)}, "Re-check"),
        el("button", {class: "btn sm", onclick: () => openDrawer(c.type, c)}, "Edit"))));
  });
  box.replaceChildren(el("div", {class: "tablewrap"}, el("table", {class: "ctab"},
    el("thead", {}, el("tr", {}, ...["Name", "Type", "Target", "Status", "Last check", ""].map(h => el("th", {}, h)))),
    el("tbody", {}, ...rows))));
}

async function recheck(id) {
  try { await api(`/api/connectors/${id}/recheck`, {}); await loadConnectors(); } catch (e) { alert(e.message); }
}

function renderCatalog() {
  const q = $("search").value.trim().toLowerCase();
  const groups = {};
  for (const [type, spec] of Object.entries(data.catalog)) {
    if (q && !`${spec.label} ${spec.checks} ${spec.summary}`.toLowerCase().includes(q)) continue;
    (groups[spec.category] = groups[spec.category] || []).push([type, spec]);
  }
  const box = $("catalog");
  box.replaceChildren();
  for (const cat of ["Identity & productivity", "Infrastructure & storage", "Endpoints & network"]) {
    if (!groups[cat]) continue;
    box.append(el("div", {class: "cat"}, cat), el("div", {class: "cgrid"}, ...groups[cat].map(([type, spec]) => {
      const n = data.connectors.filter(c => c.type === type).length;
      const planned = spec.status !== "available";
      return el("div", {class: "conn" + (planned ? " planned" : "")},
        el("div", {class: "ctop"}, icon(spec), el("div", {}, el("b", {}, spec.label), el("span", {class: "meta"}, spec.summary))),
        el("div", {class: "gain"}, spec.checks),
        el("div", {class: "acts"}, planned ? el("span", {class: "tag"}, "Planned")
          : el("button", {class: "btn sm", onclick: () => openDrawer(type)}, n ? "Add another" : "Add"),
          n ? el("span", {class: "tag ok"}, `${n} set up`) : null));
    })));
  }
  if (!box.childElementCount) box.append(el("p", {class: "note"}, "No connector matches that search."));
}
$("search").addEventListener("input", renderCatalog);
$("add-btn").addEventListener("click", () => { $("search").focus(); $("catalog").scrollIntoView({behavior: "smooth"}); });

// -- drawer ---------------------------------------------------------------------------
function fieldInput(fd, value, secretSet) {
  const id = "f-" + fd.name;
  if (fd.kind === "checkbox")
    return el("div", {}, el("label", {class: "check"}, el("input", {type: "checkbox", id, checked: !!value}), el("span", {}, fd.label)),
      fd.help ? el("p", {class: "help"}, fd.help) : null);
  let input;
  if (fd.kind === "textarea") { input = el("textarea", {id, placeholder: fd.placeholder || "", spellcheck: "false"}); input.value = value || ""; }
  else if (fd.kind === "select") { input = el("select", {id}, ...fd.options.map(o => el("option", {value: o}, o))); input.value = value || fd.default; }
  else {
    input = el("input", {id, type: fd.kind === "password" ? "password" : fd.kind === "number" ? "number" : "text", class: fd.mono ? "mono" : null,
      placeholder: fd.kind === "password" ? (secretSet ? "Saved. Leave blank to keep it" : "Stored encrypted, never shown again") : (fd.placeholder || ""),
      autocomplete: fd.kind === "password" ? "new-password" : "off", spellcheck: "false"});
    if (fd.kind !== "password") input.value = value ?? "";
  }
  return el("div", {}, el("label", {for: id}, fd.label), input, fd.help ? el("p", {class: "help"}, fd.help) : null);
}

async function openDrawer(type, existing = null, suggestion = null) {
  const spec = data.catalog[type];
  editing = {type, id: existing ? existing.id : null};
  $("d-tag").replaceChildren(el("span", {class: "tag" + (suggestion && suggestion.new ? " new" : "")},
    existing ? spec.label : suggestion ? (suggestion.new ? "Suggested · new device" : "Suggested") : spec.multi ? "You can add several" : spec.label));
  $("d-title").textContent = existing ? `Edit ${existing.name}` : `Connect ${spec.label}`;
  $("d-checks").textContent = "Checks: " + spec.checks;
  $("d-steps").replaceChildren(...spec.steps.map(s => el("li", {}, s)));
  $("d-key").replaceChildren();
  if (spec.uses_guardian_key) {
    try {
      const k = await api("/api/connectors/ssh-key");
      const box = el("div", {class: "keybox"}, k.public_key);
      $("d-key").append(el("label", {}, "Guardian's public key"), box,
        el("button", {class: "btn sm", type: "button", onclick: async ev => { try { await navigator.clipboard.writeText(k.public_key); ev.target.textContent = "Copied"; } catch (e) { getSelection().selectAllChildren(box); } }}, "Copy key"));
    } catch (e) { $("d-key").append(el("p", {class: "err"}, e.message)); }
  }
  const prefill = existing ? existing.fields : (suggestion ? suggestion.prefill : {});
  $("d-name").value = existing ? existing.name : (prefill.name || "");
  $("d-fields").replaceChildren(...spec.fields.map(fd => fieldInput(fd, prefill[fd.name] ?? fd.default, existing && existing.secrets_set && existing.secrets_set[fd.name])));
  $("d-result").replaceChildren(existing && existing.message ? result({level: existing.status, message: existing.message, details: existing.details}) : "");
  $("d-delete").classList.toggle("hidden", !existing);
  $("drawer").classList.add("on"); $("scrim").classList.add("on");
  $("d-name").focus();
}

function closeDrawer() { $("drawer").classList.remove("on"); $("scrim").classList.remove("on"); editing = null; }
$("d-close").addEventListener("click", closeDrawer);
$("scrim").addEventListener("click", closeDrawer);
document.addEventListener("keydown", e => { if (e.key === "Escape" && editing) closeDrawer(); });

function formBody() {
  const spec = data.catalog[editing.type], fields = {};
  for (const fd of spec.fields) {
    const input = $("f-" + fd.name);
    fields[fd.name] = fd.kind === "checkbox" ? input.checked : input.value;
  }
  return {id: editing.id, type: editing.type, name: $("d-name").value, fields};
}

function result(r) {
  return el("div", {class: `result ${r.level}`}, el("div", {class: "stat"}, el("span", {class: `sd ${r.level}`}), el("b", {}, r.message)),
    r.details && r.details.length ? el("ul", {}, ...r.details.map(d => el("li", {}, d))) : null);
}

function busy(btn, on, text) { btn.disabled = on; if (text) btn.textContent = text; }

$("d-test").addEventListener("click", async () => {
  const b = $("d-test");
  busy(b, true, "Testing…"); $("d-result").replaceChildren();
  try { $("d-result").replaceChildren(result(await api("/api/connectors/test", formBody()))); }
  catch (e) { $("d-result").replaceChildren(result({level: "error", message: e.message})); }
  busy(b, false, "Test connection");
});

$("d-form").addEventListener("submit", async e => {
  e.preventDefault();
  const b = $("d-save");
  busy(b, true, "Testing and saving…");
  try {
    const c = await api("/api/connectors", formBody());
    $("d-result").replaceChildren(result({level: c.status, message: `Saved. ${c.message}`, details: c.details}));
    editing.id = c.id; $("d-delete").classList.remove("hidden");
    await loadConnectors();
  } catch (err) { $("d-result").replaceChildren(result({level: "error", message: err.message})); }
  busy(b, false, "Save connector");
});

$("d-delete").addEventListener("click", async () => {
  if (!editing || !editing.id || !confirm("Remove this connector? Its saved password or token is deleted too.")) return;
  try { await api(`/api/connectors/${editing.id}/delete`, {}); closeDrawer(); await loadConnectors(); } catch (e) { alert(e.message); }
});

// -- AI engine ------------------------------------------------------------------------
function renderConfig(c) {
  $("model").replaceChildren(...Object.entries(c.models).map(([v, t]) => el("option", {value: v}, t)));
  $("effort").replaceChildren(...c.efforts.map(v => el("option", {value: v}, v + (v === "medium" ? " (default)" : ""))));
  $("model").value = c.model; $("effort").value = c.effort;
  $("akey-state").replaceChildren(c.anthropic_key_set ? el("span", {class: "ok"}, "✓ set") : el("span", {class: "c-high"}, "not set"));
  $("nkey-state").replaceChildren(c.nvd_key_set ? el("span", {class: "ok"}, "✓ set") : el("span", {}, "(optional)"));
}
$("ai-form").addEventListener("submit", async e => {
  e.preventDefault(); $("ai-msg").textContent = "";
  try {
    renderConfig(await api("/api/settings", {model: $("model").value, effort: $("effort").value, anthropic_key: $("akey").value, nvd_key: $("nkey").value}));
    $("akey").value = ""; $("nkey").value = ""; $("ai-msg").textContent = "Saved";
  } catch (err) { $("ai-msg").textContent = err.message; }
});

// -- access -----------------------------------------------------------------------------
function renderAccess(on) {
  $("access-state").textContent = on ? "On: the console asks for the access code." : "Off: anyone on your network can use the console.";
  $("access-btn").textContent = on ? "Turn off" : "Turn on";
  $("access-btn").className = on ? "btn" : "btn primary";
  $("access-btn").onclick = async () => {
    if (on && !confirm("Turn sign-in off? Anyone on your network will be able to use the console.")) return;
    try {
      const r = await api("/api/access", {auth: !on});
      renderAccess(r.auth);
      $("access-code").classList.toggle("hidden", !r.code);
      $("access-code").textContent = r.code ? `Access code: ${r.code}  (shown once; it's also in /opt/ai-guardian/console/access-code)` : "";
    } catch (e) { alert(e.message); }
  };
}

// -- theme and start-up -----------------------------------------------------------------
const theme = store.get("guardian-theme");
if (theme) document.documentElement.dataset.theme = theme;
$("theme").addEventListener("click", () => {
  const r = document.documentElement;
  const dark = r.dataset.theme ? r.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  r.dataset.theme = dark ? "light" : "dark"; store.set("guardian-theme", r.dataset.theme);
});

(async () => {
  showSection();
  const s = await api("/api/session");
  if (!s.signed_in) { location.href = "/"; return; }
  renderAccess(s.auth);
  const o = await api("/api/overview");
  renderConfig(o.config);
  await loadConnectors();
})();
