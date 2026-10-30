"use strict";
const $ = id => document.getElementById(id);
let data = null;           // /api/connectors
let editing = null;        // {type, id, suggestion}

async function api(path, body) {
  const opts = body === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json", "X-Guardian": "1"}, body: JSON.stringify(body)};
  const r = await fetch(path, opts);
  if (r.status === 401) { location.replace("/signin"); throw new Error("Sign in first"); }
  const out = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(out.detail || `Request failed (${r.status})`);
  return out;
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "style") {                    // CSSOM: style="" attributes are blocked by the page's CSP
      for (const d of String(v).split(";")) { const i = d.indexOf(":"); if (i > 0) e.style.setProperty(d.slice(0, i).trim(), d.slice(i + 1).trim()); }
    } else e.setAttribute(k, v === true ? "" : v);
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
  let s = (location.hash || "").slice(1);
  if (!SECTIONS.includes(s) || (me && !allowed(s))) s = me && me.role === "viewer" ? "account" : "connectors";
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("on", a.dataset.s === s));
  for (const id of SECTIONS) $("s-" + id).classList.toggle("hidden", id !== s);
  if (s === "users") loadUsers();
  if (s === "security") loadSecurity();
  if (s === "account") loadAccount();
  if (s === "appearance") renderAppearance();
  if (s === "schedules" && typeof Schedule !== "undefined") Schedule.load();
  if (s === "ticketing" && typeof Ticketing !== "undefined") Ticketing.load();
}
const SECTIONS = ["connectors", "users", "security", "account", "ai", "scope", "schedules", "ticketing", "appearance"];
window.addEventListener("hashchange", showSection);

// -- connectors -----------------------------------------------------------------------
async function loadConnectors() {
  if (me.role === "viewer") return;
  data = await api("/api/connectors");
  $("locked-card").classList.toggle("hidden", !data.locked);
  document.querySelectorAll(".unlocked-only").forEach(e => e.classList.toggle("hidden", data.locked));
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
        data.can_edit ? el("button", {class: "btn primary sm", onclick: () => openDrawer(x.type, null, x)}, "Connect") : el("span", {class: "note"}, "An admin can connect this"),
        data.can_edit ? el("button", {class: "btn ghost sm", onclick: () => dismiss(x.key)}, "Not now") : null)));
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
        data.can_edit ? el("button", {class: "btn sm", onclick: () => openDrawer(c.type, c)}, "Edit") : null)));
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
          : data.can_edit ? el("button", {class: "btn sm", onclick: () => openDrawer(type)}, n ? "Add another" : "Add") : null,
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

// -- AI agents ------------------------------------------------------------------------
const AGENT_INFO = {
  discovery: {what: "Identifies device type, vendor, model, OS and firmware; flags devices it can't identify.",
    tools: "Scan data, read-only probes, web pages (GET), web search", always: true},
  network: {what: "Cleartext and legacy protocols, weak SSH, SMB signing, open DNS, UPnP; devices exposing more than their role needs.",
    tools: "Scan data, read-only probes", connector: "With an SNMPv3 or firewall connector: VLANs, firewall rules, switch ports."},
  os: {what: "OS and server-software versions, end-of-life status, known vulnerabilities (CVEs), remote access on endpoints.",
    tools: "Scan data, read-only probes, CVE and end-of-life databases, web search", connector: "With a Linux SSH or Windows connector: installed patches, users, services from the inside."},
  web: {what: "Admin pages over plain HTTP, TLS and certificates, security headers, exposed APIs and default pages.",
    tools: "Web pages (GET/HEAD), TLS inspection, read-only probes, CVE database", connector: "With a NAS or hypervisor connector: the settings behind the login page."},
  firmware: {what: "Installed firmware against the vendor's latest release; end of support; known-exploited firmware CVEs.",
    tools: "Scan data, web pages (GET), CVE database, web search", connector: "With a device connector: exact firmware versions it can't see from outside."},
  wan: {what: "What the internet sees on your public IP, router port forwards and UPnP rules, mapped to the device behind them.",
    tools: "Public-IP data (Shodan InternetDB), CVE database"},
  ad: {what: "Reads the Windows domain: admin accounts and groups, accounts open to Kerberoasting or AS-REP roasting, delegation, password and lockout policy, krbtgt age, stale accounts, end-of-life domain controllers, LAPS. Like Tenable Identity Exposure; read-only, nothing is attacked.",
    tools: "Fixed read-only LDAP queries through the Active Directory connector", connector: "Needs the Active Directory connector (a normal domain user over LDAPS)."},
  m365: {what: "Checks the Microsoft 365 / Entra ID tenant: MFA registration and enforcement, security defaults and Conditional Access, legacy sign-ins, how many admins, guests, third-party app consents, mail forwarding rules, Secure Score and open alerts. Like Microsoft Secure Score and Tenable Identity Exposure for Entra.",
    tools: "Microsoft Graph, fixed list of read-only paths", connector: "Needs the Microsoft 365 connector (an app with read-only Graph permissions)."},
  devices: {what: "Covers laptops and phones wherever they are, through Intune and Defender: non-compliant, unencrypted or stale devices, end-of-life OS versions, missing compliance policies, open Defender alerts. Like the endpoint agents of Tenable, Qualys and Rapid7.",
    tools: "Microsoft Graph (Intune, Defender), end-of-life database", connector: "Needs the Microsoft 365 connector with the Intune permissions."},
  patch: {what: "Looks inside servers and Windows machines: missing security updates, packages with known vulnerabilities, reboot needed, end-of-life OS, SSH, firewall, users and kernel hardening (CIS); DSM version on Synology; pending updates, users and backup jobs on Proxmox. Like Nessus credentialed scans and Qualys VMDR.",
    tools: "Fixed read-only checks over SSH (no sudo), the Synology and Proxmox read-only APIs, OSV, CVE and end-of-life databases", connector: "Needs a Linux SSH, Synology or Proxmox connector."},
  risk: {what: "Analyst. Ranks every finding 1 to 4 by real-world risk (actively exploited, ransomware use, chance of exploitation, internet exposure, how important the device is), merges duplicates and carries owners over from the last assessment. Like Tenable VPR, Qualys TruRisk, Rapid7 Active Risk.",
    tools: "The run's findings, CISA KEV, FIRST EPSS, web search"},
  paths: {what: "Analyst. Chains findings into realistic attack paths to what matters most and names the fixes that break them. Reasoned from the evidence; nothing is exploited.",
    tools: "The run's findings and inventory"},
  compliance: {what: "Analyst. Maps the assessment to CIS Controls v8 IG1, ISO 27001:2022 Annex A, NIS2 Article 21 and Swiss revFADP / nLPD: met, partly, gap or not assessed, with the evidence.",
    tools: "The run's findings and inventory, built-in control lists"},
};
let agentsOff = new Set();
let scaleMode = "auto", scale = {};
function renderScale(c) {
  scaleMode = c.scale_mode; scale = JSON.parse(JSON.stringify(c.scale));
  $("per-copy").value = c.per_copy;
  const paint = () => {
    document.querySelectorAll("[data-scale]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.scale === scaleMode)));
    $("per-copy-v").textContent = `· ${$("per-copy").value}`;
    $("scale-note").textContent = scaleMode === "auto" ? "Guardian decides how many copies of each agent to run from how many devices it gets, within the limits below."
                                                       : "Each agent runs the number of copies you set, within the limits below.";
    document.querySelectorAll(".scale-manual").forEach(i => i.disabled = scaleMode !== "manual");
  };
  const num = (k, key, lo, hi, cls) => { const i = el("input", {type: "number", min: lo, max: hi, class: "wauto " + (cls || ""), "aria-label": `${c.agents[k]} ${key}`});
    i.value = scale[k][key]; i.disabled = k === "wan" && key !== "min";
    i.addEventListener("input", () => { scale[k][key] = Math.max(lo, Math.min(hi, +i.value || lo)); }); return i; };
  $("scale-rows").replaceChildren(...Object.keys(c.scale).map(k => el("tr", {}, el("td", {}, c.agents[k]),
    el("td", {}, num(k, "min", 1, 20)), el("td", {}, num(k, "max", 1, 20)), el("td", {}, num(k, "manual", 1, 20, "scale-manual")))));
  document.querySelectorAll("[data-scale]").forEach(b => b.onclick = () => { scaleMode = b.dataset.scale; paint(); });
  $("per-copy").oninput = paint;
  paint();
}
function renderAgents(c) {
  agentsOff = new Set(c.agents_off);
  const box = $("agent-cards"); box.replaceChildren();
  for (const [k, info] of Object.entries(AGENT_INFO)) {
    const on = !agentsOff.has(k);
    const sw = el("input", {type: "checkbox", "aria-label": `${c.agents[k]} on`});
    sw.checked = on; if (info.always) sw.disabled = true;
    sw.addEventListener("change", () => { sw.checked ? agentsOff.delete(k) : agentsOff.add(k); card.classList.toggle("off", !sw.checked); });
    const card = el("div", {class: "conn agent" + (on ? "" : " off")},
      el("div", {class: "ahead"}, el("b", {}, c.agents[k]), el("label", {class: "switch", title: info.always ? "Always on: the other agents depend on it" : ""}, sw, el("span"))),
      el("p", {class: "note"}, info.what), el("p", {class: "note"}, el("b", {}, "Checks: "), info.tools),
      info.connector ? el("p", {class: "note"}, el("b", {}, "Sees more with: "), info.connector.replace(/^With /, "")) : null);
    box.append(card);
  }
}
function renderConfig(c) {
  $("model").replaceChildren(...Object.entries(c.models).map(([v, t]) => el("option", {value: v}, t)));
  $("effort").replaceChildren(...c.efforts.map(v => el("option", {value: v}, v + (v === "medium" ? " (default)" : ""))));
  $("model").value = c.model; $("effort").value = c.effort;
  $("rounds").replaceChildren(...c.rounds.map(v => el("option", {value: v}, v + (v === 40 ? " (default)" : ""))));
  $("parallel").replaceChildren(...c.parallels.map(v => el("option", {value: v}, v + (v === 3 ? " (default)" : v > 6 ? " (needs a higher API tier)" : ""))));
  $("rounds").value = c.max_rounds; $("parallel").value = c.parallel;
  renderAgents(c); renderScale(c);
  $("akey-state").replaceChildren(c.anthropic_key_set ? el("span", {class: "ok"}, "✓ set") : el("span", {class: "c-high"}, "not set"));
  $("nkey-state").replaceChildren(c.nvd_key_set ? el("span", {class: "ok"}, "✓ set") : el("span", {}, "(optional)"));
}
$("ai-form").addEventListener("submit", async e => {
  e.preventDefault(); $("ai-msg").textContent = "";
  try {
    renderConfig(await api("/api/settings", {model: $("model").value, effort: $("effort").value, max_rounds: +$("rounds").value,
      parallel: +$("parallel").value, agents_off: [...agentsOff],
      scale_mode: scaleMode, per_copy: +$("per-copy").value, scale, anthropic_key: $("akey").value, nvd_key: $("nkey").value}));
    $("akey").value = ""; $("nkey").value = ""; $("ai-msg").textContent = "Saved";
  } catch (err) { $("ai-msg").textContent = err.message; }
});

// -- me, vault --------------------------------------------------------------------------
let me = null;
const ADMIN_ONLY = ["users", "security", "ai", "schedules", "ticketing"];
const allowed = s => s === "appearance" || me.role === "admin" || (me.role === "operator" ? !ADMIN_ONLY.includes(s) : s === "account");
function renderMe() {
  $("me").textContent = `${me.name} · ${me.role}`;
  $("vault-chip").className = "vchip " + (me.unlocked ? "open" : "shut");
  $("vault-chip").textContent = me.unlocked ? "Vault unlocked" : (me.can_unlock ? "Vault locked" : "Read-only");
  $("unlock").classList.toggle("hidden", me.unlocked || !me.can_unlock);
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("hidden", !allowed(a.dataset.s)));
}
async function refreshMe() { me = await api("/api/me"); if (me.prefs && me.prefs.theme) Theme.set(me.prefs); renderMe(); }
async function unlock() {
  try { const r = await Passkey.authenticate(true); if (r.note) alert(r.note); await refreshMe(); await loadConnectors(); showSection(); }
  catch (e) { alert(Passkey.explain(e)); }
}
$("unlock").addEventListener("click", unlock);
$("unlock-inline").addEventListener("click", unlock);
$("signout").addEventListener("click", async () => { await api("/api/auth/signout", {}); location.replace("/signin"); });
const when = t => t ? new Date(t * 1000).toLocaleString([], {dateStyle: "medium", timeStyle: "short"}) : "—";
const ROLE = {viewer: "Viewer", operator: "Operator", admin: "Admin"};

// -- users ----------------------------------------------------------------------------------
async function loadUsers() {
  const d = await api("/api/users");
  $("users-count").textContent = `${d.users.length} user${d.users.length === 1 ? "" : "s"}` + (d.invites.length ? ` · ${d.invites.length} pending` : "");
  $("inv-note").textContent = "The link works once, only for that e-mail address, and expires after 7 days. Send it to them yourself."
    + (Object.keys(d.providers).length ? ` They sign in with ${Object.values(d.providers).join(" or ")}.` : " No Google or Microsoft sign-in is set up yet, so they'll use a passkey only.");
  const rows = d.users.map(u => {
    const isMe = u.id === me.id;
    const role = el("select", {class: "mini", disabled: isMe, onchange: async e => { try { await api(`/api/users/${u.id}`, {role: e.target.value}); } catch (x) { alert(x.message); } loadUsers(); }},
      ...Object.entries(ROLE).map(([v, t]) => el("option", {value: v, selected: v === u.role}, t)));
    let access;
    if (u.role === "viewer") access = el("span", {class: "tag"}, "Not needed");
    else if (u.vault) access = el("span", {class: "tag ok"}, "Granted");
    else if (!u.has_key) access = el("span", {class: "tag"}, "Needs a passkey first");
    else access = el("button", {class: "btn sm primary", onclick: async () => { try { await api(`/api/users/${u.id}/grant`, {}); } catch (x) { alert(x.message); } loadUsers(); }}, "Grant vault access");
    const acts = el("div", {class: "row"});
    if (!isMe) {
      if (u.vault) acts.append(el("button", {class: "btn sm", onclick: async () => { if (confirm(`Remove ${u.name}'s vault access?`)) { try { await api(`/api/users/${u.id}/revoke`, {}); } catch (x) { alert(x.message); } loadUsers(); } }}, "Revoke vault"));
      acts.append(el("button", {class: "btn sm", onclick: async () => { try { await api(`/api/users/${u.id}`, {status: u.status === "active" ? "disabled" : "active"}); } catch (x) { alert(x.message); } loadUsers(); }}, u.status === "active" ? "Disable" : "Enable"));
      acts.append(el("button", {class: "btn sm ghost danger", onclick: async () => { if (confirm(`Remove ${u.email}?`)) { try { await api(`/api/users/${u.id}/delete`, {}); } catch (x) { alert(x.message); } loadUsers(); } }}, "Remove"));
    }
    return el("tr", {class: u.status === "active" ? "" : "muted"},
      el("td", {}, el("b", {}, u.name + (isMe ? " (you)" : "")), el("br"), el("span", {class: "meta"}, u.email)),
      el("td", {}, u.provider ? {google: "Google", microsoft: "Microsoft"}[u.provider] : "Passkey only"),
      el("td", {}, role),
      el("td", {}, String(u.passkeys), u.passkey_names ? el("span", {class: "meta"}, ` (${u.passkey_names})`) : null),
      el("td", {}, access),
      el("td", {class: "meta"}, u.status === "active" ? when(u.last_login) : "disabled"),
      el("td", {}, acts));
  });
  const inv = d.invites.map(i => el("tr", {},
    el("td", {}, el("b", {}, i.email), el("br"), el("span", {class: "meta"}, "invited " + when(i.created))),
    el("td", {class: "meta"}, "—"), el("td", {}, ROLE[i.role]), el("td", {class: "meta"}, "—"),
    el("td", {}, el("span", {class: "tag new"}, "Invite pending")), el("td", {class: "meta"}, "expires " + when(i.expires)),
    el("td", {}, el("button", {class: "btn sm ghost danger", onclick: async () => { await api(`/api/invites/${i.id}/revoke`, {}); loadUsers(); }}, "Revoke"))));
  $("users").replaceChildren(el("div", {class: "tablewrap"}, el("table", {class: "ctab"},
    el("thead", {}, el("tr", {}, ...["Person", "Signs in with", "Role", "Passkeys", "Vault access", "Last sign-in", ""].map(h => el("th", {}, h)))),
    el("tbody", {}, ...rows, ...inv))));
}
$("invite-form").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    const r = await api("/api/users/invite", {email: $("inv-email").value, role: $("inv-role").value});
    const box = el("div", {class: "codebox"}, r.link);
    $("inv-out").replaceChildren(el("p", {class: "note"}, `Invite for ${r.email} (${ROLE[r.role]}). Copy this link and send it to them:`), box,
      el("button", {class: "btn sm", type: "button", onclick: async ev => { try { await navigator.clipboard.writeText(r.link); ev.target.textContent = "Copied"; } catch (x) { getSelection().selectAllChildren(box); } }}, "Copy link"));
    $("inv-email").value = ""; loadUsers();
  } catch (x) { $("inv-out").replaceChildren(el("p", {class: "err"}, x.message)); }
});

// -- security --------------------------------------------------------------------------------
async function loadSecurity() {
  const d = await api("/api/security");
  $("vault-status").replaceChildren(
    el("span", {class: "vbig " + (d.unlocked ? "open" : "shut")}, d.unlocked ? "🔓" : "🔒"),
    el("div", {}, el("b", {}, d.unlocked ? "Vault unlocked" : "Vault locked"), el("div", {class: "note"},
      d.unlocked ? `By ${d.unlocked_by} at ${when(d.unlocked_at)} · ${d.holders} session${d.holders === 1 ? "" : "s"} · ${d.records} connector${d.records === 1 ? "" : "s"} stored`
                 : `${d.records} connector${d.records === 1 ? "" : "s"} stored, all encrypted`)));
  $("al-idle").value = d.autolock.idle; $("al-max").value = d.autolock.max;
  $("rec-state").textContent = d.recovery_created ? "Created " + when(d.recovery_created) : "Not created yet";
  $("rec-state").className = "tag" + (d.recovery_created ? " ok" : " warn");
  $("oidc").replaceChildren(...Object.entries(d.oidc).map(([k, v]) => {
    const label = k === "google" ? "Google" : "Microsoft";
    const id = el("input", {class: "mono", value: v.client_id, placeholder: "Client ID"});
    const secret = el("input", {type: "password", autocomplete: "new-password", placeholder: v.secret_set ? "Saved. Leave blank to keep it" : "Client secret"});
    const msg = el("span", {class: "note"});
    return el("div", {class: "provbox"},
      el("div", {class: "sechead"}, el("b", {}, label), el("span", {class: "tag" + (v.client_id && v.secret_set ? " ok" : "")}, v.client_id && v.secret_set ? "Enabled" : "Not set up")),
      el("label", {}, "Redirect URI to register with " + label), el("div", {class: "codebox"}, v.redirect),
      el("div", {class: "f2"}, el("div", {}, el("label", {}, "Client ID"), id), el("div", {}, el("label", {}, "Client secret"), secret)),
      el("div", {class: "row field"}, el("button", {class: "btn sm primary", type: "button", onclick: async () => {
        try { await api("/api/security/oidc", {provider: k, client_id: id.value, client_secret: secret.value}); secret.value = ""; msg.textContent = "Saved"; loadSecurity(); }
        catch (x) { msg.textContent = x.message; } }}, "Save"), msg));
  }));
  const a = await api("/api/audit?limit=100");
  $("audit").replaceChildren(el("div", {class: "tablewrap logbox"}, el("table", {class: "ctab"},
    el("thead", {}, el("tr", {}, ...["When", "Who", "What", ""].map(h => el("th", {}, h)))),
    el("tbody", {}, ...a.rows.map(r => el("tr", {}, el("td", {class: "meta nowrap"}, when(r.ts)), el("td", {}, r.actor),
      el("td", {}, r.action.replace(/-/g, " ")), el("td", {class: "meta"}, r.detail)))))));
}
$("al-save").addEventListener("click", async () => {
  try { await api("/api/security/autolock", {idle: +$("al-idle").value, max: +$("al-max").value}); $("al-msg").textContent = "Saved"; } catch (x) { $("al-msg").textContent = x.message; }
});
$("rec-rotate").addEventListener("click", async () => {
  if (!confirm("Create a new recovery key? The current one stops working immediately.")) return;
  try {
    const r = await api("/api/security/recovery", {});
    $("rec-out").replaceChildren(el("p", {class: "note"}, "Your new recovery key. It's shown only now: store it safely."), el("div", {class: "codebox big"}, r.recovery_key));
    loadSecurity();
  } catch (x) { $("rec-out").replaceChildren(el("p", {class: "err"}, x.message)); }
});
$("audit-verify").addEventListener("click", async () => {
  const r = await api("/api/audit/verify");
  $("audit-msg").textContent = r.ok ? `Intact: ${r.entries} entries checked.` : `Tampering detected at entry ${r.broken_at ?? "(entries were deleted)"}.`;
  $("audit-msg").className = r.ok ? "note ok" : "err";
});

// -- my account --------------------------------------------------------------------------------
async function loadAccount() {
  await refreshMe();
  $("acct-lede").textContent = `${me.name} (${me.email}) · ${ROLE[me.role]}`;
  $("my-passkeys").replaceChildren(el("div", {class: "tablewrap"}, el("table", {class: "ctab"},
    el("thead", {}, el("tr", {}, ...["Passkey", "Opens the vault", "Added", "Last used", ""].map(h => el("th", {}, h)))),
    el("tbody", {}, ...me.passkeys.map(p => el("tr", {}, el("td", {}, el("b", {}, p.name)),
      el("td", {}, p.unlock ? el("span", {class: "tag ok"}, "Yes") : el("span", {class: "tag"}, "No")),
      el("td", {class: "meta"}, when(p.created)), el("td", {class: "meta"}, when(p.last_used)),
      el("td", {}, me.passkeys.length > 1 ? el("button", {class: "btn sm ghost danger", onclick: async () => {
        if (confirm(`Remove passkey "${p.name}"?`)) { try { await api(`/api/me/passkeys/${p.id}/delete`, {}); } catch (x) { alert(x.message); } loadAccount(); } }}, "Remove") : null)))))));
  const provs = Object.entries(me.providers);
  $("link-note").textContent = me.provider
    ? `You sign in with ${{google: "Google", microsoft: "Microsoft"}[me.provider]}, then confirm with a passkey.`
    : provs.length ? "Your account isn't linked to Google or Microsoft yet: you sign in with a passkey only." : "No Google or Microsoft sign-in is set up: you sign in with a passkey.";
  $("link-btns").replaceChildren(...(me.provider ? [] : provs.map(([k, l]) => el("a", {class: "btn sm", href: `/auth/${k}/start?link=1`}, `Link ${l} account`))));
}
$("pk-add").addEventListener("click", async () => {
  const name = prompt("Name for the new passkey (e.g. iPhone, YubiKey):", Passkey.deviceName());
  if (!name) return;
  try {
    if (!me.can_add_passkey) { alert("First confirm with one of your current passkeys."); await Passkey.authenticate(me.unlocked); }
    await Passkey.register(name);
    alert("Now confirm once with the NEW passkey so it can also open the vault.");
    await Passkey.authenticate(me.unlocked);
  } catch (e) { alert(Passkey.explain(e)); }
  loadAccount();
});

// -- appearance ---------------------------------------------------------------------------
function renderAppearance() {
  const box = $("themes");
  if (!box.childElementCount) {
    for (const [id, [name, desc]] of Object.entries(Theme.THEMES)) {
      const mini = el("div", {class: "mini"}, el("div", {class: "mp"}, el("div", {class: "k"}, "Score"), el("div", {class: "n"}, "64 ", el("small", {}, "/ 100")),
        el("div", {class: "bar"}, el("i"))), el("div", {class: "row2"}, el("span"), el("span"), el("span")));
      box.append(el("button", {type: "button", class: "tcard", role: "radio", "data-theme": id, onclick: () => Theme.set({theme: id}, true)},
        mini, el("div", {class: "meta2"}, el("b", {}, name, el("span", {class: "on"}, "Active")), el("span", {class: "d"}, desc))));
    }
    box.addEventListener("keydown", e => {
      const keys = {ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1};
      if (!keys[e.key]) return;
      e.preventDefault();
      const ids = Object.keys(Theme.THEMES), i = ids.indexOf(Theme.get().theme);
      const next = ids[(i + keys[e.key] + ids.length) % ids.length];
      Theme.set({theme: next}, true); box.querySelector(`[data-theme="${next}"]`).focus();
    });
    document.querySelectorAll("#s-appearance .seg button").forEach(b => b.addEventListener("click", () => Theme.set({mode: b.dataset.mode}, true)));
    $("sizes").append(...Theme.SIZES.map(z => el("button", {type: "button", "data-size": z, "aria-pressed": "false", onclick: () => Theme.set({size: z}, true)},
      z === "auto" ? "Auto" : `${z}%`)));
    Theme.onChange(paintAppearance);
  }
  paintAppearance();
}
function paintAppearance() {
  const t = Theme.get();
  document.querySelectorAll("#s-appearance .seg button[data-mode]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.mode === t.mode)));
  document.querySelectorAll("#sizes button").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.size === t.size)));
  $("size-note").textContent = t.size === "auto" ? `Grows with the window on large screens. Now ${Math.round(t.zoom * 100)}% on this screen.` : `Fixed at ${t.size}% on every screen.`;
  document.querySelectorAll(".tcard").forEach(c => { c.dataset.scheme = t.scheme; c.setAttribute("aria-checked", String(c.dataset.theme === t.theme)); c.tabIndex = c.dataset.theme === t.theme ? 0 : -1; });
  $("theme-saved").textContent = `${Theme.THEMES[t.theme][0]} · ${t.mode === "system" ? `follows your system (now ${t.scheme})` : t.mode}`;
}

(async () => {
  await refreshMe();
  showSection();
  if (me.role === "admin") renderConfig((await api("/api/overview")).config);
  await loadConnectors();
})();
