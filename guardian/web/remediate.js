"use strict";
const $ = id => document.getElementById(id);
async function api(path, body) {
  const opts = body === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json", "X-Guardian": "1"}, body: JSON.stringify(body)};
  const r = await fetch(path, opts);
  if (r.status === 401) { location.replace("/signin"); throw new Error("Sign in first"); }
  const out = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(out.detail || `Request failed (${r.status})`); e.status = r.status; throw e; }
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
const when = t => new Date(t * 1000).toLocaleString([], {dateStyle: "short", timeStyle: "short"});
const RISK = {low: "ok", medium: "warn", high: "error"};
const STATUS = {approved: "Approved", running: "Running", done: "Done", "rolled-back": "Rolled back", "not-applied": "Not applied", "needs-attention": "Needs attention"};
let data = null, timer = null;

// Each sensitive action asks for a passkey right before it, so the server sees a fresh confirmation.
async function confirmed(action) {
  try { await Passkey.authenticate(true); } catch (e) { alert(Passkey.explain(e)); return null; }
  try { return await action(); } catch (e) { alert(e.message); return null; }
}

function render() {
  const d = data;
  const left = Math.max(0, Math.round((d.until - Date.now() / 1000) / 60));
  $("st").textContent = d.on ? "ON" : "OFF";
  $("st").className = "val " + (d.on ? "c-critical" : "");
  $("st-note").textContent = d.on ? `Changes allowed for ${left} more min (turned on by ${d.by}). Each one still needs approval.` : "Guardian is read-only. No device can be changed.";
  $("chip").className = "chip" + (d.on ? " live" : ""); $("chip-t").textContent = d.on ? `Remediation on · ${left} min` : "Read-only";
  $("on").disabled = d.on || !d.admin; $("off").disabled = !d.on || !d.admin;
  $("vault-chip").className = "vchip " + (d.unlocked ? "open" : "shut"); $("vault-chip").textContent = d.unlocked ? "Vault unlocked" : "Vault locked";
  $("never").replaceChildren(...d.never.map(t => el("li", {}, t)));
  $("run").textContent = d.run ? `from run ${d.run.slice(0, 8)} ${d.run.slice(9, 11)}:${d.run.slice(11, 13)}` : "no run yet";
  $("props").replaceChildren(...(d.proposals.length ? d.proposals.map(proposal) : [el("p", {class: "note"}, "Nothing Guardian can fix automatically in the latest run.")]));
  $("changes").replaceChildren(...(d.changes.length ? d.changes.map(change) : [el("p", {class: "note"}, "No changes yet.")]));
  $("recipes").replaceChildren(...Object.values(d.recipes).map(r => el("tr", {},
    el("td", {}, el("b", {}, r.title)), el("td", {}, r.applies), el("td", {}, el("span", {class: "tag " + (RISK[r.risk] || "")}, r.risk)),
    el("td", {}, `${r.backup} · ${r.rollback}`), el("td", {}, r.needs),
    el("td", {}, el("span", {class: "tag " + (r.status === "active" ? "ok" : r.status === "manual" ? "new" : "")}, r.status)))));
  document.querySelectorAll(".admin-only").forEach(e => e.classList.toggle("hidden", !d.admin));
  $("pubkey").textContent = d.public_key || "Created when you add the first server.";
  $("sudoers").textContent = d.sudoers;
  $("fa-rows").replaceChildren(...Object.entries(d.hosts).map(([h, a]) => el("tr", {}, el("td", {class: "mono"}, h), el("td", {class: "mono"}, a.user),
    el("td", {}, String(a.port)), el("td", {class: "mono"}, a.guest || "—"), el("td", {}, el("button", {class: "btn ghost danger sm", onclick: () => account({host: h, remove: true})}, "Remove")))));
  $("wf-rows").replaceChildren(...Object.entries(d.windows || {}).map(([h, a]) => el("tr", {}, el("td", {class: "mono"}, h), el("td", {class: "mono"}, a.user),
    el("td", {}, String(a.port)), el("td", {}, el("button", {class: "btn ghost danger sm", onclick: () => post("/api/fix/windows", {host: h, remove: true})}, "Remove")))));
  $("m-allowed").textContent = (d.m365_allowed || []).join(", ");
  $("m-state").textContent = d.m365 ? `Saved: app ${d.m365.client_id}, ${d.m365.roles.length} permission(s).` : "Not set up.";
  if (d.m365) { $("m-tenant").value = d.m365.tenant_id || ""; $("m-client").value = d.m365.client_id || ""; }
  $("n-state").textContent = d.ninja ? `Saved: ${d.ninja.region}, client ${d.ninja.client_id}.` : "Not set up.";
  if (d.ninja) { $("n-region").value = d.ninja.region; $("n-client").value = d.ninja.client_id; }
  $("px-state").textContent = d.proxmox ? `Saved: ${d.proxmox.token_id} on ${d.proxmox.host}.` : "Not set up: Linux updates run without a snapshot.";
  if (d.proxmox) { $("px-host").value = d.proxmox.host; $("px-id").value = d.proxmox.token_id; }
  const running = d.changes.some(c => c.status === "running" || c.status === "approved");
  clearTimeout(timer); timer = setTimeout(load, running ? 2000 : 30000);
}

function proposal(p) {
  const r = data.recipes[p.recipe];
  const acts = el("div", {class: "row mt16"});
  if (p.change) acts.append(el("span", {class: "tag ok"}, `Applied · ${p.change}`));
  else if (!p.ready) acts.append(el("span", {class: "tag warn"}, p.blocked));
  else if (data.admin) {
    const rb = p.recipe === "windows.updates_install" ? el("input", {type: "checkbox"}) : null;
    if (rb) acts.append(el("label", {class: "check"}, rb, "Restart if needed (15 min warning)"));
    acts.append(el("button", {class: "btn solid", disabled: !data.on, onclick: () => approve(p, rb && rb.checked)}, data.on ? "Approve and apply · passkey" : "Turn remediation on first"));
  }
  else acts.append(el("span", {class: "note"}, "An admin approves fixes."));
  return el("div", {class: "box field"},
    el("div", {class: "row"}, el("span", {class: "tag " + (RISK[r.risk] || "")}, `${r.risk} risk`), el("span", {class: "tag"}, p.recipe), p.finding ? el("span", {class: "tag"}, p.finding) : null),
    el("h3", {class: "stitle"}, p.title),
    el("div", {class: "kv"}, el("span", {}, "Why"), el("span", {}, p.why)),
    el("div", {class: "kv"}, el("span", {}, "Could break"), el("span", {}, r.breaks)),
    el("div", {class: "kv"}, el("span", {}, "Backup / rollback"), el("span", {}, `${r.backup} · ${r.rollback}`)), acts);
}

function change(c) {
  const can = data.admin && (c.status === "done" || c.status === "needs-attention") && c.recipe;
  return el("div", {class: "box field"},
    el("div", {class: "row"}, el("b", {}, c.id), el("span", {class: "tag " + ({done: "ok", "rolled-back": "warn", "needs-attention": "error", "not-applied": "warn"}[c.status] || "")}, STATUS[c.status] || c.status),
      el("span", {class: "note m0"}, `${c.title} · ${c.by} · ${when(c.created)}`)),
    el("div", {class: "steps mt16"}, ...c.steps.map(s => el("div", {class: "ev " + (s.ok ? "done" : "error")},
      el("span", {class: "t"}, `${when(s.t)}  ${s.step}  `), s.text))),
    can ? el("div", {class: "row mt16"}, el("button", {class: "btn danger sm", onclick: () => undo(c)}, "Roll back · passkey")) : null);
}

async function approve(p, reboot) {
  if (!confirm(`Apply "${p.title}"?\n\nGuardian backs up first and rolls back automatically if the check fails.`)) return;
  if (await confirmed(() => api("/api/fix/apply", {proposal: p.id, reboot: !!reboot}))) load();
}
async function post(path, body) {
  try { await api(path, body); load(); } catch (e) { alert(e.message); }
}
async function undo(c) {
  if (!confirm(`Roll back ${c.id}: "${c.title}"?`)) return;
  if (await confirmed(() => api(`/api/fix/changes/${c.id}/rollback`, {}))) load();
}
async function account(body) {
  try { await api("/api/fix/accounts", body); load(); } catch (e) { alert(e.message); }
}
$("on").addEventListener("click", async () => {
  if (await confirmed(() => api("/api/fix/on", {minutes: +$("dur").value}))) load();
});
$("off").addEventListener("click", async () => { try { await api("/api/fix/off", {}); load(); } catch (e) { alert(e.message); } });
$("fa-add").addEventListener("click", () => account({host: $("fa-host").value.trim(), user: $("fa-user").value.trim() || "guardian-fix", guest: $("fa-guest").value.trim()}));
$("wf-add").addEventListener("click", () => post("/api/fix/windows", {host: $("wf-host").value.trim(), user: $("wf-user").value.trim(),
  password: $("wf-pass").value || null, verify_tls: $("wf-tls").checked}).then(() => { $("wf-pass").value = ""; }));
$("m-save").addEventListener("click", () => post("/api/fix/m365", {tenant_id: $("m-tenant").value, client_id: $("m-client").value, client_secret: $("m-secret").value || null}).then(() => { $("m-secret").value = ""; }));
$("m-del").addEventListener("click", () => confirm("Remove the Microsoft 365 fix app from Guardian?") && post("/api/fix/m365", {remove: true}));
$("n-save").addEventListener("click", () => post("/api/fix/ninja", {region: $("n-region").value, client_id: $("n-client").value, client_secret: $("n-secret").value || null}).then(() => { $("n-secret").value = ""; }));
$("n-del").addEventListener("click", () => confirm("Remove the NinjaOne patch credentials?") && post("/api/fix/ninja", {remove: true}));
$("px-save").addEventListener("click", () => post("/api/fix/proxmox", {host: $("px-host").value.trim(), token_id: $("px-id").value.trim(), token_secret: $("px-secret").value || null}).then(() => { $("px-secret").value = ""; }));
$("px-del").addEventListener("click", () => confirm("Remove the Proxmox snapshot token?") && post("/api/fix/proxmox", {remove: true}));

async function load() {
  try { data = await api("/api/fix"); render(); }
  catch (e) { $("note").textContent = e.status === 403 ? "Fixes are for operators and admins." : e.message; $("note").classList.remove("hidden"); }
}
(async () => {
  try { const me = await api("/api/me"); if (me.prefs && me.prefs.theme) Theme.set(me.prefs); } catch (e) { /* signed out: api() redirects */ }
  load();
})();
