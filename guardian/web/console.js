"use strict";
const $ = id => document.getElementById(id);
const store = {get(k){try{return localStorage.getItem(k)}catch(e){return null}}, set(k,v){try{localStorage.setItem(k,v)}catch(e){}}};
const SEVS = ["critical", "high", "medium", "low"];
let current = null;       // run id shown in the report tab
let seq = 0;              // last log line received
let polling = null;

async function api(path, body) {
  const opts = body === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json", "X-Guardian": "1"}, body: JSON.stringify(body)};
  const r = await fetch(path, opts);
  if (r.status === 401) { location.replace("/signin"); throw new Error("Sign in first"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `Request failed (${r.status})`);
  return data;
}

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}

const fmtRun = id => `${id.slice(0,4)}-${id.slice(4,6)}-${id.slice(6,8)} ${id.slice(9,11)}:${id.slice(11,13)}`;
const mins = s => Math.max(0, Math.round(s / 60));

// -- who is signed in, vault state ----------------------------------------------------
let me = null;
function renderMe() {
  $("me").textContent = `${me.name} · ${me.role[0].toUpperCase()}${me.role.slice(1)}`;
  $("avatar").textContent = me.name.split(/\s+/).map(w => w[0]).slice(0, 2).join("").toUpperCase();
  const vaultRole = me.role !== "viewer";
  document.querySelectorAll(".op-only").forEach(e => e.classList.toggle("hidden", !vaultRole));
  $("vault-chip").className = "vchip " + (me.unlocked ? "open" : "shut");
  $("vault-chip").textContent = me.unlocked ? "Vault unlocked" : (me.can_unlock ? "Vault locked" : "Read-only");
  $("vault-chip").classList.toggle("hidden", !vaultRole && !me.unlocked);
  $("unlock").classList.toggle("hidden", me.unlocked || !me.can_unlock);
  $("lock").classList.toggle("hidden", !me.unlocked);
}
async function refreshMe() { me = await api("/api/me"); renderMe(); }
async function unlock() {
  try { const r = await Passkey.authenticate(true); if (r.note) note(r.note); await refreshMe(); return me.unlocked; }
  catch (e) { alert(Passkey.explain(e)); return false; }
}
function note(text) { $("note").textContent = text; $("note").classList.toggle("hidden", !text); }
$("unlock").addEventListener("click", unlock);
$("lock").addEventListener("click", async () => { await api("/api/vault/lock", {}); await refreshMe(); });
$("signout").addEventListener("click", async () => { await api("/api/auth/signout", {}); location.replace("/signin"); });

// -- runs ---------------------------------------------------------------------
function renderRuns(runs, job) {
  const box = $("runs");
  box.replaceChildren();
  if (job.running && job.mode !== "report" && job.mode !== "resume")
    box.append(el("div", {class: "run on"}, el("div", {class: "top"}, el("span", {class: "mono"}, "New run"), el("span", {class: "meta"}, "running")),
      el("div", {class: "sevs"}, job.label)));
  if (!runs.length && !job.running) box.append(el("p", {class: "note"}, "No runs yet. Start a scan with the buttons at the top."));
  for (const r of runs) {
    const busy = job.running && job.run_id === r.id;
    const top = el("div", {class: "top"}, el("span", {class: "mono"}, fmtRun(r.id)),
      busy ? el("span", {class: "meta"}, "running")
        : r.score != null ? el("span", {class: "score"}, String(r.score), " ", el("small", {}, r.grade || ""))
        : el("span", {class: "meta"}, r.has_graph ? "scan only" : "incomplete"));
    const sevs = el("div", {class: "sevs"});
    if (r.devices != null) sevs.append(el("span", {}, `${r.devices} device${r.devices === 1 ? "" : "s"}`));
    if (r.analysed) for (const s of SEVS) if (r.counts[s]) sevs.append(el("span", {}, el("b", {class: `c-${s}`}, String(r.counts[s])), ` ${s === "medium" ? "med" : s}`));
    if (r.has_graph && !r.analysed) sevs.append(el("span", {}, "no AI analysis yet"));
    const acts = el("div", {class: "row"});
    const canRun = me && me.role !== "viewer";
    if (r.has_report) acts.append(el("button", {class: "btn sm", onclick: ev => { ev.stopPropagation(); openRun(r.id, true); }}, "Report"));
    if (r.has_graph) {
      if (canRun) acts.append(el("button", {class: "btn sm", onclick: ev => { ev.stopPropagation(); startJob("resume", r.id); }}, r.analysed ? "Re-run AI" : "Run AI"));
      if (canRun && (r.analysed || r.has_report)) acts.append(el("button", {class: "btn sm", onclick: ev => { ev.stopPropagation(); startJob("report", r.id); }}, "Rebuild report"));
      acts.append(el("a", {class: "btn sm", href: `/api/runs/${r.id}/graph`, onclick: ev => ev.stopPropagation()}, "Data"));
    }
    box.append(el("div", {class: "run" + (r.id === current ? " on" : ""), onclick: () => openRun(r.id, r.has_report)}, top, sevs, acts));
  }
}

function openRun(id, hasReport) {
  current = id;
  document.querySelectorAll(".run").forEach(n => n.classList.toggle("on", n.querySelector(".mono")?.textContent === fmtRun(id)));
  $("current").textContent = `run ${fmtRun(id)}`;
  const url = `/api/runs/${id}/report`;
  if (hasReport) {
    $("frame").src = url; $("frame-empty").classList.add("hidden");
    $("newtab").href = url; $("newtab").classList.remove("hidden");
  } else {
    $("frame").removeAttribute("src"); $("frame-empty").textContent = "This run has no report yet."; $("frame-empty").classList.remove("hidden");
    $("newtab").classList.add("hidden");
  }
  showTab("report");
}

// -- job ----------------------------------------------------------------------
async function startJob(mode, runId) {
  try {
    seq = 0; $("p-log").replaceChildren();
    let s;
    try { s = await api("/api/job/start", {mode, run_id: runId || null}); }
    catch (e) {
      if (!/Unlock the vault/.test(e.message) || !confirm(e.message + "\n\nUnlock now?") || !await unlock()) throw e;
      s = await api("/api/job/start", {mode, run_id: runId || null});
    }
    showTab("log"); renderJob(s); poll();
  } catch (err) { alert(err.message); }
}
$("go-collect").addEventListener("click", () => startJob("collect"));
$("go-full").addEventListener("click", () => {
  if (confirm("Start a full scan with the AI assessment? It takes about 30 minutes and uses your API credit.")) startJob("full");
});
$("stop").addEventListener("click", async () => {
  if (!confirm("Stop the current run?")) return;
  try { await api("/api/job/stop", {}); } catch (err) { alert(err.message); }
});

function appendLog(lines) {
  const box = $("p-log");
  const atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  for (const l of lines) {
    const row = el("div", {}, el("span", {class: "t"}, l.t + "  "));
    const m = l.text.match(/^\[(\w+)\]\s?(.*)$/);
    if (m) {
      row.append(el("span", {class: m[1] === "console" ? "c" : "a"}, m[1]), "  ");
      const f = m[2].match(/^(F\d+ \[(\w+)\])(.*)$/);
      if (f) row.append(el("span", {class: `s-${f[2]}`}, f[1]), f[3]); else row.append(m[2]);
    } else row.append(l.text);
    box.append(row);
  }
  while (box.childElementCount > 3000) box.firstElementChild.remove();
  if (atEnd) box.scrollTop = box.scrollHeight;
}

function renderJob(s) {
  const busy = s.running;
  $("dot").className = "dot" + (busy ? " busy" : "");
  for (const b of ["go-collect", "go-full"]) $(b).disabled = busy;
  document.querySelectorAll(".run .btn").forEach(b => { if (b.tagName === "BUTTON" && b.textContent !== "Report") b.disabled = busy; });
  if (!s.mode) { $("job").classList.add("hidden"); return; }
  const failed = !busy && (s.stopped || s.exit_code !== 0);
  $("job").className = "job" + (busy ? "" : failed ? " failed" : " done");
  $("job-dot").className = "dot" + (busy ? " busy" : failed ? " bad" : "");
  $("stop").classList.toggle("hidden", !busy);
  const elapsed = mins(((busy ? Date.now() / 1000 : s.ended) || s.started) - s.started);
  $("job-title").textContent = busy ? `${s.label} running` : s.stopped ? `${s.label} stopped` : failed ? `${s.label} failed` : `${s.label} finished`;
  const step = s.steps.length > 1 ? `step ${s.step} of ${s.steps.length}, ${s.steps[s.step - 1]} · ` : "";
  $("job-detail").textContent = busy ? `· ${step}${elapsed} min elapsed` : `· ${elapsed} min${failed && !s.stopped ? ", see the live log" : ""}`;
  $("job-bar").style.width = busy ? `${Math.round((s.step - 0.5) / s.steps.length * 100)}%` : "100%";
}

async function poll() {
  clearTimeout(polling);
  try {
    const s = await api(`/api/job?since=${seq}`);
    if (s.lines.length) { appendLog(s.lines); seq = s.seq; }
    renderJob(s);
    if (s.running) { polling = setTimeout(poll, 2000); return; }
    const o = await api("/api/overview");
    renderRuns(o.runs, o.job);
    if (s.run_id && s.exit_code === 0) {
      const r = o.runs.find(x => x.id === s.run_id);
      if (r && r.has_report && s.mode !== "collect") openRun(r.id, true);
    }
  } catch (err) { polling = setTimeout(poll, 5000); }
}

// -- tabs, theme, start-up ----------------------------------------------------------
function showTab(t) {
  document.querySelectorAll(".tab").forEach(b => b.classList.toggle("on", b.dataset.t === t));
  $("p-report").classList.toggle("hidden", t !== "report");
  $("p-log").classList.toggle("hidden", t !== "log");
  if (t === "log") $("p-log").scrollTop = $("p-log").scrollHeight;
}
document.querySelectorAll(".tab").forEach(b => b.addEventListener("click", () => showTab(b.dataset.t)));
$("refresh").addEventListener("click", () => poll());

const theme = store.get("guardian-theme");
if (theme) document.documentElement.dataset.theme = theme;
$("theme").addEventListener("click", () => {
  const r = document.documentElement;
  const dark = r.dataset.theme ? r.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  r.dataset.theme = dark ? "light" : "dark";
  store.set("guardian-theme", r.dataset.theme);
});

async function start() {
  await refreshMe();
  const n = sessionStorage.getItem("guardian-note"); if (n) { note(n); sessionStorage.removeItem("guardian-note"); }
  const o = await api("/api/overview");
  renderRuns(o.runs, o.job);
  const latest = o.runs.find(r => r.has_report);
  if (latest) openRun(latest.id, true);
  const s = await api("/api/job?since=0");
  if (s.lines.length) { appendLog(s.lines); seq = s.seq; }
  renderJob(s);
  if (s.running) { showTab("log"); poll(); }
}
start();
setTimeout(() => me && me.role !== "viewer" && fetch("/api/connectors").then(r => r.ok ? r.json() : null).then(d => {
  if (d && d.suggestions.length) { $("set-count").textContent = d.suggestions.length; $("set-count").classList.remove("hidden"); }
}).catch(() => {}), 500);
