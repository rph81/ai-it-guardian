"use strict";
const $ = id => document.getElementById(id);
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
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "style") setStyle(e, v);       // CSSOM: style="" attributes are blocked by the page's CSP
    else e.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}

function setStyle(e, css) {
  for (const decl of String(css).split(";")) { const i = decl.indexOf(":"); if (i > 0) e.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim()); }
}
const AGENT_NAMES = {orchestrator: "Orchestrator", discovery: "Discovery", network: "Network", os: "OS & endpoints", web: "Web & APIs",
                     firmware: "Firmware", wan: "Internet perimeter", report: "Report writer", collector: "Scanner",
                     ad: "Active Directory", m365: "Microsoft 365", devices: "Device fleet", azure: "Azure", aws: "AWS", business: "Business systems", patch: "Patch & config", risk: "Risk analyst", paths: "Attack paths", compliance: "Compliance"};
const SEVS_ALL = ["critical", "high", "medium", "low", "info"];
const money = v => v == null ? "—" : `$${Number(v).toFixed(2)}`;
const fmtRun = id => `${id.slice(0,4)}-${id.slice(4,6)}-${id.slice(6,8)} ${id.slice(9,11)}:${id.slice(11,13)}`;
const mins = s => Math.max(0, Math.round(s / 60));

// -- who is signed in, vault state ----------------------------------------------------
let me = null;
function renderMe() {
  $("me").textContent = `${me.name} · ${me.role[0].toUpperCase()}${me.role.slice(1)}`;
  if (me.prefs && me.prefs.theme) Theme.set(me.prefs);
  $("r-vault").textContent = me.unlocked ? "Unlocked" : me.can_unlock ? "Locked" : "Read-only";
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

// -- sites ----------------------------------------------------------------------
let SITE = "local", SITES = [];
try { SITE = localStorage.getItem("guardian-site") || "local"; } catch (e) { /* storage blocked */ }
const siteLabel = s => s.id === "local" ? "This network (Guardian's own)" : [s.customer, s.name].filter(Boolean).join(" · ");
const siteRuns = o => o.runs.filter(r => SITE === "all" || r.site === SITE);

function setSites(sites) {
  SITES = sites;
  if (SITE !== "all" && !sites.some(s => s.id === SITE)) SITE = sites.length ? sites[0].id : "local";
  if (SITE === "all" && sites.length < 2) SITE = sites.length ? sites[0].id : "local";
  const pick = $("site-pick");
  pick.replaceChildren(...(sites.length > 1 ? [el("option", {value: "all"}, "All sites")] : []),
    ...sites.map(s => el("option", {value: s.id}, siteLabel(s))));
  pick.value = SITE;
  pick.closest(".sitepick").classList.toggle("hidden", sites.length < 2);
  const cur = sites.find(s => s.id === SITE);
  $("site-name").textContent = SITE === "all" ? "All sites" : cur ? siteLabel(cur) : "";
  $("ptitle").textContent = SITE === "all" ? "Sites / Portfolio." : "Site / Overview.";
  $("psub").textContent = SITE === "all" ? "Which customer needs attention first." : "Network, devices, AI agents and findings.";
  document.body.classList.toggle("all-sites", SITE === "all");
  $("portfolio").classList.toggle("hidden", SITE !== "all");
  const remote = SITE !== "all" && SITE !== "local";
  for (const id of ["go-collect", "go-full", "go-replay"]) $(id).classList.toggle("hidden", remote);
  $("go-newrun").classList.toggle("hidden", !remote);
  $("remote-note").classList.toggle("hidden", !remote);
  if (SITE === "all") renderPortfolio();
}
$("site-pick").addEventListener("change", e => {
  try { localStorage.setItem("guardian-site", e.target.value); } catch (err) { /* storage blocked */ }
  location.reload();
});

async function renderPortfolio() {
  let d;
  try { d = await api("/api/portfolio"); } catch (e) { return; }
  const pick = id => { try { localStorage.setItem("guardian-site", id); } catch (e) { /* storage blocked */ } location.reload(); };
  const col = s => s == null ? "" : s >= 75 ? "ok" : s >= 60 ? "warn" : "error";
  const coll = c => c === "local" ? "Guardian itself" : !c ? "none" : c === "running" ? "online" : c.replace("_", " ");
  $("pf-rows").replaceChildren(...d.sites.map(s => el("tr", {class: "clickable", tabindex: "0", onclick: () => pick(s.id),
      onkeydown: e => { if (e.key === "Enter") pick(s.id); }},
    el("td", {}, el("b", {}, s.id === "local" ? "This network" : s.name)), el("td", {}, s.customer || "—"),
    el("td", {}, s.score != null ? el("span", {class: `score ${col(s.score)}`}, String(s.score)) : el("span", {class: "meta"}, s.run ? "not analysed" : "no assessment")),
    el("td", {class: "mono"}, s.run ? fmtRun(s.run) : "—"),
    el("td", {}, s.p1 ? el("span", {class: "tag error"}, String(s.p1)) : "0"),
    el("td", {}, s.overdue ? el("span", {class: "tag warn"}, String(s.overdue)) : "0"),
    el("td", {}, String(s.open)), el("td", {}, coll(s.collector)), el("td", {}, s.tickets))));
}

$("go-newrun").addEventListener("click", async () => {
  try {
    const r = await api(`/api/sites/${SITE}/runs`, {});
    const o = await api("/api/overview");
    renderRuns(siteRuns(o), o.job);
    openRun(r.run, false); go("plan");
  } catch (e) { alert(e.message); }
});

// -- runs ---------------------------------------------------------------------
function renderTrend(runs) {
  const pts = runs.filter(r => r.analysed).slice(0, 12).reverse().map(r => ({id: r.id, n: SEVS_ALL.reduce((a, s) => a + (r.counts[s] || 0), 0)}));
  const svg = $("t-spark"); svg.replaceChildren();
  const NS = "http://www.w3.org/2000/svg";
  if (!pts.length) { $("t-axis").replaceChildren(el("span", {}, "No AI runs yet")); return; }
  const max = Math.max(...pts.map(p => p.n), 1), W = 300, H = 96;
  const xy = pts.map((p, i) => [pts.length === 1 ? W / 2 : i * W / (pts.length - 1), H - 8 - (p.n / max) * (H - 20)]);
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", xy.map((c, i) => (i ? "L" : "M") + c[0].toFixed(1) + " " + c[1].toFixed(1)).join(" "));
  path.setAttribute("class", "tline"); svg.append(path);
  const last = xy[xy.length - 1], dot = document.createElementNS(NS, "circle");
  dot.setAttribute("cx", last[0]); dot.setAttribute("cy", last[1]); dot.setAttribute("r", 3.5); dot.setAttribute("class", "tdot"); svg.append(dot);
  $("t-axis").replaceChildren(el("span", {}, fmtRun(pts[0].id).slice(5, 10)), el("span", {}, `${pts.length} AI run${pts.length > 1 ? "s" : ""}`), el("span", {}, "Now"));
}

function renderRuns(runs, job) {
  renderTrend(runs);
  const box = $("runs");
  box.replaceChildren();
  if (job.running && job.mode !== "report" && job.mode !== "resume" && SITE === "local")
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
    if (r.has_graph && !r.analysed) sevs.append(el("span", {}, r.site === "local" ? "no AI analysis yet" : "imported results"));
    if (r.cost != null) sevs.append(el("span", {}, `AI $${r.cost.toFixed(2)}`));
    const acts = el("div", {class: "row"});
    const canRun = me && me.role !== "viewer" && r.site === "local";
    if (r.has_report) acts.append(el("button", {class: "btn sm", onclick: ev => { ev.stopPropagation(); openRun(r.id, true); }}, "Report"));
    if (r.has_agents) acts.append(el("button", {class: "btn sm", onclick: ev => { ev.stopPropagation(); openRun(r.id, r.has_report); showTab("map"); }}, "Agent map"));
    if (r.has_graph) {
      if (canRun) acts.append(el("button", {class: "btn sm", onclick: ev => { ev.stopPropagation(); startJob("resume", r.id); }}, r.analysed ? "Re-run AI" : "Run AI"));
      if (canRun && (r.analysed || r.has_report)) acts.append(el("button", {class: "btn sm", onclick: ev => { ev.stopPropagation(); startJob("report", r.id); }}, "Rebuild report"));
      acts.append(el("a", {class: "btn sm", href: `/api/runs/${r.id}/graph`, onclick: ev => ev.stopPropagation()}, "Data"));
    }
    box.append(el("div", {class: "run" + (r.id === current ? " on" : ""), onclick: () => openRun(r.id, r.has_report)}, top, sevs, acts));
  }
}

// -- overview panels --------------------------------------------------------------------
async function loadOverview(id) {
  let d;
  try { d = await api(`/api/runs/${id}/summary`); } catch (e) { return; }
  if (current !== id) return;
  $("o-run").textContent = `Run ${fmtRun(id)}`;
  $("o-headline").textContent = d.headline || "";
  $("o-sampled").textContent = d.started ? `Sampled ${d.started.replace("T", " ").slice(0, 16)}` : "";
  $("k-score").replaceChildren(d.score != null ? String(d.score) : "—", el("small", {}, d.score != null ? "/100" : ""));
  $("k-grade").textContent = d.score != null ? `Grade ${d.grade} · AI assessment` : "No AI assessment on this run";
  $("k-devices").textContent = d.devices;
  $("k-unid").textContent = d.unidentified ? `${d.unidentified} unidentified` : "All identified";
  $("k-forwards").replaceChildren(String(d.forwards), el("small", {}, "forwards"));
  $("k-services").replaceChildren(String(d.services), el("small", {}, "open"));
  $("k-sev").replaceChildren(...["critical", "high", "medium", "low"].map(s => el("span", {}, el("b", {class: d.severity[s] ? `c-${s}` : ""}, String(d.severity[s])), s === "critical" ? "crit" : s === "medium" ? "med" : s)));
  $("k-open").textContent = `${d.open} open · ${d.resolved} resolved`;
  let acc = 0; const stops = [];
  const tot = Math.max(1, ["critical", "high", "medium", "low"].reduce((a, s) => a + d.severity[s], 0));
  for (const s of ["critical", "high", "medium", "low"]) { const from = acc; acc += d.severity[s] / tot * 100; stops.push(`var(--${{critical: "crit", high: "high", medium: "med", low: "low"}[s]}) ${from}% ${acc}%`); }
  $("k-pie").style.setProperty("background", d.open ? `conic-gradient(${stops.join(",")})` : "var(--line)");
  $("t-now").replaceChildren(String(d.open), el("small", {}, "open now"));
  $("c-cost").textContent = d.cost ? money(d.cost) : "$0.00";
  const by = Object.entries(d.cost_by).sort((a, b) => b[1] - a[1]).slice(0, 4);
  $("c-by").replaceChildren(...(by.length ? by.map(([k, v]) => el("div", {class: "kv"}, el("span", {}, AGENT_NAMES[k] || k), el("span", {}, money(v))))
                                         : [el("div", {class: "kv"}, el("span", {}, "No AI work on this run"), el("span", {}, ""))]));
  $("c-min").replaceChildren(d.minutes != null ? String(d.minutes) : "—", el("small", {}, d.minutes != null ? " min" : ""));
  const tk = d.tokens >= 1e6 ? (d.tokens / 1e6).toFixed(1) + "M" : d.tokens >= 1e3 ? Math.round(d.tokens / 1e3) + "k" : String(d.tokens);
  $("c-work").replaceChildren(...[["Rounds", d.rounds], ["Checks", d.checks], ["Notes", d.notes], ["Tokens", tk]].map(([k, v]) => el("div", {class: "kv"}, el("span", {}, k), el("span", {}, String(v)))));
  $("o-changes").textContent = changeText(d.changes);
  $("f-list").replaceChildren(...(d.top.length ? d.top.map(f => el("div", {class: "frow"},
      el("span", {class: `sev ${f.severity}`}, f.severity === "medium" ? "Med" : f.severity === "critical" ? "Crit" : f.severity),
      el("div", {}, el("b", {}, f.title), el("span", {}, `${f.asset} · ${AGENT_NAMES[f.layer] || f.layer || ""}`)),
      el("span", {class: "id"}, f.ranked ? el("span", {class: `prio p${f.priority}`}, `P${f.priority}`) : "", f.kev ? el("span", {class: "tag error"}, "KEV") : "", " ", f.id || "")))
    : [el("p", {class: "note"}, d.score != null ? "Nothing open. Well done." : "Findings appear after an AI assessment.")]));
  $("i-body").replaceChildren(...d.inventory.map(r => el("tr", {}, el("td", {}, r.name), el("td", {class: "m"}, r.type), el("td", {class: "m"}, "." + r.ip.split(".").pop()),
    el("td", {}, el("span", {class: `dotc bg-${r.risk}`}), r.risk === "ok" ? "OK" : r.risk[0].toUpperCase() + r.risk.slice(1)))));
  $("i-note").textContent = `${d.devices} devices · riskiest ${d.inventory.length} shown`;
}

function changeText(ch) {
  if (!ch) return "";
  const s = ch.scan, f = ch.findings, bits = [];
  if (s) {
    for (const [k, w] of [["new_devices", "new device"], ["gone_devices", "device gone"], ["new_ports", "new open port"],
                          ["new_internet_ports", "new internet port"], ["new_forwards", "new port forward"]])
      if ((s[k] || []).length) bits.push(`${s[k].length} ${w}${s[k].length > 1 && !w.endsWith("gone") ? "s" : ""}`);
  }
  if (f) {
    if (f.new.length) bits.push(`${f.new.length} new finding${f.new.length > 1 ? "s" : ""}`);
    if (f.not_seen_again.length) bits.push(`${f.not_seen_again.length} not found again`);
  }
  const against = (s && s.against) || (f && f.against);
  return against ? `Since ${fmtRun(against)}: ${bits.length ? bits.join(" · ") : "no changes"}` : "";
}

// the report is a sandboxed page: it gets the account's theme and light/dark mode in its address
function themeHash() { const t = Theme.get(); return `#theme=${t.theme}&scheme=${t.scheme}`; }
Theme.onChange(() => {
  for (const id of ["frame", "newtab"]) {
    const e = $(id), attr = id === "frame" ? "src" : "href", u = e.getAttribute(attr);
    if (u) e.setAttribute(attr, u.split("#")[0] + themeHash());
  }
});

function openRun(id, hasReport) {
  current = id;
  loadOverview(id);
  document.querySelectorAll(".run").forEach(n => n.classList.toggle("on", n.querySelector(".mono")?.textContent === fmtRun(id)));
  $("current").textContent = `run ${fmtRun(id)}`;
  if (typeof Agents !== "undefined") Agents.show(id);
  if (typeof Plan !== "undefined") Plan.show(id);
  const url = `/api/runs/${id}/report` + themeHash();
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

function renderSide(s) {
  const busy = s.running;
  const pct = !s.mode ? 0 : busy ? Math.round((s.step - 0.5) / s.steps.length * 100) : 100;
  $("r-ring").setAttribute("stroke-dashoffset", String(176 - 176 * pct / 100));
  $("r-pct").replaceChildren(busy ? String(pct) : s.mode ? "Done" : "Idle", busy ? el("small", {}, "%") : "");
  $("r-step").textContent = busy ? `Step ${s.step} of ${s.steps.length} · ${s.steps[s.step - 1]}` : s.mode ? `${s.label} ${s.stopped ? "stopped" : s.exit_code === 0 ? "finished" : "failed"}` : "Nothing running";
  $("r-label").textContent = s.label || "—";
  $("r-elapsed").replaceChildren(s.started ? String(mins(((busy ? Date.now() / 1000 : s.ended) || s.started) - s.started)) : "—", s.started ? el("small", {}, " min") : "");
  $("r-by").textContent = s.by || "—";
  $("r-stop").classList.toggle("hidden", !busy || !me || me.role === "viewer");
}

function renderJob(s) {
  const busy = s.running;
  renderSide(s);
  if (typeof Agents !== "undefined") Agents.follow(s);
  for (const b of ["go-collect", "go-full"]) $(b).disabled = busy;
  document.querySelectorAll(".run .btn").forEach(b => { if (b.tagName === "BUTTON" && !["Report", "Agent map"].includes(b.textContent)) b.disabled = busy; });
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

// Anthropic keys expire (Claude Console); Guardian can't read the date from the key, so an admin enters it in Settings › AI.
function keyWarning(c) {
  const exp = c && c.anthropic_key_expires, box = $("key-warn");
  const days = exp ? Math.ceil((new Date(exp + "T23:59:59") - Date.now()) / 86400000) : null;
  box.classList.toggle("hidden", days === null || days > 30);
  if (days === null || days > 30) return;
  box.textContent = days < 0 ? `The Anthropic API key expired on ${exp}: AI assessments, re-checks and chat stop working. Create a new key in the Claude Console and paste it in Settings › AI agents.`
    : `The Anthropic API key expires in ${days} day${days === 1 ? "" : "s"} (${exp}). Create a new key in the Claude Console and paste it in Settings › AI agents before then.`;
}

async function poll() {
  clearTimeout(polling);
  try {
    const s = await api(`/api/job?since=${seq}`);
    if (s.lines.length) { appendLog(s.lines); seq = s.seq; }
    renderJob(s);
    if (s.running) { polling = setTimeout(poll, 2000); return; }
    const o = await api("/api/overview");
    renderRuns(siteRuns(o), o.job);
    keyWarning(o.config);
    if (s.run_id && s.exit_code === 0) {
      const r = o.runs.find(x => x.id === s.run_id);
      if (r && r.has_report && s.mode !== "collect") openRun(r.id, true);
    }
  } catch (err) { polling = setTimeout(poll, 5000); }
}

// -- tabs, theme, start-up ----------------------------------------------------------
function showTab(t) {
  document.querySelectorAll(".tab").forEach(b => b.classList.toggle("on", b.dataset.t === t));
  for (const p of ["report", "plan", "paths", "attack", "comp", "agents", "map", "log"]) $("p-" + p).classList.toggle("hidden", t !== p);
  if (["plan", "paths", "attack", "comp"].includes(t) && typeof Plan !== "undefined") Plan.refresh(t);
  if ((t === "agents" || t === "map") && typeof Agents !== "undefined") Agents.refresh();
  if (t === "log") $("p-log").scrollTop = $("p-log").scrollHeight;
}
document.querySelectorAll(".tab").forEach(b => b.addEventListener("click", () => showTab(b.dataset.t)));
$("refresh").addEventListener("click", () => poll());

// -- rail and shortcuts -------------------------------------------------------------------
function go(where) {
  document.querySelectorAll(".rail .ri[data-go]").forEach(b => b.classList.toggle("on", b.dataset.go === where));
  if (where === "overview") { scrollTo({top: 0, behavior: "smooth"}); return; }
  showTab(where);
  $("workspace").scrollIntoView({behavior: "smooth", block: "start"});
}
document.querySelectorAll(".rail .ri[data-go]").forEach(b => b.addEventListener("click", () => go(b.dataset.go)));
$("go-report").addEventListener("click", async () => {
  const o = await api("/api/overview"); const r = siteRuns(o).find(x => x.has_report);
  if (!r) { alert("No report yet. Run an AI assessment first."); return; }
  openRun(r.id, true); go("report");
});
$("go-replay").addEventListener("click", () => { go("map"); setTimeout(() => { const b = $("m-replay"); if (!b.classList.contains("hidden")) b.click(); }, 400); });
$("r-stop").addEventListener("click", () => $("stop").click());

async function start() {
  await refreshMe();
  const n = sessionStorage.getItem("guardian-note"); if (n) { note(n); sessionStorage.removeItem("guardian-note"); }
  const o = await api("/api/overview");
  setSites(o.sites || []);
  const runs = siteRuns(o);
  renderRuns(runs, o.job);
  const latest = runs.find(r => r.has_report);
  if (SITE === "all") { /* the portfolio is the page */ }
  else if (latest) openRun(latest.id, true);
  else if (runs.length) openRun(runs[0].id, false);
  const s = await api("/api/job?since=0");
  if (s.lines.length) { appendLog(s.lines); seq = s.seq; }
  renderJob(s);
  if (s.running) { showTab("log"); poll(); }
}
start();
setTimeout(() => me && me.role !== "viewer" && fetch("/api/connectors").then(r => r.ok ? r.json() : null).then(d => {
  if (d && d.suggestions.length) { $("set-count").textContent = d.suggestions.length; $("set-count").classList.remove("hidden"); }
}).catch(() => {}), 500);
