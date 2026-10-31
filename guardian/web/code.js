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
const when = t => t ? new Date(t * 1000).toLocaleString([], {dateStyle: "short", timeStyle: "short"}) : "";
const SEV = ["critical", "high", "medium", "low", "info"];
const STAGES = {fetch: "Fetch", unpack: "Unpack", static: "Static checks", deps: "Dependencies", ai: "AI review", report: "Report"};
const WORDS = {malicious: "Malicious", suspicious: "Suspicious", review: "Review", clean: "No issues"};
const CHECKS = [
  ["install", "Install-time scripts", "npm install hooks, setup.py"],
  ["obfuscation", "Hidden or obfuscated code", "eval of decoded strings, encoded blobs, scrambled JavaScript"],
  ["network", "Outbound connections", "hard-coded IPs, webhooks, paste sites, download-and-run"],
  ["credentials", "Credential theft", "SSH, cloud and registry credentials, browser data, wallets, environment"],
  ["secrets", "Leaked secrets", "API keys, tokens and private keys in the code"],
  ["deps", "Dependencies", "look-alike names, git/URL sources, known vulnerabilities and malware (OSV)"],
  ["actions", "GitHub Actions", "pull_request_target with PR code, script injection, unpinned actions"],
  ["binaries", "Binaries", "executables and compiled files that can't be read"],
  ["persistence", "Persistence", "cron, services, login items, shell profile edits"],
  ["manipulation", "Attempts to fool the review", "text addressed to scanners or AI reviewers"],
  ["signals", "Repository signals", "new accounts, new repositories, archived projects"],
  ["iac", "Infrastructure as code", "Terraform, Kubernetes, Dockerfiles, Bicep / ARM: open firewalls, public storage, privileged containers, secrets"],
];
let ov = null, scan = null, shown = null, filter = "all", timer = null;
const canRun = () => ov && ov.role !== "viewer";

function renderPipe(d) {
  $("pipe").classList.remove("hidden");
  $("pipe").replaceChildren(...Object.entries(STAGES).map(([k, label]) => {
    const st = (d.stages || {})[k] || {state: "waiting", text: ""};
    return el("div", {class: "cs-st " + st.state}, label, el("small", {}, st.text || (st.state === "waiting" ? "Waiting" : "")));
  }));
}

function code(lines) {
  return el("pre", {class: "cs-code"}, ...lines.map(([n, t, hit]) => el("span", {"data-n": String(n), class: hit ? "hit" : null}, t)));
}

function live(f) { return !f.dismissed && !(f.ai && f.ai.verdict === "false_positive"); }

function renderResult(d) {
  const done = d.status !== "running";
  $("res").classList.toggle("hidden", !done || d.status === "failed");
  if (!done || d.status === "failed") return;
  const v = d.verdict || {word: "clean", text: ""};
  $("rname").textContent = `${d.repo} @ ${(d.sha || "").slice(0, 7)}`;
  $("vbox").className = "cs-vbox " + v.word;
  $("vby").textContent = v.by === "ai" ? "Code agent's verdict" : "Static checks only";
  $("vword").textContent = WORDS[v.word] || v.word;
  $("vtext").textContent = v.text;
  const counts = {};
  for (const f of d.findings) if (live(f)) counts[f.sev] = (counts[f.sev] || 0) + 1;
  $("sevs").replaceChildren(...SEV.filter(s => counts[s]).map(s => el("span", {class: s}, el("i"), `${counts[s]} ${s}`)));
  const fx = d.facts || {};
  const facts = [[fx.files ?? "-", "Files"], [fx.read ?? "-", "Read as text"], ["0", "Executed"],
                 [fx.dependencies ?? "-", "Dependencies"], [fx.cves ?? (d.deps_requested ? "0" : "-"), "Known CVEs"],
                 [d.cost ? `$${d.cost.toFixed(2)}` : "$0", "AI cost"]];
  $("facts").replaceChildren(...facts.map(([b, s]) => el("div", {}, el("b", {}, String(b)), el("span", {}, s))));
  const m = d.meta || {};
  const bits = [m.description, m.stars != null && `${m.stars} stars`, m.license && `licence ${m.license}`, m.fork_of && `fork of ${m.fork_of}`,
                m.created && `created ${m.created.slice(0, 10)}`, m.commit_date && `commit ${m.commit_date.slice(0, 10)}`, d.by && `scanned by ${d.by}`, when(d.started)];
  $("meta").replaceChildren(...bits.filter(Boolean).map(t => el("span", {}, t)));
  $("download").href = `/api/code/${d.id}?download=1`;
  const all = d.findings.length;
  const present = SEV.filter(s => d.findings.some(f => f.sev === s));
  if (filter !== "all" && !present.includes(filter)) filter = "all";
  $("filter").replaceChildren(...["all", ...present].map(s => el("button", {type: "button", "aria-pressed": String(s === filter),
    onclick: () => { filter = s; renderResult(d); }}, s === "all" ? `All · ${all}` : `${s} · ${d.findings.filter(f => f.sev === s).length}`)));
  const list = d.findings.filter(f => filter === "all" || f.sev === filter);
  $("findings").replaceChildren(...(list.length ? list.map((f, i) => finding(d, f, i === 0 && live(f) && SEV.indexOf(f.sev) <= 1))
    : [el("p", {class: "note"}, "No findings.")]));
  $("checks").replaceChildren(...CHECKS.map(([g, t, s]) => el("li", {class: (d.checks || {})[g] ? "flag" : ""},
    el("span", {}, el("b", {}, t), el("br"), el("small", {}, s)), (d.checks || {})[g] ? el("span", {class: "tag warn"}, String(d.checks[g])) : el("span"))));
}

function finding(d, f, open) {
  const loc = f.path ? `${f.path}${f.line ? ":" + f.line : ""}` : "";
  const body = el("div", {class: "cs-fb"});
  if (f.evidence && f.evidence.length) body.append(code(f.evidence));
  if (f.files && f.files.length) body.append(el("ul", {class: "cs-list"}, ...f.files.map(t => el("li", {}, t))));
  body.append(el("dl", {class: "kv"}, el("dt", {}, "Why it matters"), el("dd", {}, f.why), el("dt", {}, "What to do"), el("dd", {}, f.fix)));
  if (f.ai && f.ai.note) body.append(el("div", {class: "cs-ai"}, el("b", {}, f.ai.verdict === "false_positive" ? "Code agent · false positive" : "Code agent"), f.ai.note));
  if (canRun()) body.append(el("div", {class: "row mt16"}, el("button", {class: "btn sm", type: "button", onclick: () => dismiss(d, f)},
    f.dismissed ? "Restore finding" : "Mark as false positive"), f.dismissed ? el("span", {class: "note m0"}, `Marked by ${f.dismissed_by || "someone"}`) : null));
  const sum = el("summary", {}, el("span", {class: "tag sev-" + f.sev}, f.sev),
    el("div", {}, el("h3", {}, f.title), loc ? el("div", {class: "loc"}, loc) : null),
    el("div", {class: "cs-how"}, ...f.how.map(h => el("span", {class: "tag"}, h)), f.dismissed ? el("span", {class: "tag"}, "dismissed") : null));
  return el("details", {class: `cs-f ${f.sev}${live(f) ? "" : " off"}`, open}, sum, body);
}

function renderHistory() {
  $("history").replaceChildren(...(ov.scans.length ? ov.scans.map(s => el("tr", {class: "cs-click", tabindex: "0", onclick: () => show(s.id, true),
    onkeydown: e => { if (e.key === "Enter") show(s.id, true); }},
    el("td", {}, el("b", {}, s.repo || "")), el("td", {class: "mono"}, s.sha || ""), el("td", {}, when(s.started)), el("td", {}, s.by || ""),
    el("td", {}, s.status === "done" ? el("span", {class: "tag v-" + s.verdict}, WORDS[s.verdict] || s.verdict) : el("span", {class: "tag" + (s.status === "failed" ? " error" : "")}, s.status)),
    el("td", {}, SEV.filter(k => s.counts[k]).map(k => `${s.counts[k]} ${k}`).join(" · ") || (s.status === "done" ? "none" : s.error || "")),
    el("td", {}, s.cost ? `$${s.cost.toFixed(2)}` : "-"))) : [el("tr", {}, el("td", {colspan: "7", class: "note"}, "No scans yet."))]));
}

async function show(id, jump) {
  const was = scan && scan.id === id ? scan.status : null;
  shown = id;
  try { scan = await api(`/api/code/${id}`); } catch (e) { $("err").textContent = e.message; return; }
  renderPipe(scan);
  $("err").textContent = scan.status === "failed" ? `Scan failed: ${scan.error || "unknown error"}` : "";
  renderResult(scan);
  clearTimeout(timer);
  if (scan.status === "running") timer = setTimeout(() => show(id), 1500);
  else if (ov && ov.running === id) load();
  if (scan.status === "done" && (jump || was === "running")) $("res").scrollIntoView({behavior: "smooth", block: "start"});
}

async function dismiss(d, f) {
  try { await api(`/api/code/${d.id}/findings/${f.n}`, {dismissed: !f.dismissed}); await show(d.id); load(true); }
  catch (e) { alert(e.message); }
}

async function start(url, ref) {
  $("err").textContent = "";
  try {
    const r = await api("/api/code/scan", {url, ref: ref || null, ai: $("opt-ai").checked, deps: $("opt-deps").checked});
    $("res").classList.add("hidden");
    await load(true);
    show(r.id);
  } catch (e) { $("err").textContent = e.message; }
}

$("form").addEventListener("submit", e => { e.preventDefault(); start($("url").value.trim(), $("ref").value.trim()); });
$("rescan").addEventListener("click", () => { if (scan) start(scan.url, scan.ref); });
$("stop").addEventListener("click", async () => { try { await api("/api/code/stop", {}); } catch (e) { alert(e.message); } load(true); });

async function load(quiet) {
  try { ov = await api("/api/code"); }
  catch (e) { $("note").textContent = e.message; $("note").classList.remove("hidden"); return; }
  const busy = !!ov.running;
  $("scan").disabled = busy || !canRun();
  $("stop").classList.toggle("hidden", !busy || !canRun());
  $("ai-note").textContent = !canRun() ? "Operators and admins can start scans." : ov.ai_ready ? "The AI review uses your Anthropic key and usually costs $0.10–$1 per repository."
    : ov.unlocked ? "No Anthropic API key yet: scans run the static and dependency checks only." : "The vault is locked: scans run the static and dependency checks only. Unlock it to add the AI review.";
  document.querySelectorAll(".op-only").forEach(e => e.classList.toggle("hidden", !canRun()));
  renderHistory();
  if (!quiet && !shown) {
    if (ov.running) show(ov.running);
    else if (ov.scans[0]) show(ov.scans[0].id);
    else $("checks").replaceChildren(...CHECKS.map(([g, t, s]) => el("li", {class: "idle"}, el("span", {}, el("b", {}, t), el("br"), el("small", {}, s)), el("span"))));
  }
}
(async () => {
  try { const me = await api("/api/me"); if (me.prefs && me.prefs.theme) Theme.set(me.prefs); } catch (e) { /* signed out: api() redirects */ }
  await load();
  setInterval(() => load(true), 15000);
})();
