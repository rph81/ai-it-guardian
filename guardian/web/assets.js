"use strict";
// Assets: the site's lasting device list (merged across runs and sources).
const $ = id => document.getElementById(id);
async function api(path) {
  const r = await fetch(path);
  if (r.status === 401) { location.replace("/signin"); throw new Error("Sign in first"); }
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
const day = t => (t || "").slice(0, 10);
const FILTERS = [["all", "All"], ["new", "New this week"], ["stale", "Not seen for 30 days"], ["p12", "With P1–P2"], ["single", "Only in one source"]];
const S = {site: "local", data: null, filter: "all", open: null};

function keep(a) {
  if (S.filter === "new" && !a.new) return false;
  if (S.filter === "stale" && !a.stale) return false;
  if (S.filter === "p12" && !(a.open["1"] || a.open["2"])) return false;
  if (S.filter === "single" && Object.keys(a.sources).length !== 1) return false;
  const q = $("as-q").value.trim().toLowerCase();
  return !q || [a.name, ...a.ips, ...a.macs, a.os, a.type, a.vendor, a.model].some(x => (x || "").toLowerCase().includes(q));
}

function detail(a) {
  return el("tr", {class: "as-detail"}, el("td", {colspan: "7"},
    el("div", {class: "row"}, ...Object.entries(a.sources).map(([s, t]) => el("span", {class: "tag"}, `${s} · ${day(t)}`))),
    el("p", {class: "note"}, [a.ips.length ? `IP ${a.ips.join(", ")}` : "", a.macs.length ? `MAC ${a.macs.join(", ")}` : "",
      a.vendor ? `vendor ${a.vendor}` : "", a.model ? `model ${a.model}` : "", a.firmware ? `firmware ${a.firmware}` : "",
      `seen in ${a.runs.length} assessment(s): ${a.runs.slice(-5).join(", ")}`].filter(Boolean).join(" · "))));
}

function render() {
  const d = S.data, rows = d.assets.filter(keep);
  $("as-filters").replaceChildren(...FILTERS.map(([k, label]) => el("button", {type: "button", "aria-pressed": String(k === S.filter),
    onclick: () => { S.filter = k; render(); }}, `${label} · ${d.counts[k] ?? 0}`)));
  $("as-updated").textContent = d.updated ? `updated ${d.updated.replace("T", " ").slice(0, 16)}` : "";
  const out = [];
  for (const a of rows) {
    const open = ["1", "2", "3", "4"].filter(p => a.open[p]).map(p => el("span", {class: "tag" + (p === "1" ? " error" : p === "2" ? " warn" : "")}, `P${p} · ${a.open[p]}`));
    out.push(el("tr", {class: "as-row", tabindex: "0", onclick: () => { S.open = S.open === a.id ? null : a.id; render(); },
                       onkeydown: e => { if (e.key === "Enter") { S.open = S.open === a.id ? null : a.id; render(); } }},
      el("td", {}, el("b", {}, a.name || a.ips[0] || "?"), el("div", {class: "mini mono"}, [a.ips[0], a.macs[0]].filter(Boolean).join(" · ") || "no address")),
      el("td", {}, a.type || "—"), el("td", {}, [a.os, a.firmware && `firmware ${a.firmware}`].filter(Boolean).join(" · ") || "—"),
      el("td", {}, ...Object.keys(a.sources).map(s => el("span", {class: "tag"}, s))),
      el("td", {}, day(a.first_seen), a.new ? el("span", {class: "tag new"}, "new") : null),
      el("td", {}, a.stale ? el("span", {class: "tag warn"}, day(a.last_seen)) : day(a.last_seen)),
      el("td", {}, ...(open.length ? open : [document.createTextNode("—")]))));
    if (S.open === a.id) out.push(detail(a));
  }
  $("as-rows").replaceChildren(...out);
  $("as-empty").textContent = d.assets.length ? (rows.length ? "" : "Nothing matches.") : "No devices yet: they appear after the first assessment of this site.";
}

async function load() {
  try { S.data = await api(`/api/sites/${encodeURIComponent(S.site)}/assets`); render(); }
  catch (e) { $("as-empty").textContent = e.message; }
}

(async () => {
  try { S.site = localStorage.getItem("guardian-site") || "local"; } catch (e) { /* storage blocked */ }
  let sites = [];
  try { sites = (await api("/api/overview")).sites || []; } catch (e) { /* signed out */ }
  if (S.site === "all" || !sites.some(s => s.id === S.site)) S.site = (sites[0] || {}).id || "local";
  $("as-site").replaceChildren(...sites.map(s => el("option", {value: s.id, selected: s.id === S.site}, s.name)));
  $("as-site").addEventListener("change", e => { S.site = e.target.value; try { localStorage.setItem("guardian-site", S.site); } catch (err) { /* storage blocked */ } load(); });
  $("as-q").addEventListener("input", () => S.data && render());
  load();
})();
