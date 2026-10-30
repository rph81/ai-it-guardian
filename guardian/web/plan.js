"use strict";
// Fix plan (remediation tracking), Attack paths and Compliance tabs. Uses $, el, api, me, unlock and fmtRun from console.js.
const Plan = (() => {
  const S = {run: null, tracking: null, paths: null, comp: null, filter: "open", fw: "cis_ig1", cfilter: "all"};
  const STATUS = {open: "Open", in_progress: "In progress", fixed: "Fixed (to verify)", accepted: "Risk accepted", verified: "Verified fixed"};
  const CSTAT = {met: "Met", partial: "Partly", gap: "Gap", not_assessed: "Not assessed"};
  const STAGE = {entry: "Entry", foothold: "Foothold", move: "Move", escalate: "Escalate", target: "Target"};
  const canEdit = () => me && me.role !== "viewer";
  const today = () => new Date().toISOString().slice(0, 10);

  function show(id) { S.run = id; S.tracking = S.paths = S.comp = null; }

  async function refresh(tab) {
    if (!S.run) return;
    try {
      if (tab === "plan") { S.tracking = await api(`/api/runs/${S.run}/tracking`); renderPlan(); }
      if (tab === "paths") { S.paths = await api(`/api/runs/${S.run}/paths`); renderPaths(); }
      if (tab === "comp") { S.comp = await api(`/api/runs/${S.run}/compliance`); renderComp(); }
    } catch (e) { /* the run may have no data yet */ }
  }

  // -- fix plan --------------------------------------------------------------------------------
  function renderPlan() {
    const t = S.tracking, rows = t.rows;
    $("pl-meta").textContent = `${t.counts.open} open · ${t.counts.overdue} overdue · ${t.counts.verified} verified fixed` +
      (t.ranked ? "" : " · not ranked yet: priorities come from severity until the Risk analyst runs");
    const F = {open: r => ["open", "in_progress"].includes(r.status), overdue: r => r.overdue, p1: r => r.priority <= 2 && !["verified", "accepted"].includes(r.status),
               done: r => ["fixed", "verified", "accepted"].includes(r.status), all: () => true};
    const L = {open: "Open", overdue: "Overdue", p1: "Priority 1–2", done: "Done", all: "All"};
    $("pl-filter").replaceChildren(el("div", {class: "seg"}, ...Object.keys(F).map(k => el("button", {type: "button", "aria-pressed": String(S.filter === k),
      onclick: () => { S.filter = k; renderPlan(); }}, `${L[k]} · ${rows.filter(F[k]).length}`))));
    const list = rows.filter(F[S.filter]);
    $("pl-rows").replaceChildren(...(list.length ? list.map(row) : [el("p", {class: "note"}, rows.length ? "Nothing here." : "Findings appear after an AI assessment.")]));
  }

  function row(r) {
    const chips = el("div", {class: "row"}, el("span", {class: `prio p${r.priority}`}, `P${r.priority}`),
      el("span", {class: `sev ${r.severity}`}, r.severity), r.kev ? el("span", {class: "tag error"}, "Actively exploited") : null,
      r.ransomware ? el("span", {class: "tag error"}, "Ransomware") : null,
      r.epss != null ? el("span", {class: "tag"}, `EPSS ${(r.epss * 100).toFixed(r.epss < 0.01 ? 2 : 0)}%`) : null,
      r.exposure ? el("span", {class: "tag"}, r.exposure) : null, el("span", {class: "tag"}, STATUS[r.status] || r.status),
      r.overdue ? el("span", {class: "tag error"}, "Overdue") : null, r.carried_from ? el("span", {class: "tag new"}, "carried over") : null);
    const head = el("div", {class: "pl-head"}, el("div", {}, el("b", {}, r.title), el("div", {class: "meta"}, `${r.id} · ${r.asset} · first seen ${r.first_seen}`)), chips);
    const body = el("div", {class: "pl-body"});
    if (r.reason) body.append(el("p", {class: "pl-why"}, el("b", {}, "Why this priority: "), r.reason));
    if (r.recommendation) body.append(el("p", {class: "note"}, el("b", {}, "Fix: "), r.recommendation));
    if (canEdit() && r.status !== "verified") {
      const owner = el("input", {value: r.owner || "", placeholder: "Owner", maxlength: "80", "aria-label": "Owner"});
      const due = el("input", {type: "date", value: r.due || "", "aria-label": "Due date"});
      const st = el("select", {"aria-label": "Status"}, ...["open", "in_progress", "fixed", "accepted"].map(k => {
        const o = el("option", {value: k}, STATUS[k]); if (k === r.status) o.selected = true; return o; }));
      const nt = el("input", {value: r.note || "", placeholder: "Note", maxlength: "300", "aria-label": "Note", class: "grow"});
      const save = el("button", {class: "btn sm primary", type: "button", onclick: async () => {
        try { await api(`/api/runs/${S.run}/tracking/${r.id}`, {owner: owner.value, due: due.value || null, status: st.value, note: nt.value}); refresh("plan"); }
        catch (e) { alert(e.message); } }}, "Save");
      const re = el("button", {class: "btn sm", type: "button", onclick: () => recheck(r)}, "Re-check");
      body.append(el("div", {class: "pl-edit"}, owner, due, st, nt, save, re));
      if (r.recheck) body.append(el("p", {class: "micro"}, `Re-check asked by ${r.recheck.by} ${new Date(r.recheck.at * 1000).toLocaleString()}`));
    } else {
      body.append(el("p", {class: "meta"}, `Owner: ${r.owner || "—"} · due ${r.due || "—"}` + (r.note ? ` · ${r.note}` : "")));
    }
    return el("details", {class: `pl-row p${r.priority}` + (r.overdue ? " late" : "")}, el("summary", {}, head), body);
  }

  async function recheck(r) {
    if (!confirm(`Send ${r.id} back to the agent that found it for a read-only re-check?\n\nThis starts a short follow-up run and uses your API credit.`)) return;
    const go = () => api(`/api/runs/${S.run}/findings/${r.id}/recheck`, {});
    try {
      try { await go(); }
      catch (e) { if (!/Unlock the vault/.test(e.message) || !confirm(e.message + "\n\nUnlock now?") || !await unlock()) throw e; await go(); }
      showTab("log"); poll();
    } catch (e) { alert(e.message); }
  }

  // -- attack paths ----------------------------------------------------------------------------
  function renderPaths() {
    const d = S.paths;
    $("ap-meta").textContent = d.paths.length ? `${d.paths.length} path${d.paths.length > 1 ? "s" : ""}` : "";
    if (!d.paths.length) {
      $("ap-list").replaceChildren(el("p", {class: "note"}, d.analysed ? "The Attack paths agent found no realistic path in this run's findings." : "Attack paths appear after an AI assessment."));
      return;
    }
    const fref = id => { const f = d.findings[id]; return f ? el("span", {class: "micro"}, `${id} · P${f.priority} · ${f.title}`) : null; };
    $("ap-list").replaceChildren(...d.paths.map(p => el("div", {class: "ap"},
      el("div", {class: "row"}, el("span", {class: `tag ${p.likelihood === "high" ? "error" : p.likelihood === "medium" ? "warn" : ""}`}, `${p.likelihood} likelihood`),
        el("span", {class: "tag"}, p.id), el("b", {}, p.title)),
      el("p", {class: "note"}, "Ends at: ", el("b", {}, p.target)),
      el("div", {class: "ap-steps"}, ...p.steps.map(s => el("div", {class: "ap-step" + (p.choke_points.some(c => c.finding && c.finding === s.finding) ? " choke" : "")},
        el("b", {}, STAGE[s.stage] || s.stage), s.asset ? el("span", {class: "micro"}, s.asset) : null, el("span", {}, s.text), s.finding ? fref(s.finding) : null))),
      p.choke_points.length ? el("div", {class: "ap-choke"}, el("b", {}, "Choke points: "),
        ...p.choke_points.map(c => el("div", {}, "• ", c.fix, c.finding ? ` (${c.finding})` : ""))) : null,
      el("p", {class: "note"}, p.summary))));
  }

  // -- compliance --------------------------------------------------------------------------------
  function renderComp() {
    const d = S.comp, fw = d.frameworks[S.fw];
    $("co-meta").textContent = d.analysed ? "" : "Not mapped yet: runs after the next AI assessment";
    $("co-tabs").replaceChildren(el("div", {class: "seg"}, ...Object.entries(d.frameworks).map(([k, v]) => el("button", {type: "button",
      "aria-pressed": String(k === S.fw), onclick: () => { S.fw = k; S.cfilter = "all"; renderComp(); }}, v.title))));
    const n = fw.controls.length;
    $("co-bar").replaceChildren(...["met", "partial", "gap", "not_assessed"].map(s => {
      const i = el("i", {class: `cb-${s}`, title: `${CSTAT[s]}: ${fw.counts[s]}`}); i.style.setProperty("width", `${fw.counts[s] / n * 100}%`); return i; }));
    $("co-filter").replaceChildren(el("div", {class: "seg"}, ...["all", "gap", "partial", "met", "not_assessed"].map(s => el("button", {type: "button",
      "aria-pressed": String(S.cfilter === s), onclick: () => { S.cfilter = s; renderComp(); }}, `${s === "all" ? "All" : CSTAT[s]} · ${s === "all" ? n : fw.counts[s]}`))));
    const list = fw.controls.filter(c => S.cfilter === "all" || c.status === S.cfilter);
    $("co-list").replaceChildren(...list.map(c => el("div", {class: `co-row cs-${c.status}`},
      el("div", {class: "co-id"}, c.id), el("div", {}, el("b", {}, c.title), el("div", {class: "note m0"}, c.note || ""),
        c.findings.length ? el("div", {class: "micro"}, c.findings.map(f => `${f} ${d.findings[f] || ""}`).join(" · ")) : null),
      el("span", {class: `tag co-${c.status}`}, CSTAT[c.status]))));
  }

  return {show, refresh};
})();
