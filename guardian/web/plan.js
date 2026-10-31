"use strict";
// Fix plan (remediation tracking), Attack paths and Compliance tabs. Uses $, el, api, me, unlock and fmtRun from console.js.
const Plan = (() => {
  const S = {run: null, tracking: null, paths: null, attack: null, pick: null, comp: null, filter: "open", fw: "cis_ig1", cfilter: "all"};
  const STATUS = {open: "Open", in_progress: "In progress", fixed: "Fixed (to verify)", accepted: "Risk accepted", verified: "Verified fixed"};
  const CSTAT = {met: "Met", partial: "Partly", gap: "Gap", not_assessed: "Not assessed"};
  const STAGE = {entry: "Entry", foothold: "Foothold", move: "Move", escalate: "Escalate", target: "Target"};
  const canEdit = () => me && me.role !== "viewer";
  const today = () => new Date().toISOString().slice(0, 10);

  function show(id) { S.run = id; S.tracking = S.paths = S.attack = S.comp = S.pick = null; }

  async function refresh(tab) {
    if (!S.run) return;
    try {
      if (tab === "plan") { S.tracking = await api(`/api/runs/${S.run}/tracking`); renderPlan(); }
      if (tab === "paths") { S.paths = await api(`/api/runs/${S.run}/paths`); renderPaths(); }
      if (tab === "attack") { S.attack = await api(`/api/runs/${S.run}/attack`); renderAttack(); }
      if (tab === "comp") { S.comp = await api(`/api/runs/${S.run}/compliance`); renderComp(); }
    } catch (e) { /* the run may have no data yet */ }
  }

  // -- fix plan --------------------------------------------------------------------------------
  function renderPlan() {
    if (!$("pl-import").childElementCount) { const p = importPanel(); if (p) $("pl-import").append(p); }
    const t = S.tracking, rows = t.rows;
    $("pl-meta").textContent = `${t.counts.open} open · ${t.counts.overdue} overdue · ${t.counts.verified} verified fixed` +
      (t.ranked ? "" : " · not ranked yet: priorities come from severity until the Risk analyst runs");
    const F = {open: r => ["open", "in_progress"].includes(r.status), overdue: r => r.overdue, p1: r => r.priority <= 2 && !["verified", "accepted"].includes(r.status),
               done: r => ["fixed", "verified", "accepted"].includes(r.status), all: () => true};
    const L = {open: "Open", overdue: "Overdue", p1: "Priority 1–2", done: "Done", all: "All"};
    $("pl-filter").replaceChildren(...[el("div", {class: "seg"}, ...Object.keys(F).map(k => el("button", {type: "button", "aria-pressed": String(S.filter === k),
      onclick: () => { S.filter = k; renderPlan(); }}, `${L[k]} · ${rows.filter(F[k]).length}`))),
      rows.some(r => r.ticket) && canEdit() ? el("button", {class: "btn sm", type: "button", onclick: async () => {
        try { const x = await api(`/api/runs/${S.run}/tickets/sync`, {}); alert(`Tickets synced: ${x.updated} updated.`); refresh("plan"); }
        catch (e) { alert(e.message); } }}, "Sync tickets") : null].filter(Boolean));
    const list = rows.filter(F[S.filter]);
    $("pl-rows").replaceChildren(...(list.length ? list.map(row) : [el("p", {class: "note"}, rows.length ? "Nothing here." : "Findings appear after an AI assessment.")]));
  }

  // -- import of another scanner's report ------------------------------------------------------------
  function importPanel() {
    if (!canEdit()) return null;
    const file = el("input", {type: "file", accept: ".nessus,.xml,.csv", "aria-label": "Scanner report"});
    const out = el("div", {class: "note"});
    const send = async commit => {
      const f = file.files[0];
      if (!f) { out.textContent = "Choose a file first."; return null; }
      const r = await fetch(`/api/runs/${S.run}/import?commit=${commit}`, {method: "POST", body: f, headers: {"X-Guardian": "1",
        "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(f.name)}});
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || `Failed (${r.status})`);
      return d;
    };
    const go = el("button", {class: "btn sm primary", type: "button", disabled: true, onclick: async () => {
      try { const d = await send(1); out.textContent = `Imported: ${d.added} new finding(s), ${d.merged} merged into existing ones.`; go.disabled = true; refresh("plan"); }
      catch (e) { out.textContent = e.message; } }}, "Import");
    const pre = el("button", {class: "btn sm", type: "button", onclick: async () => {
      out.textContent = "Reading…"; go.disabled = true;
      try {
        const d = await send(0);
        const sev = Object.entries(d.by_severity).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(", ");
        out.replaceChildren(el("b", {}, `${d.format}: ${d.findings} finding(s) on ${d.devices} device(s)`),
          ` (${sev || "none"}${d.new_devices ? `; ${d.new_devices} device(s) Guardian hasn't seen` : ""}). Duplicates of Guardian's findings are merged on import.`);
        go.disabled = !d.findings;
      } catch (e) { out.textContent = e.message; } }}, "Preview");
    file.addEventListener("change", () => { go.disabled = true; out.textContent = ""; });
    return el("details", {class: "co-export"}, el("summary", {}, "Import results from another scanner"),
      el("p", {class: "note"}, "Nessus (.nessus), OpenVAS / Greenbone, Qualys or Rapid7 InsightVM XML, or a CSV with ip, title, severity and optionally cve, port, description, solution. Up to 50 MB."),
      el("div", {class: "row mt16"}, file, pre, go), out, pullRow());
  }

  // pull open findings straight from a scanner connector (Tenable, Qualys, Rapid7) of this site
  function pullRow() {
    const box = el("div", {class: "mt16"});
    const out = el("div", {class: "note"});
    const pick = el("select", {"aria-label": "Scanner connector"});
    const send = commit => api(`/api/runs/${S.run}/pull/${encodeURIComponent(pick.value)}?commit=${commit}`, {});
    const go = el("button", {class: "btn sm primary", type: "button", disabled: true, onclick: async () => {
      out.textContent = "Importing…";
      try { const d = await send(1); out.textContent = `Imported: ${d.added} new finding(s), ${d.merged} merged into existing ones.`; go.disabled = true; refresh("plan"); }
      catch (e) { out.textContent = e.message; } }}, "Import");
    const pre = el("button", {class: "btn sm", type: "button", onclick: async () => {
      out.textContent = "Reading from the scanner (Tenable exports can take a few minutes)…"; go.disabled = true;
      try {
        let d;
        try { d = await send(0); }
        catch (e) { if (!/Unlock the vault/.test(e.message) || !confirm(e.message + "\n\nUnlock now?") || !await unlock()) throw e; d = await send(0); }
        const sev = Object.entries(d.by_severity).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(", ");
        out.replaceChildren(el("b", {}, `${d.format}: ${d.findings} finding(s) on ${d.devices} device(s)`),
          ` (${sev || "none"}${d.new_devices ? `; ${d.new_devices} device(s) Guardian hasn't seen` : ""}). Duplicates of Guardian's findings are merged on import.`);
        go.disabled = !d.findings;
      } catch (e) { out.textContent = e.message; } }}, "Preview");
    pick.addEventListener("change", () => { go.disabled = true; out.textContent = ""; });
    api(`/api/runs/${S.run}/pull-sources`).then(d => {
      if (!d.sources.length) { box.append(el("p", {class: "note"}, "Or pull them directly: add a Tenable, Qualys or Rapid7 InsightVM connector for this site in Settings › Connectors.")); return; }
      pick.replaceChildren(...d.sources.map(x => el("option", {value: x.id}, `${x.name} (${x.label})`)));
      box.append(el("p", {class: "note"}, "Or pull the open findings from a scanner connector of this site:"), el("div", {class: "row"}, pick, pre, go), out);
    }).catch(() => {});
    return box;
  }

  function row(r) {
    const chips = el("div", {class: "row"}, el("span", {class: `prio p${r.priority}`}, `P${r.priority}`),
      el("span", {class: `sev ${r.severity}`}, r.severity), r.kev ? el("span", {class: "tag error"}, "Actively exploited") : null,
      r.ransomware ? el("span", {class: "tag error"}, "Ransomware") : null,
      r.epss != null ? el("span", {class: "tag"}, `EPSS ${(r.epss * 100).toFixed(r.epss < 0.01 ? 2 : 0)}%`) : null,
      r.exposure ? el("span", {class: "tag"}, r.exposure) : null, el("span", {class: "tag"}, STATUS[r.status] || r.status),
      r.overdue ? el("span", {class: "tag error"}, "Overdue") : null,
      r.source ? el("span", {class: "tag", title: "Imported from another scanner"}, `from ${r.source}`) : null,
      (r.also || []).length ? el("span", {class: "tag", title: r.also.join(", ")}, `also ${r.also.length} scanner${r.also.length > 1 ? "s" : ""}`) : null, r.carried_from ? el("span", {class: "tag new"}, "carried over") : null,
      ...(r.attack || []).map(t => el("a", {class: "tag att", href: attUrl(t), target: "_blank", rel: "noopener", title: "MITRE ATT&CK technique"}, t)),
      r.ticket ? el("a", {class: "tag", href: r.ticket.url, target: "_blank", rel: "noopener"}, `${r.ticket.number} · ${(r.ticket.state || "").replace("_", " ")}`) : null);
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
      const tk = r.ticket ? null : el("button", {class: "btn sm", type: "button", onclick: async () => {
        try { const t = await api(`/api/runs/${S.run}/tracking/${r.id}/ticket`, {}); alert(`Ticket ${t.number} opened.`); refresh("plan"); }
        catch (e) { alert(e.message); } }}, "Open ticket");
      body.append(el("div", {class: "pl-edit"}, owner, due, st, nt, save, re, tk));
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
        el("b", {}, STAGE[s.stage] || s.stage), s.asset ? el("span", {class: "micro"}, s.asset) : null, el("span", {}, s.text), s.technique ? el("a", {class: "tag att", href: attUrl(s.technique), target: "_blank", rel: "noopener"}, s.technique) : null,
        s.finding ? fref(s.finding) : null))),
      p.choke_points.length ? el("div", {class: "ap-choke"}, el("b", {}, "Choke points: "),
        ...p.choke_points.map(c => el("div", {}, "• ", c.fix, c.finding ? ` (${c.finding})` : ""))) : null,
      (p.actors || []).length ? el("p", {class: "note"}, "Techniques also used by: ", ...p.actors.map(a => el("span", {class: "tag"}, a)),
        " (known groups using the same techniques; not a sign they target you)") : null,
      el("p", {class: "note"}, p.summary))));
  }

  // -- MITRE ATT&CK ------------------------------------------------------------------------------
  const attUrl = t => `https://attack.mitre.org/techniques/${t.replace(".", "/")}/`;
  function renderAttack() {
    const d = S.attack, max = Math.max(1, ...d.tactics.flatMap(c => c.techniques.map(t => t.findings.length)));
    $("at-meta").textContent = d.total ? `${d.techniques} techniques in ${d.tactics.filter(c => c.techniques.length).length} of ${d.tactics.length} tactics · ${d.mapped} of ${d.total} open findings mapped` : "";
    if (!d.techniques) {
      $("at-grid").replaceChildren(el("p", {class: "note"}, d.total ? "No open finding maps to an ATT&CK technique." : "The matrix appears after an assessment."));
      $("at-detail").replaceChildren();
      return;
    }
    const cols = d.tactics.filter(c => c.techniques.length);
    $("at-grid").style.gridTemplateColumns = `repeat(${cols.length}, minmax(120px, 1fr))`;
    $("at-grid").replaceChildren(...cols.map(c => el("div", {class: "at-col"},
      el("div", {class: "at-head"}, el("b", {}, c.name), el("span", {class: "micro"}, String(c.techniques.length))),
      ...c.techniques.map(t => el("button", {type: "button", class: "at-cell" + (S.pick === t.id ? " on" : ""), "aria-pressed": String(S.pick === t.id),
        style: `--h:${(0.15 + 0.85 * t.findings.length / max).toFixed(2)}`, onclick: () => { S.pick = S.pick === t.id ? null : t.id; renderAttack(); }},
        el("span", {class: "micro"}, t.id), el("span", {}, t.name.replace(/^.*?: /, "")), el("b", {}, String(t.findings.length)))))));
    const t = d.tactics.flatMap(c => c.techniques).find(x => x.id === S.pick);
    $("at-detail").replaceChildren(...(t ? [el("div", {class: "ap"},
      el("div", {class: "row"}, el("a", {class: "tag att", href: t.url, target: "_blank", rel: "noopener"}, t.id), el("b", {}, t.name), el("span", {class: "micro"}, t.tactic_name)),
      ...t.findings.map(id => { const f = d.findings[id] || {}; return el("div", {class: "at-f"}, el("span", {class: `sev ${f.severity}`}, f.severity || ""),
        el("span", {class: "micro"}, `${id} · P${f.priority}`), el("span", {}, f.title || ""), f.asset ? el("span", {class: "micro"}, f.asset) : null); }),
      ...d.paths.filter(p => p.steps.some(s => s.technique === t.id)).map(p => el("p", {class: "note"}, `Used in attack path ${p.id}: ${p.title}`)))] : []));
  }

  // -- compliance --------------------------------------------------------------------------------
  const kb = n => n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`;
  const ESTATE = {valid: ["ok", "valid"], expiring: ["warn", "expires soon"], expired: ["error", "expired"]};

  async function upload(file, fwKey, ctl, valid) {
    const r = await fetch("/api/evidence", {method: "POST", body: file, headers: {"X-Guardian": "1", "Content-Type": "application/octet-stream",
      "X-Filename": encodeURIComponent(file.name), "X-Controls": encodeURIComponent(`${fwKey}:${ctl}`), "X-Valid-Until": valid || ""}});
    const out = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(out.detail || `Upload failed (${r.status})`);
    return out;
  }

  function controlBody(c, fwKey) {
    const d = S.comp, body = el("div", {class: "co-body"});
    if (c.findings.length) body.append(el("div", {class: "micro"}, c.findings.map(f => `${f} ${d.findings[f] || ""}`).join(" · ")));
    if (c.agent_status !== c.status) body.append(el("p", {class: "micro"}, `Agent: ${CSTAT[c.agent_status]} · shown: ${CSTAT[c.status]} (${c.source === "evidence" ? "evidence attached" : "your status"})`));
    if (c.blocked) body.append(el("p", {class: "note"}, `Your status isn't applied while ${c.blocked.join(", ")} ${c.blocked.length > 1 ? "are" : "is"} open: fix ${c.blocked.length > 1 ? "them" : "it"} and re-check.`));
    for (const e of c.evidence || []) {
      const [cls, lbl] = ESTATE[e.state] || ["", e.state];
      body.append(el("div", {class: "co-ev"}, el("span", {}, el("b", {}, e.name), ` · ${kb(e.size)} · ${e.uploaded_by} ${new Date(e.uploaded_at * 1000).toLocaleDateString()}`,
        e.valid_until ? ` · valid until ${e.valid_until}` : ""), el("span", {class: "tag " + cls}, lbl),
        el("a", {class: "btn sm", href: `/api/evidence/${e.id}/download`}, "Download")));
    }
    if (!d.evidence_unlocked) { body.append(el("p", {class: "note"}, "Unlock the vault to see and add evidence: it's encrypted.")); return body; }
    if (!canEdit()) return body;
    const o = c.override || {};
    const st = el("select", {"aria-label": "Your status"}, el("option", {value: ""}, "Agent's status"),
      ...["met", "partial", "gap", "not_assessed"].map(k => { const x = el("option", {value: k}, CSTAT[k]); if (o.status === k) x.selected = true; return x; }));
    const nt = el("input", {class: "grow", maxlength: "500", placeholder: "Note for the auditor", value: o.note || "", "aria-label": "Note"});
    const save = el("button", {class: "btn sm primary", type: "button", onclick: async () => {
      try { await api("/api/compliance/override", {framework: fwKey, control: c.id, status: st.value || null, note: nt.value}); await refresh("comp"); }
      catch (e) { alert(e.message); } }}, "Save");
    const file = el("input", {type: "file", accept: ".pdf,.png,.jpg,.jpeg,.txt,.csv,.docx,.xlsx", class: "hidden"});
    const valid = el("input", {type: "date", "aria-label": "Valid until (optional)", title: "Valid until (optional)"});
    file.addEventListener("change", async () => {
      if (!file.files[0]) return;
      try { await upload(file.files[0], fwKey, c.id, valid.value); await refresh("comp"); } catch (e) { alert(e.message); }
    });
    body.append(el("div", {class: "pl-edit"}, st, nt, save),
      el("div", {class: "pl-edit"}, el("span", {class: "micro"}, "Evidence valid until"), valid,
        el("button", {class: "btn sm", type: "button", onclick: () => file.click()}, "Add evidence"), file,
        el("span", {class: "micro"}, "PDF, PNG, JPG, TXT, CSV, DOCX, XLSX · 10 MB")));
    return body;
  }

  function exportBar() {
    const d = S.comp, picks = Object.keys(d.frameworks);
    const boxes = picks.map(k => { const b = el("input", {type: "checkbox", value: k}); b.checked = true; return [b, el("label", {class: "check"}, b, d.frameworks[k].title)]; });
    const opt = (label, on) => { const b = el("input", {type: "checkbox"}); b.checked = on; return [b, el("label", {class: "check"}, b, label)]; };
    const [fnd, fl] = opt("Findings appendix", true), [na, nl] = opt('Controls "not assessed"', false);
    const q = () => `frameworks=${boxes.filter(([b]) => b.checked).map(([b]) => b.value).join(",")}&findings=${+fnd.checked}&na=${+na.checked}`;
    const go = kind => { if (!d.evidence_unlocked) return alert("Unlock the vault first: the export includes your encrypted evidence and notes.");
      location.href = `/api/runs/${S.run}/${kind}?${q()}`; };
    return el("details", {class: "co-export"}, el("summary", {}, "Export · PDF or evidence pack"),
      el("div", {class: "row mt16"}, ...boxes.map(x => x[1])), el("div", {class: "row"}, fl, nl),
      el("div", {class: "row mt16"}, el("button", {class: "btn primary", type: "button", onclick: () => go("compliance.pdf")}, "Download PDF"),
        el("button", {class: "btn", type: "button", onclick: () => go("compliance-pack.zip")}, "Evidence pack (ZIP)")),
      el("p", {class: "note"}, "The pack holds the PDF, the evidence files and SHA256SUMS.txt, so an auditor can check each file against the PDF's list."),
      letterForm());
  }

  // one-page letter confirming the assessment (for an auditor or insurer); the issuer fields are remembered in this browser
  function letterForm() {
    const mem = (() => { try { return JSON.parse(localStorage.getItem("guardian-letter") || "{}"); } catch (e) { return {}; } })();
    const inp = (k, ph) => el("input", {value: mem[k] || "", placeholder: ph, maxlength: "200", "aria-label": ph});
    const f = {issuer: inp("issuer", "Your company"), issuer_address: inp("issuer_address", "Address"), place: inp("place", "Place, e.g. Zürich"),
               signer: inp("signer", "Signed by: name, role"), recipient: el("input", {placeholder: "Recipient (optional)", maxlength: "200", "aria-label": "Recipient"})};
    const open = el("select", {"aria-label": "Open findings"}, el("option", {value: "counts"}, "State fixed and open findings"), el("option", {value: "none"}, "Don't mention open findings"));
    const go = el("button", {class: "btn", type: "button", onclick: () => {
      const keep = {}; for (const k of ["issuer", "issuer_address", "place", "signer"]) keep[k] = f[k].value;
      try { localStorage.setItem("guardian-letter", JSON.stringify(keep)); } catch (e) { /* private window */ }
      const q = new URLSearchParams({...Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.value])), open_text: open.value});
      location.href = `/api/runs/${S.run}/assessment-letter.pdf?${q}`; }}, "Assessment letter (PDF)");
    return el("div", {class: "mt16"}, el("p", {class: "note"}, "Assessment letter: one page confirming scope, dates, method and outcome, for an auditor or insurer. Not a certification."),
      el("div", {class: "row"}, f.issuer, f.issuer_address, f.place), el("div", {class: "row"}, f.signer, f.recipient, open, go));
  }

  function renderComp() {
    const d = S.comp;
    if (!d.frameworks[S.fw]) S.fw = Object.keys(d.frameworks)[0];
    const fw = d.frameworks[S.fw];
    $("co-meta").textContent = d.analysed ? "" : "Not mapped yet: runs after the next AI assessment";
    $("co-tabs").replaceChildren(el("div", {class: "seg"}, ...Object.entries(d.frameworks).map(([k, v]) => el("button", {type: "button",
      "aria-pressed": String(k === S.fw), onclick: () => { S.fw = k; S.cfilter = "all"; renderComp(); }}, v.title))), exportBar());
    const n = fw.controls.length;
    $("co-bar").replaceChildren(...["met", "partial", "gap", "not_assessed"].map(s => {
      const i = el("i", {class: `cb-${s}`, title: `${CSTAT[s]}: ${fw.counts[s]}`}); i.style.setProperty("width", `${fw.counts[s] / n * 100}%`); return i; }));
    $("co-filter").replaceChildren(el("div", {class: "seg"}, ...["all", "gap", "partial", "met", "not_assessed"].map(s => el("button", {type: "button",
      "aria-pressed": String(S.cfilter === s), onclick: () => { S.cfilter = s; renderComp(); }}, `${s === "all" ? "All" : CSTAT[s]} · ${s === "all" ? n : fw.counts[s]}`))));
    const list = fw.controls.filter(c => S.cfilter === "all" || c.status === S.cfilter);
    $("co-list").replaceChildren(...list.map(c => {
      const dt = el("details", {class: `co-row cs-${c.status}`, ...(S.open === `${S.fw}:${c.id}` ? {open: true} : {})},
        el("summary", {}, el("div", {class: "co-id"}, c.id), el("div", {}, el("b", {}, c.title),
          el("div", {class: "note m0"}, (c.override && c.override.note) || c.note || "")),
          el("span", {class: "row"}, (c.evidence || []).length ? el("span", {class: "tag"}, `${c.evidence.length} file${c.evidence.length > 1 ? "s" : ""}`) : null,
            el("span", {class: `tag co-${c.status}`}, CSTAT[c.status]))),
        controlBody(c, S.fw));
      dt.addEventListener("toggle", () => { if (dt.open) S.open = `${S.fw}:${c.id}`; });
      return dt;
    }));
  }

  return {show, refresh};
})();
