"use strict";
// Agents tab, live agent map and the Orchestrator chat. Uses $, el, api and me from console.js.
const Agents = (() => {
  const ORDER = ["collector", "discovery", "orchestrator", "network", "os", "web", "firmware", "wan", "report"];
  const NODES = {
    orchestrator: {x: 400, y: 320, sub: "assigns · relays", center: true},
    collector: {x: 400, y: 70, sub: "program, not AI"},
    discovery: {x: 640, y: 150, sub: "identifies devices"},
    network: {x: 700, y: 380, sub: "exposure, protocols"},
    os: {x: 560, y: 560, sub: "versions, EOL, CVEs"},
    web: {x: 240, y: 560, sub: "admin pages, TLS"},
    firmware: {x: 100, y: 380, sub: "vendor releases"},
    wan: {x: 160, y: 150, sub: "public IP, forwards"},
    report: {x: 400, y: 470, sub: "score, summary", small: true},
  };
  const SHORT = {collector: "Scanner", discovery: "Discovery", orchestrator: "Orchestrator", network: "Network", os: "OS & endpoints",
                 web: "Web & APIs", firmware: "Firmware", wan: "Internet perimeter", report: "Report writer"};
  const KIND = {order: "order", tool: "check", read: "read", find: "finding", note: "note", note_outcome: "then", done: "done", start: "start", error: "error"};
  const CHECKS = {probe: "probes", http_get: "web pages", tls_inspect: "TLS checks", cve_lookup: "CVE lookups", eol_lookup: "EOL lookups",
                  web_search: "searches", wan_info: "public-IP lookups", annotate_asset: "identifications"};
  const NS = "http://www.w3.org/2000/svg";
  const S = {run: null, since: 0, events: [], agents: {}, notes: [], running: false, timer: null, t0: null,
             replay: null, speed: 3, links: {}, selected: null, nfind: 0, nnote: 0, cost: 0, view: null, drill: null};
  const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const COLOR = {order: "--accent", tool: "--low", find: "--high", note: "--note", done: "--ok"};
  const color = k => cssVar(COLOR[k] || "--muted");
  const fmtT = s => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
  const money = v => v == null ? "—" : `$${v.toFixed(2)}`;
  const tokens = u => { const n = u ? u.input + u.output + u.cache_read + u.cache_write : 0; return n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? Math.round(n / 1e3) + "k" : String(n); };

  // ---------------------------------------------------------------- map drawing
  let svg, gEdges, gLinks, gPackets, nodeEls = {}, edges = {};
  function mk(t, a = {}, p = svg) { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); p.append(e); return e; }
  function buildMap() {
    svg = $("map"); svg.replaceChildren(); nodeEls = {}; edges = {}; S.links = {}; S.selected = null;
    const defs = mk("defs");
    const m = mk("marker", {id: "arr", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 5, markerHeight: 5, orient: "auto-start-reverse"}, defs);
    mk("path", {d: "M0,0 L10,5 L0,10 z", class: "arrowhead"}, m);
    gEdges = mk("g");
    for (const id in NODES) if (id !== "orchestrator")
      edges[id] = mk("line", {class: "edge", x1: NODES.orchestrator.x, y1: NODES.orchestrator.y, x2: NODES[id].x, y2: NODES[id].y}, gEdges);
    gLinks = mk("g"); gPackets = mk("g");
    for (const [id, n] of Object.entries(NODES)) {
      const g = mk("g", {class: "node " + (n.center ? "center" : "waiting"), transform: `translate(${n.x},${n.y})`, tabindex: 0, role: "button",
                         "aria-label": `${SHORT[id]}: show what it did`});
      const w = Math.max(n.center ? 156 : 124, SHORT[id].length * 9.4 + 30), h = n.center ? 62 : 50;
      mk("rect", {class: "ring", x: -w / 2, y: -h / 2, width: w, height: h}, g); mk("rect", {class: "body", x: -w / 2, y: -h / 2, width: w, height: h}, g);
      mk("text", {class: "label", y: -1}, g).textContent = SHORT[id];
      mk("text", {class: "sub", y: 14}, g).textContent = n.sub;
      const badge = mk("text", {class: "badge", y: h / 2 + 16}, g);
      g.addEventListener("click", () => openDrill(id));
      g.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrill(id); } });
      nodeEls[id] = {g, badge, finds: 0};
    }
    $("feed").replaceChildren(); $("lp").hidden = true;
    S.nfind = S.nnote = 0; S.cost = 0; totals(null);
  }
  function setState(id, st) {
    const n = nodeEls[id]; if (!n || NODES[id].center) return;
    n.g.classList.remove("waiting", "queued", "working", "done", "off"); n.g.classList.add(st);
  }
  function packet(kind, from, to, path, animate) {
    if (!animate || !NODES[from] || !NODES[to]) return;
    const a = NODES[from], b = NODES[to];
    if (from === to) {                                           // a check on the network: a pulse out and back
      const c = mk("circle", {r: 5, fill: color(kind), cx: a.x, cy: a.y}, gPackets);
      let t = 0; const ang = Math.atan2(a.y - 320, a.x - 400) || -Math.PI / 2;
      const step = () => { t += 0.04 * S.speedNow(); const d = 70 * Math.sin(Math.min(t, 1) * Math.PI);
        c.setAttribute("cx", a.x + Math.cos(ang) * d); c.setAttribute("cy", a.y + Math.sin(ang) * d);
        if (t < 1) requestAnimationFrame(step); else c.remove(); };
      return requestAnimationFrame(step);
    }
    if (!path) { const e = edges[from === "orchestrator" ? to : from]; if (e) { e.classList.add("hot"); setTimeout(() => e.classList.remove("hot"), 900); } }
    const c = mk("circle", {r: 7, fill: color(kind)}, gPackets);
    let t = 0;
    const step = () => { t += 0.025 * S.speedNow(); let x, y;
      if (path) { const L = path.getTotalLength(), p = path.getPointAtLength(L * Math.min(t, 1)); x = p.x; y = p.y; }
      else { x = a.x + (b.x - a.x) * Math.min(t, 1); y = a.y + (b.y - a.y) * Math.min(t, 1); }
      c.setAttribute("cx", x); c.setAttribute("cy", y);
      if (t < 1) requestAnimationFrame(step); else c.remove(); };
    requestAnimationFrame(step);
  }
  S.speedNow = () => S.replay ? S.speed : 3;

  // -- persistent links between agents --------------------------------------------------
  function linkPath(from, to) {          // curve to one side so A→B and B→A don't overlap; stop at the circles' edges
    const a = NODES[from], b = NODES[to], dx = b.x - a.x, dy = b.y - a.y;
    const mx = (a.x + b.x) / 2 - dy * 0.22, my = (a.y + b.y) / 2 + dx * 0.22;
    const edge = (p, r) => { const l = Math.hypot(mx - p.x, my - p.y); return [p.x + (mx - p.x) / l * r, p.y + (my - p.y) / l * r]; };
    const [sx, sy] = edge(a, 44), [ex, ey] = edge(b, 46);
    return `M${sx},${sy} Q${mx},${my} ${ex},${ey}`;
  }
  function getLink(from, to) {
    const key = from + ">" + to;
    if (S.links[key]) return S.links[key];
    const g = mk("g", {class: "link", tabindex: 0, role: "button", "aria-label": `Notes from ${SHORT[from]} to ${SHORT[to]}`}, gLinks);
    const d = linkPath(from, to);
    mk("path", {class: "hit", d}, g);
    const line = mk("path", {class: "line", d, "marker-end": "url(#arr)", "stroke-width": 2}, g);
    const m = line.getPointAtLength(line.getTotalLength() / 2);
    const count = mk("g", {class: "count", transform: `translate(${m.x},${m.y})`}, g);
    mk("rect", {x: -10, y: -10, width: 20, height: 20}, count); const ct = mk("text", {y: 4}, count);
    const title = mk("title", {}, g);
    const link = {key, from, to, g, line, ct, title, msgs: []};
    g.addEventListener("click", () => selectLink(link));
    g.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectLink(link); } });
    return S.links[key] = link;
  }
  function addNote(ev) {
    const link = getLink(ev.from, ev.to);
    const known = S.notes.find(n => n.id === ev.note);
    link.msgs.push({id: ev.note, text: ev.text, t: ev.t, outcome: known && S.replay === null && !S.running ? known.outcome : null});
    const n = link.msgs.length;
    link.ct.textContent = n; link.line.setAttribute("stroke-width", Math.min(2 + (n - 1) * 1.5, 6));
    link.title.textContent = `${SHORT[ev.from]} → ${SHORT[ev.to]}: ${n} note${n > 1 ? "s" : ""}`;
    if (S.selected === link) renderLink();
    return link.line;
  }
  function noteOutcome(ev) {
    for (const l of Object.values(S.links)) for (const m of l.msgs) if (m.id === ev.note) { m.outcome = ev.text; if (S.selected === l) renderLink(); }
  }
  function selectLink(link) {
    if (S.selected) S.selected.g.classList.remove("sel");
    S.selected = S.selected === link ? null : link;
    if (S.selected) S.selected.g.classList.add("sel");
    renderLink();
  }
  function renderLink() {
    const lp = $("lp"), l = S.selected;
    if (!l) { lp.hidden = true; return; }
    lp.hidden = false; lp.replaceChildren();
    lp.append(el("h3", {}, `${SHORT[l.from]} → ${SHORT[l.to]}`, el("button", {"aria-label": "Close", onclick: () => selectLink(l)}, "×")));
    for (const m of l.msgs) {
      const then = m.outcome ? el("div", {class: "then"}, el("b", {}, "Then: "), m.outcome)
                             : el("div", {class: "then wait"}, `Waiting for ${SHORT[l.to]} to read it`);
      lp.append(el("div", {class: "msg"}, el("div", {class: "t"}, fmtT(m.t - S.t0) + "  note"), m.text, then));
    }
  }

  // -- events ------------------------------------------------------------------------------
  function totals(ev) {
    if (ev) { S.cost = ev.total || S.cost; }
    $("m-clock").textContent = ev && S.t0 ? fmtT(ev.t - S.t0) : "0:00";
    $("m-find").textContent = S.nfind; $("m-note").textContent = S.nnote; $("m-cost").textContent = money(S.cost);
  }
  function fire(ev, animate) {
    if (S.t0 === null) S.t0 = ev.t;
    const k = ev.kind;
    if (k === "start") setState(ev.from, "working");
    if (k === "order" && ev.to !== "orchestrator") setState(ev.to, ev.queued ? "queued" : nodeEls[ev.to]?.g.classList.contains("working") ? "working" : "waiting");
    if (k === "done") setState(ev.from, "done");
    if (k === "find" && !ev.status) {
      S.nfind++;
      const n = nodeEls[ev.from];
      if (n) { n.finds++; n.badge.textContent = `${n.finds} finding${n.finds > 1 ? "s" : ""}`; }
    }
    let path = null;
    if (k === "note") { S.nnote++; path = addNote(ev); }
    if (k === "note_outcome") noteOutcome(ev);
    if (["order", "find", "note"].includes(k) && ev.from !== ev.to) packet(k, ev.from, ev.to, path, animate);
    if (k === "tool" && ev.active) packet("tool", ev.from, ev.from, null, animate);
    totals(ev);
    if (k !== "read" && k !== "start") feedRow(ev);
  }
  function feedRow(ev) {
    const who = ["order", "note"].includes(ev.kind) && ev.from !== ev.to ? `${SHORT[ev.from] || ev.from} → ${SHORT[ev.to] || ev.to}`
              : ev.kind === "note_outcome" ? `${SHORT[ev.from] || ev.from} read the note` : (SHORT[ev.from] || ev.from);
    const row = el("div", {class: "ev " + ev.kind}, el("div", {class: "t"}, fmtT(ev.t - S.t0) + "  " + (KIND[ev.kind] || ev.kind)),
      el("b", {}, who + ": "), ev.text);
    const feed = $("feed"); feed.prepend(row);
    while (feed.childElementCount > 400) feed.lastElementChild.remove();
  }
  function applyAll(events) { for (const ev of events) fire(ev, false); }

  // -- replay of a finished run: real gaps compressed (a 30-minute run takes about a minute at 1×) --
  function startReplay() {
    if (!S.events.length) return;
    buildMap(); S.t0 = S.events[0].t; markOff();
    const times = []; let acc = 0;
    S.events.forEach((e, i) => { if (i) acc += Math.min(e.t - S.events[i - 1].t, 20) / 30; times.push(acc); });
    S.replay = {i: 0, clock: 0, times, last: performance.now(), playing: true};
    $("m-play").textContent = "Pause"; $("m-play").classList.remove("hidden");
    requestAnimationFrame(tickReplay);
  }
  function tickReplay(now) {
    const r = S.replay; if (!r) return;
    const dt = (now - r.last) / 1000; r.last = now;
    if (r.playing) {
      r.clock += dt * S.speed / 3;
      while (r.i < S.events.length && r.times[r.i] <= r.clock) fire(S.events[r.i++], true);
      if (r.i >= S.events.length) { S.replay = null; $("m-play").classList.add("hidden"); return; }
    }
    requestAnimationFrame(tickReplay);
  }
  function markOff() { for (const [id, a] of Object.entries(S.agents)) if (a.status === "off") setState(id, "off"); }

  // ---------------------------------------------------------------- data loading
  async function load(runId, fresh) {
    if (fresh || runId !== S.run) {
      S.run = runId; S.since = 0; S.events = []; S.t0 = null; S.replay = null; S.drill = null;
      buildMap(); $("m-play").classList.add("hidden");
      loadChat();
    }
    if (!S.run) return;
    let d;
    try { d = await api(`/api/runs/${S.run}/live?since=${S.since}`); } catch (e) { return; }
    if (runId !== S.run) return;
    S.agents = d.agents; S.notes = d.notes; S.running = d.running; S.ai = d.ai || {};
    const animate = S.since > 0 && !S.replay;
    S.events.push(...d.events);
    if (d.events.length) S.since = d.events[d.events.length - 1].n;
    if (!S.replay) { if (animate) for (const ev of d.events) fire(ev, true); else applyAll(d.events); }
    markOff();
    S.cost = d.cost_total || S.cost; totals(S.events[S.events.length - 1] || null);
    $("m-empty").classList.toggle("hidden", S.events.length > 0);
    $("m-replay").classList.toggle("hidden", S.running || !S.events.length);
    $("m-live").classList.toggle("hidden", !S.running);
    renderCards(); renderTable(); if (S.drill) renderDrill();
    clearTimeout(S.timer); S.timer = null;
    if (S.running) S.timer = setTimeout(() => load(S.run), 2000);
  }

  // ---------------------------------------------------------------- Agents tab
  const STATUS = {waiting: "Waiting", queued: "Queued", working: "Working", done: "Done", off: "Turned off"};
  function sevLine(by) {
    const out = el("span", {class: "sevs"});
    for (const s of ["critical", "high", "medium", "low", "info"]) if (by && by[s]) out.append(el("span", {}, el("b", {class: `c-${s}`}, String(by[s])), " " + (s === "medium" ? "med" : s)));
    return out;
  }
  function checksText(c) {
    if (!c) return "—";
    const parts = Object.entries(CHECKS).filter(([k]) => c[k]).map(([k, label]) => `${c[k]} ${label}`);
    return parts.join(", ") || "—";
  }
  function renderCards() {
    const box = $("a-cards"); box.replaceChildren();
    const names = ORDER.filter(n => S.agents[n]);
    $("a-empty").classList.toggle("hidden", names.length > 0);
    $("a-cost").textContent = names.length ? `AI cost so far: ${money(S.cost)}` : "";
    for (const n of names) {
      const a = S.agents[n];
      const head = el("div", {class: "ahead"}, el("b", {}, SHORT[n]), el("span", {class: "tag st-" + a.status}, STATUS[a.status] || a.status));
      const meta = el("div", {class: "ameta"});
      if (a.rounds) meta.append(el("span", {}, `${a.rounds}${a.max_rounds && a.status === "working" ? " / " + a.max_rounds : ""} rounds`));
      if (a.findings) meta.append(sevLine(a.by_severity));
      if (a.followups) meta.append(el("span", {}, `${a.followups} follow-up${a.followups > 1 ? "s" : ""}`));
      if (n !== "collector") meta.append(el("span", {}, money(a.cost || 0)));
      const act = a.status === "queued" ? `Starts when a slot frees up (${S.ai.parallel || 3} at a time).`
                : a.status === "waiting" ? (n === "report" ? "Runs after all specialists finish." : "Not started yet.")
                : a.status === "off" ? "Turned off in Settings → AI agents." : (a.activity || "");
      box.append(el("div", {class: "acard " + a.status, tabindex: 0, role: "button", onclick: () => openDrill(n),
        onkeydown: e => { if (e.key === "Enter") openDrill(n); }}, head, el("div", {class: "aact"}, act), meta));
    }
  }
  function renderTable() {
    const box = $("a-table"); box.replaceChildren();
    const names = ORDER.filter(n => S.agents[n] && n !== "collector" && S.agents[n].status !== "off");
    if (S.running || !names.some(n => S.agents[n].rounds)) { box.classList.add("hidden"); return; }
    box.classList.remove("hidden");
    const tb = el("tbody");
    let tot = {rounds: 0, findings: 0, cost: 0, tok: 0};
    for (const n of names) {
      const a = S.agents[n];
      const tk = a.usage ? a.usage.input + a.usage.output + a.usage.cache_read + a.usage.cache_write : 0;
      tot.rounds += a.rounds || 0; tot.findings += a.findings || 0; tot.cost += a.cost || 0; tot.tok += tk;
      tb.append(el("tr", {class: "click", onclick: () => openDrill(n)}, el("td", {}, SHORT[n]), el("td", {}, String(a.devices || "—")),
        el("td", {}, String(a.rounds || 0)), el("td", {}, checksText(a.checks)), el("td", {}, String(a.findings || 0)),
        el("td", {}, tokens(a.usage)), el("td", {}, money(a.cost || 0))));
    }
    tb.append(el("tr", {class: "total"}, el("td", {}, "Total"), el("td"), el("td", {}, String(tot.rounds)), el("td"),
      el("td", {}, String(tot.findings)), el("td", {}, tokens({input: tot.tok, output: 0, cache_read: 0, cache_write: 0})), el("td", {}, money(tot.cost))));
    box.append(el("h2", {}, "What each agent did"),
      el("div", {class: "tablewrap"}, el("table", {class: "atable"}, el("thead", {}, el("tr", {}, ...["Agent", "Devices", "Rounds", "Checks run", "Findings", "Tokens", "Cost"].map(h => el("th", {}, h)))), tb)),
      el("p", {class: "note"}, "Click an agent to see every step it took. Tokens include cached ones, which cost a tenth of normal input or less."));
  }
  function openDrill(n) { S.drill = n; renderDrill(); showTab("agents"); $("a-drill").scrollIntoView({behavior: "smooth", block: "start"}); }
  function renderDrill() {
    const box = $("a-drill"), n = S.drill; box.replaceChildren();
    if (!n) { box.classList.add("hidden"); return; }
    box.classList.remove("hidden");
    const evs = S.events.filter(e => e.from === n || (e.to === n && ["order", "note"].includes(e.kind)));
    box.append(el("div", {class: "cardhead"}, el("h2", {}, `${SHORT[n]}: every step`),
      el("button", {class: "btn sm", onclick: () => { S.drill = null; renderDrill(); }}, "Close")));
    if (!evs.length) box.append(el("p", {class: "note"}, "Nothing yet."));
    const list = el("div", {class: "steps"});
    for (const e of evs) list.append(el("div", {class: "ev " + e.kind}, el("span", {class: "t"}, fmtT(e.t - (S.t0 || e.t)) + "  " + (KIND[e.kind] || e.kind) + "  "),
      e.to === n && e.from !== n ? el("b", {}, `from ${SHORT[e.from] || e.from}: `) : null, e.text));
    box.append(list);
  }

  // ---------------------------------------------------------------- chat
  let chatState = {can_ask: false, can_order: false};
  async function loadChat() {
    const box = $("c-msgs"); box.replaceChildren();
    if (!S.run) return;
    let d; try { d = await api(`/api/runs/${S.run}/chat`); } catch (e) { return; }
    chatState = d;
    box.append(el("div", {class: "bub ai"}, "I coordinated this run. Ask me anything about it" + (d.can_order ? ", or tell me what to check next." : "."),
      el("div", {class: "meta2"}, "Orchestrator")));
    for (const m of d.messages) bubble(m);
    $("c-locked").classList.toggle("hidden", d.can_ask);
    $("c-input").disabled = $("c-send").disabled = !d.can_ask;
    $("c-waiting").classList.toggle("hidden", !(d.waiting && d.can_order));
  }
  function bubble(m) {
    const box = $("c-msgs");
    const b = el("div", {class: "bub " + (m.role === "user" ? "me" : "ai")}, m.text);
    for (const o of m.orders || []) b.append(orderBox(o));
    b.append(el("div", {class: "meta2"}, m.role === "user" ? m.by : `Orchestrator${m.cost ? " · " + money(m.cost) : ""}`));
    box.append(b); box.scrollTop = box.scrollHeight;
  }
  function orderBox(o) {
    const box = el("div", {class: "act"}, el("div", {}, el("b", {}, `Order → ${SHORT[o.agent] || o.agent}: `), o.instruction),
      el("div", {class: "meta2"}, `Estimated ${o.estimate || "cost unknown"}`));
    const st = el("div", {class: "row"});
    if (o.status === "proposed" && chatState.can_order) {
      st.append(el("button", {class: "btn sm primary", onclick: () => sendOrder(o, "send", st)}, "Send order"),
                el("button", {class: "btn sm", onclick: () => sendOrder(o, "dismiss", st)}, "Dismiss"));
    } else st.append(el("span", {class: "tag " + (o.status === "sent" ? "ok" : "")}, o.status === "sent" ? `Sent by ${o.by}` : o.status === "dismissed" ? "Dismissed" : "Waiting for an operator"));
    box.append(st);
    return box;
  }
  async function sendOrder(o, action, st) {
    const call = () => api(`/api/runs/${S.run}/chat/orders/${o.id}`, {action});
    try {
      let r;
      try { r = await call(); }
      catch (e) { if (!/Unlock the vault/.test(e.message) || !confirm(e.message + "\n\nUnlock now?") || !await unlock()) throw e; r = await call(); }
      st.replaceChildren(el("span", {class: "tag " + (action === "send" ? "ok" : "")}, action === "send"
        ? (r.delivered === "live" ? "Sent: the agent gets it on its next round" : "Sent: follow-up started") : "Dismissed"));
      if (r.job) { renderJob(r.job); poll(); load(S.run); }
      else if (action === "send") load(S.run);
    } catch (e) { alert(e.message); }
  }
  async function ask() {
    const q = $("c-input").value.trim(); if (!q || !S.run) return;
    $("c-input").value = ""; $("c-send").disabled = true;
    bubble({role: "user", by: me.name, text: q});
    const wait = el("div", {class: "bub ai thinking"}, "Thinking…"); $("c-msgs").append(wait);
    try { const r = await api(`/api/runs/${S.run}/chat`, {message: q}); wait.remove(); bubble(r); }
    catch (e) { wait.remove(); bubble({role: "assistant", text: "Couldn't answer: " + e.message}); }
    $("c-send").disabled = false; $("c-input").focus();
  }
  $("c-send").addEventListener("click", ask);
  $("c-input").addEventListener("keydown", e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask(); } });
  $("c-run").addEventListener("click", async () => {
    try { const s = await api(`/api/runs/${S.run}/followup`, {}); renderJob(s); poll(); $("c-waiting").classList.add("hidden"); }
    catch (e) { alert(e.message); }
  });

  // ---------------------------------------------------------------- controls
  $("m-replay").addEventListener("click", startReplay);
  $("m-play").addEventListener("click", e => { if (!S.replay) return; S.replay.playing = !S.replay.playing; e.target.textContent = S.replay.playing ? "Pause" : "Play"; });
  document.querySelectorAll("[data-speed]").forEach(b => b.addEventListener("click", () => {
    S.speed = +b.dataset.speed; document.querySelectorAll("[data-speed]").forEach(x => x.classList.toggle("on", x === b)); }));

  return {
    show(runId) { load(runId, runId !== S.run); },
    follow(job) { if (job.running && job.run_id && job.run_id !== S.run && ["full", "resume", "followup"].includes(job.mode)) load(job.run_id, true);
                  else if (job.running && job.run_id === S.run && !S.timer) load(S.run); },
    refresh() { if (S.run) load(S.run); },
    get run() { return S.run; },
  };
})();
