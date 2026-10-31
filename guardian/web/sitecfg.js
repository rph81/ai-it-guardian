"use strict";
// Settings › Sites › one site: general, scope, ticketing (our PSA / customer's own / off), access. Uses $, el and api from settings.js.
const SiteCfg = (() => {
  let d = null, id = null, tab = "general";
  const TABS = {general: "General", ticketing: "Ticketing", access: "Access", connectors: "Connectors", schedule: "Schedule"};
  const MODES = {msp: ["Our PSA", "Use the ticketing system from Settings › Ticketing, filed under this customer."],
                 own: ["Customer's own system", "The customer's ServiceNow, Jira… with its own address and secret, used only for this site."],
                 off: ["Off", "No tickets for this site. The Fix plan still tracks owners and due dates."]};
  const field = (lab, input, help) => el("div", {}, el("label", {for: input.id}, lab), input, help ? el("p", {class: "help"}, help) : null);

  async function open(siteId) {
    id = siteId; tab = "general";
    try { d = await api(`/api/sites/${id}/settings`); } catch (e) { alert(e.message); return; }
    $("sc-card").classList.remove("hidden");
    render();
    $("sc-card").scrollIntoView({behavior: "smooth"});
  }

  function render() {
    $("sc-title").textContent = d.local ? "This network" : [d.site.customer, d.site.name].filter(Boolean).join(" · ");
    $("sc-label").textContent = `Tickets: ${d.label}`;
    $("sc-tabs").replaceChildren(...Object.entries(TABS).map(([k, v]) => el("button", {type: "button", "aria-pressed": String(tab === k),
      onclick: () => { tab = k; render(); }}, v)));
    $("sc-body").replaceChildren(...({general, ticketing, access, connectors, schedule})[tab]());
  }

  function general() {
    const name = el("input", {id: "sc-name", maxlength: "80", value: d.site.name, disabled: d.local});
    const cust = el("input", {id: "sc-cust", maxlength: "120", value: d.site.customer || "", disabled: d.local});
    const scope = el("input", {id: "sc-scope", class: "mono", value: d.scope || "", placeholder: "10.20.0.0/22, 10.20.8.0/24", disabled: d.local});
    const out = el("span", {class: "note m0"});
    return [el("div", {class: "f3 field"}, field("Site name", name), field("Customer", cust),
              field("Networks (scope)", scope, d.local ? "Guardian scans the network of its own interface." : "Private networks only, nothing broader than /16. The collector uses them once remote scans arrive.")),
      d.local ? el("p", {class: "note"}, "The built-in site can't be renamed.") : el("div", {class: "row mt16"}, el("button", {class: "btn primary", type: "button", onclick: async () => {
        try { await api(`/api/sites/${id}`, {name: name.value, customer: cust.value, scope: scope.value}); out.textContent = "Saved."; d = await api(`/api/sites/${id}/settings`); Sites.load(); }
        catch (e) { out.textContent = e.message; } }}, "Save"), out)];
  }

  function ticketing() {
    const t = d.ticketing;
    let mode = t.mode;
    const cards = el("div", {class: "modes field"});
    const body = el("div");
    const drawModes = () => cards.replaceChildren(...Object.entries(MODES).map(([k, [h, txt]]) => el("button", {type: "button", class: "mode" + (mode === k ? " on" : ""),
      "aria-pressed": String(mode === k), onclick: () => { mode = k; drawModes(); drawBody(); }}, el("b", {}, h + (k === "msp" ? " (recommended)" : "")), el("span", {}, txt))));
    const thr = el("select", {id: "sc-th"}, el("option", {value: ""}, `Same as default (${({p1: "1 only", p2: "1 and 2", p3: "1 to 3", all: "all"})[d.msp.threshold]})`),
      el("option", {value: "p1"}, "Priority 1 only"), el("option", {value: "p2"}, "Priority 1 and 2"), el("option", {value: "p3"}, "Priority 1 to 3"), el("option", {value: "all"}, "All"));
    thr.value = t.threshold;
    const res = el("select", {id: "sc-res"}, el("option", {value: ""}, `Same as default (${d.msp.resolve ? "yes" : "no"})`), el("option", {value: "yes"}, "Yes"), el("option", {value: "no"}, "No"));
    res.value = t.resolve;
    const map = {}, own = {};
    const ownSys = el("select", {id: "sc-own-sys"}, ...Object.entries(d.systems).map(([k, v]) => el("option", {value: k}, v.label)));
    ownSys.value = t.own.system || "servicenow";
    const ownOn = el("input", {type: "checkbox", id: "sc-own-on", checked: !!t.own.on});
    const ownBox = el("div", {class: "f3 field"});
    const drawOwn = () => {
      const sys = ownSys.value, vals = (t.own.settings || {})[sys] || {}, saved = t.own.secret_set && t.own.system === sys;
      for (const k in own) delete own[k];
      ownBox.replaceChildren(...d.systems[sys].fields.map(f => {
        const i = el("input", {id: "sco-" + f.name, class: "mono", type: f.secret ? "password" : "text", autocomplete: f.secret ? "new-password" : "off",
          placeholder: f.secret ? (saved ? "unchanged" : "not set") : (f.placeholder || ""), value: f.secret ? "" : (vals[f.name] || "")});
        own[f.name] = [f, i];
        return field(f.label + (f.secret && saved ? " (saved)" : ""), i);
      }));
    };
    ownSys.addEventListener("change", drawOwn);
    const drawBody = () => {
      if (mode === "off") { body.replaceChildren(); return; }
      const common = el("div", {class: "f3 field"}, field("Open tickets automatically for", thr), field("Close the ticket when Guardian verifies the fix", res));
      if (mode === "msp") {
        const spec = d.map_fields[d.msp.system] || [];
        for (const k in map) delete map[k];
        body.replaceChildren(el("p", {class: "note"}, d.msp.on ? `Uses ${d.msp.label} from Settings › Ticketing. Fill in where this customer's tickets go; blank uses the default.`
                                                               : "Your own ticketing system isn't set up yet: do that in Settings › Ticketing first."),
          el("div", {class: "f3 field"}, ...spec.map(f => { const i = el("input", {id: "scm-" + f.name, class: "mono", value: t.map[f.name] || "", placeholder: f.placeholder || "default"}); map[f.name] = i; return field(f.label.replace(/ \(optional\)$/, ""), i); })),
          common);
      } else {
        drawOwn();
        body.replaceChildren(el("div", {class: "f3 field"}, field("System", ownSys), el("div", {}, el("label", {class: "check"}, ownOn, " Use this system"))), ownBox,
          el("p", {class: "help"}, "Use a dedicated API user at the customer. Like your own system's secret, it's kept on the server for scheduled runs."), common);
      }
    };
    drawModes(); drawBody();
    const out = el("span", {class: "note m0"});
    const save = async () => {
      const own_fields = {}; let own_secret = null;
      for (const [f, i] of Object.values(own)) { if (f.secret) own_secret = i.value || null; else own_fields[f.name] = i.value; }
      const r = await api(`/api/sites/${id}/ticketing`, {mode, threshold: thr.value, resolve: res.value,
        map: Object.fromEntries(Object.entries(map).map(([k, i]) => [k, i.value])), own_system: ownSys.value, own_on: ownOn.checked, own_fields, own_secret});
      d = await api(`/api/sites/${id}/settings`); $("sc-label").textContent = `Tickets: ${r.label}`; Sites.load();
    };
    return [cards, body, el("div", {class: "row mt16"},
      el("button", {class: "btn primary", type: "button", onclick: async () => { try { await save(); out.textContent = "Saved."; } catch (e) { out.textContent = e.message; } }}, "Save"),
      el("button", {class: "btn", type: "button", onclick: async () => { out.textContent = "Connecting…";
        try { await save(); const r = await api(`/api/sites/${id}/ticketing/test`, {}); out.textContent = `Connected to ${r.system || "the system"} as ${r.user}.`; }
        catch (e) { out.textContent = e.message; } }}, "Save and test"), out)];
  }

  function access() {
    const boxes = {};
    const rows = d.access.map(u => {
      const cb = el("input", {type: "checkbox", checked: u.here, disabled: u.role === "admin", "aria-label": `${u.email} may see this site`});
      boxes[u.id] = cb;
      return el("tr", {}, el("td", {}, el("label", {class: "check"}, cb, " ", u.email)), el("td", {}, u.role),
        el("td", {class: "note"}, u.role === "admin" ? "Admins see every site" : u.all ? "Every site" : "Only the sites given"));
    });
    const out = el("span", {class: "note m0"});
    return [el("p", {class: "note"}, "Operators and viewers see only the sites ticked for them; a user nobody has limited sees every site. The server refuses everything else, including runs, reports and tickets."),
      el("div", {class: "tablewrap field"}, el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "User"), el("th", {}, "Role"), el("th", {}, "Sees"))), el("tbody", {}, ...rows))),
      el("div", {class: "row mt16"}, el("button", {class: "btn primary", type: "button", onclick: async () => {
        try { await api(`/api/sites/${id}/access`, {users: Object.fromEntries(Object.entries(boxes).map(([k, b]) => [k, b.checked]))});
              d = await api(`/api/sites/${id}/settings`); render(); }
        catch (e) { out.textContent = e.message; } }}, "Save"), out)];
  }

  function connectors() {
    return [el("p", {class: "note"}, "Connectors (Active Directory, Microsoft 365, Azure, SSH, WinRM, NinjaOne…) belong to one site. Add and edit them in Connectors with this site chosen."),
      el("div", {class: "row mt16"}, el("a", {class: "btn", href: `#connectors`, onclick: () => { try { localStorage.setItem("guardian-site", id); } catch (e) { /* storage blocked */ } }}, "Open this site's connectors")),
      d.local ? null : el("p", {class: "help"}, "Connector agents run during an AI assessment; for remote sites that starts with the collector's remote scans (next phase).")];
  }

  function schedule() {
    return [el("p", {class: "note"}, d.local ? "This network's scans and AI assessments are scheduled in Settings › Schedules & alerts."
      : "Remote sites are scanned by their collector. Schedules per site arrive with remote scans (collector phase B); until then, import scanner results into an assessment for this site from the dashboard.")];
  }

  $("sc-close").addEventListener("click", () => $("sc-card").classList.add("hidden"));
  return {open};
})();
