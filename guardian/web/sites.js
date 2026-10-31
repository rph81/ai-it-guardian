"use strict";
// Settings › Sites & collectors. Uses $, el, api and ago from settings.js.
const Sites = (() => {
  let gw = null, current = null, tab = "linux";
  const del = async path => {
    const r = await fetch(path, {method: "DELETE", headers: {"X-Guardian": "1"}});
    const out = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(out.detail || `Request failed (${r.status})`);
    return out;
  };
  const STATE = {connected: ["", "Online"], paused: ["warn", "Paused by customer"], disconnected: ["bad", "Disconnected by customer"]};

  function status(c, pending) {
    if (!c) return pending ? el("span", {class: "tag"}, `Waiting for enrollment · code until ${new Date(pending.code_expires * 1000).toLocaleString()}`) : el("span", {class: "note m0"}, "No collector");
    const stale = Date.now() / 1000 - (c.last_seen || 0) > 180 && c.state !== "disconnected";
    const [cls, label] = stale ? ["bad", "Not reachable"] : STATE[c.state] || ["", c.state];
    return el("div", {}, el("span", {class: "row"}, el("span", {class: "dot " + cls}), `${label}`),
      el("div", {class: "micro"}, `${c.host || ""} · v${c.version || "?"}` + (c.reason ? ` · "${c.reason}"` : "")));
  }

  async function load() {
    let d; try { d = await api("/api/sites"); } catch (e) { return; }
    gw = d.gateway;
    $("si-gw").textContent = `Gateway ${gw.url}` + (gw.pin ? "" : " · not running yet");
    $("si-rows").replaceChildren(...d.sites.map(s => {
      const local = s.id === "local", c = s.collector;
      const acts = el("div", {class: "row"}, el("button", {class: "btn sm", type: "button", onclick: () => SiteCfg.open(s.id)}, "Settings"));
      if (!local) {
        acts.append(el("button", {class: "btn sm", type: "button", onclick: () => enroll(s)}, c ? "New collector" : "Install"));
        if (c) acts.append(el("button", {class: "btn sm danger", type: "button", onclick: () => revoke(s)}, "Revoke"));
        acts.append(el("button", {class: "btn sm", type: "button", onclick: () => remove(s)}, "Remove"));
      }
      return el("tr", {}, el("td", {}, el("b", {}, s.name), el("div", {class: "micro"}, local ? "This server's own network" : s.customer || "")),
        el("td", {}, local ? el("span", {class: "row"}, el("span", {class: "dot"}), "Built-in") : status(c, s.pending)),
        el("td", {}, c ? ago(c.last_seen) : "—"),
        el("td", {class: "mono"}, c ? c.scope.join(", ") : "—"), el("td", {}, acts));
    }));
  }

  async function enroll(s) {
    if (s.collector && !confirm(`Enroll a new collector for ${s.name}? The current one is revoked when the new one enrolls.`)) return;
    try {
      await Passkey.authenticate(true);
      const r = await api(`/api/sites/${s.id}/enroll`, {});
      current = {site: s, ...r};
      $("si-ititle").textContent = `Install the collector · ${s.name}`;
      $("si-inote").textContent = `One-time code ${r.code}, valid until ${new Date(r.expires * 1000).toLocaleString()}. It's shown only now; create a new one if it gets lost.`;
      $("si-install").classList.remove("hidden"); render(); load();
      $("si-install").scrollIntoView({behavior: "smooth"});
    } catch (e) { alert(e.name ? Passkey.explain(e) : e.message); }
  }

  function render() {
    if (!current) return;
    const scope = ($("si-scope").value.trim() || "<customer subnets>").split(/[\s,]+/).filter(Boolean).join(",");
    const args = `${current.url} ${current.code} --pin ${current.pin || "<gateway not running>"} --scope ${scope}`;
    const cmd = {
      linux: `# On a Linux host at the customer (Debian/Ubuntu, Python 3.11+), after installing the package:\nsudo guardian-collector enroll ${args}\nsudo systemctl enable --now guardian-collector\n# optional status page for the customer:\nsudo guardian-collector page-password && sudo systemctl enable --now guardian-collector-page`,
      docker: `docker volume create guardian-collector\ndocker run --rm -v guardian-collector:/data guardian-collector:1.1.0 enroll ${args}\ndocker run -d --name guardian-collector --restart unless-stopped --network host \\\n  --cap-add NET_RAW --cap-add NET_ADMIN -v guardian-collector:/data guardian-collector:1.1.0 run`,
      vm: `Import the Guardian collector appliance, start it, and on its console choose "Enroll" and enter:\n  Server:  ${current.url}\n  Code:    ${current.code}\n  Pin:     ${current.pin || "-"}\n  Subnets: ${scope}`}[tab];
    $("si-cmd").textContent = cmd;
    $("si-help").textContent = {linux: "Install with the .deb (collector/packaging/build-deb.sh) or from the repository's collector/ folder (sudo ./install.sh). Updates after that are signed and automatic unless the customer turns them off.",
      docker: "Build the image from the repository root: docker build -f collector/Dockerfile -t guardian-collector:1.1.0 .",
      vm: "Build the appliance with collector/packaging/appliance/build-appliance.sh (qcow2 for Proxmox/KVM, VMDK for VMware). On first sign-in it asks for these values."}[tab];
    for (const b of $("si-tabs").children) b.setAttribute("aria-pressed", String(b.dataset.k === tab));
  }

  async function revoke(s) {
    if (!confirm(`Revoke the collector of ${s.name}? It's cut off immediately and needs a new enrollment.`)) return;
    try { await api(`/api/sites/${s.id}/revoke`, {}); load(); } catch (e) { alert(e.message); }
  }
  async function remove(s) {
    if (!confirm(`Remove the site ${s.name}? Its collector is revoked.`)) return;
    try { await del(`/api/sites/${s.id}`); if (current && current.site.id === s.id) { current = null; $("si-install").classList.add("hidden"); } load(); }
    catch (e) { alert(e.message); }
  }

  $("si-add").addEventListener("submit", async e => {
    e.preventDefault();
    try { await api("/api/sites", {name: $("si-name").value, customer: $("si-cust").value}); $("si-name").value = $("si-cust").value = ""; load(); }
    catch (err) { alert(err.message); }
  });
  $("si-tabs").addEventListener("click", e => { if (e.target.dataset.k) { tab = e.target.dataset.k; render(); } });
  $("si-scope").addEventListener("input", render);
  $("si-copy").addEventListener("click", () => navigator.clipboard.writeText($("si-cmd").textContent));
  $("si-iclose").addEventListener("click", () => { current = null; $("si-install").classList.add("hidden"); });
  $("si-cancel").addEventListener("click", async () => {
    if (!current) return;
    try { await del(`/api/sites/${current.site.id}/enroll`); current = null; $("si-install").classList.add("hidden"); load(); } catch (e) { alert(e.message); }
  });
  return {load};
})();
