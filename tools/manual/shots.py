"""Captures every console screen from the demo console (tools/manual/demo_server.py) with headless Chrome."""
import base64, json, os, subprocess, sys, tempfile, time, urllib.request
import websocket
OUT, B = sys.argv[1], "http://127.0.0.1:8765"
chrome = subprocess.Popen(["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--headless=new", "--remote-debugging-port=9333",
                           f"--user-data-dir={tempfile.mkdtemp()}", "--hide-scrollbars", "--force-color-profile=srgb", "--window-size=1440,900", "about:blank"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(50):
    try:
        tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9333/json")); break
    except Exception:
        time.sleep(0.2)
ws = websocket.create_connection(next(t for t in tabs if t["type"] == "page")["webSocketDebuggerUrl"], timeout=60)
n = [0]
def cmd(method, **params):
    n[0] += 1; ws.send(json.dumps({"id": n[0], "method": method, "params": params}))
    while True:
        m = json.loads(ws.recv())
        if m.get("id") == n[0]:
            return m.get("result", {})
def js(code):
    return (cmd("Runtime.evaluate", expression=code, awaitPromise=True, returnByValue=True).get("result") or {}).get("value")
def nav(path, wait=3):
    cmd("Page.navigate", url=B + path); time.sleep(wait); js("scrollTo(0,0)")
def shot(name, selector=None, height=900, pad=0, y=None):
    if selector:
        r = js(f"(()=>{{const e=document.querySelector({json.dumps(selector)}); if(!e) return null; e.scrollIntoView({{block:'start'}}); const r=e.getBoundingClientRect(); return {{x:r.left+scrollX,y:r.top+scrollY,w:r.width,h:r.height}}}})()")
        time.sleep(0.6)
        if not r:
            print("missing", selector); return
        clip = {"x": max(0, r["x"] - pad), "y": max(0, r["y"] - pad), "width": r["w"] + 2 * pad, "height": min(r["h"] + 2 * pad, height), "scale": 1}
    else:
        clip = {"x": 0, "y": (js("scrollY") or 0) if y is None else y, "width": 1440, "height": height, "scale": 1}
    open(os.path.join(OUT, name + ".png"), "wb").write(base64.b64decode(cmd("Page.captureScreenshot", format="png", clip=clip, captureBeyondViewport=True)["data"]))
    print("saved", name)
cmd("Page.enable"); cmd("Runtime.enable")
cmd("Emulation.setDeviceMetricsOverride", width=1440, height=900, deviceScaleFactor=1, mobile=False)
cmd("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "dark"}])
nav("/", 2); js("localStorage.setItem('guardian-site','all')"); nav("/", 4); shot("01b-all-sites", height=700)
js("(async()=>{const o=await (await fetch('/api/overview')).json();const z=o.sites.find(x=>x.name.includes('Zürich'));localStorage.setItem('guardian-site',z.id)})()"); time.sleep(1)
nav("/", 4); shot("01c-remote-site", height=420)
js("localStorage.setItem('guardian-site','local')"); nav("/", 4); shot("01-dashboard"); shot("02-dashboard-full", height=2000)
for t, name in [("report", "03-report"), ("plan", "04-fix-plan"), ("paths", "05-attack-paths"), ("attack", "05b-attack-matrix"), ("comp", "06-compliance"), ("agents", "07-agents"), ("map", "08-map-chat"), ("log", "09-live-log")]:
    js(f"showTab('{t}')"); time.sleep(2.5)
    if t == "plan":
        js("document.querySelector('#pl-import details') && (document.querySelector('#pl-import details').open = true)"); time.sleep(0.3)
    if t == "attack":
        js("document.querySelector('#at-grid .at-cell') && document.querySelector('#at-grid .at-cell').click()"); time.sleep(0.5)
    if t in ("plan", "comp"):
        js(f"document.querySelector('#{'pl-rows' if t == 'plan' else 'co-list'} details') && (document.querySelector('#{'pl-rows' if t == 'plan' else 'co-list'} details').open = true)"); time.sleep(0.5)
    shot(name, "#workspace", height=1500, pad=6)
for s in ["connectors", "users", "security", "account", "ai", "scope", "evidence", "sites", "schedules", "ticketing", "appearance"]:
    nav(f"/settings#{s}"); shot(f"10-settings-{s}", height=1100)
nav("/settings#connectors", 3)
js("(()=>{const h=[...document.querySelectorAll('#s-connectors *')].find(e=>e.children.length===0&&e.textContent.trim().toLowerCase()==='business systems');if(h){h.scrollIntoView({block:'start'});scrollBy(0,-20)}})()"); time.sleep(0.8)
shot("10-settings-business", height=700)
js("(()=>{const h=[...document.querySelectorAll('#s-connectors *')].find(e=>e.children.length===0&&e.textContent.trim().toLowerCase()==='cloud');if(h){h.scrollIntoView({block:'start'});scrollBy(0,-20)}})()"); time.sleep(0.8)
shot("10-settings-cloud", height=420)
for cat, name in (("infrastructure & storage", "10-settings-infra"), ("scanners", "10-settings-scanners")):
    top = js("(()=>{const h=[...document.querySelectorAll('#s-connectors *')].find(e=>e.children.length===0&&e.textContent.trim().toLowerCase()==='%s');if(!h) return 0;h.scrollIntoView({block:'start'});return h.getBoundingClientRect().top+scrollY-20})()" % cat); time.sleep(0.8)
    shot(name, height=700 if name.endswith("infra") else 470, y=top)
for t, name in [("General", "10-site-general"), ("Ticketing", "10-site-ticketing"), ("Access", "10-site-access"), ("Disclosure", "10-site-disclosure"), ("Decoys", "10-site-decoys"), ("Schedule", "10-site-schedule")]:
    nav("/settings#sites", 2)
    js("(()=>{const z=[...document.querySelectorAll('#si-rows tr')].find(r=>r.textContent.includes('Zürich'));z.querySelector('button').click()})()"); time.sleep(1)
    js(f"[...document.querySelectorAll('#sc-tabs button')].find(x=>x.textContent==='{t}').click()"); time.sleep(1.2)
    shot(name, "#sc-card", height=1000, pad=6)
nav("/vdp/DemoDisclosureLink-0000000000", 2); shot("13-disclosure-page", height=900)
nav("/settings#integrations", 2); shot("10-settings-integrations", height=1500)
nav("/code", 3); js("(()=>{const r=[...document.querySelectorAll('#wc-history tr')][0]; r && r.click()})()"); time.sleep(1.5)
shot("12-web-check", "section[aria-labelledby=wc-title]", height=1800, pad=6)
nav("/fix"); shot("11-fix", height=1400); shot("11-fix-accounts", "section[aria-labelledby=fa-title]", height=1800, pad=6)
nav("/code"); shot("12-code-scan")
nav("/", 3); js("showTab('comp')"); time.sleep(2.5)
js("(()=>{const b=[...document.querySelectorAll('#workspace button')].find(x=>/PCI DSS/i.test(x.textContent));b&&b.click()})()"); time.sleep(1)
shot("06b-compliance-pci", "#workspace", height=900, pad=6)
ws.close(); chrome.terminate()
