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
def shot(name, selector=None, height=900, pad=0):
    if selector:
        r = js(f"(()=>{{const e=document.querySelector({json.dumps(selector)}); if(!e) return null; e.scrollIntoView({{block:'start'}}); const r=e.getBoundingClientRect(); return {{x:r.left+scrollX,y:r.top+scrollY,w:r.width,h:r.height}}}})()")
        time.sleep(0.6)
        if not r:
            print("missing", selector); return
        clip = {"x": max(0, r["x"] - pad), "y": max(0, r["y"] - pad), "width": r["w"] + 2 * pad, "height": min(r["h"] + 2 * pad, height), "scale": 1}
    else:
        clip = {"x": 0, "y": js("scrollY") or 0, "width": 1440, "height": height, "scale": 1}
    open(os.path.join(OUT, name + ".png"), "wb").write(base64.b64decode(cmd("Page.captureScreenshot", format="png", clip=clip, captureBeyondViewport=True)["data"]))
    print("saved", name)
cmd("Page.enable"); cmd("Runtime.enable")
cmd("Emulation.setDeviceMetricsOverride", width=1440, height=900, deviceScaleFactor=1, mobile=False)
cmd("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "dark"}])
nav("/", 4); shot("01-dashboard"); shot("02-dashboard-full", height=2000)
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
nav("/fix"); shot("11-fix", height=1400); shot("11-fix-accounts", "section[aria-labelledby=fa-title]", height=1800, pad=6)
nav("/code"); shot("12-code-scan")
ws.close(); chrome.terminate()
