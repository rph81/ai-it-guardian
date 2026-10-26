"""Deterministic, read-only data collection. Runs before any agent.

Everything here observes: ARP, nmap service/OS detection, broadcast discovery
(mDNS, UPnP/SSDP), HTTP/TLS banners and a passive WAN lookup. Nothing logs in
to a device or changes its configuration.
"""
import ipaddress
import json
import re
import socket
import subprocess
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from . import netutil

UDP_PORTS = "53,67,69,123,137,161,500,1900,5353,5683,47808"
# admin / service ports outside nmap's top 1000 that matter on small-business networks
EXTRA_TCP = ("1883,2375,2376,2379,3001,3003,4443,5001,5555,5683,6443,7443,8006,8007,8086,8123,8291,8728,"
             "8834,8880,8883,8888,9001,9090,9091,9093,9200,9443,10000,10250,10443,11211,15672,27017,32400,51413")
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ai-guardian-assessment/0.1"}


def run(cmd, timeout=1800):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"ERROR: {e}"


def local_network(iface):
    out = run(["ip", "-4", "-o", "addr", "show", iface])
    m = re.search(r"inet (\S+)", out)
    if not m:
        raise SystemExit(f"no IPv4 address on {iface}")
    me = ipaddress.ip_interface(m.group(1))
    gw = re.search(r"default via (\S+)", run(["ip", "route"]))
    return str(me.network), str(me.ip), gw.group(1) if gw else None


# -- ARP ----------------------------------------------------------------------
def arp_sweep(g, iface):
    out = run(["arp-scan", "--localnet", "--interface", iface, "--retry", "2"], timeout=300)
    n = 0
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            g.merge_asset(parts[0], "arp", mac=parts[1].lower(),
                          mac_vendor=parts[2] if len(parts) > 2 else None)
            n += 1
    g.log("collector", f"ARP sweep found {n} hosts")


# -- nmap ---------------------------------------------------------------------
def parse_nmap_xml(g, xml_text, source):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        g.log("collector", f"{source}: could not parse nmap output")
        return
    for host in root.findall("host"):
        if host.find("status") is not None and host.find("status").get("state") != "up":
            continue
        ip, fields = None, {}
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                fields["mac"] = addr.get("addr").lower()
                fields["mac_vendor"] = addr.get("vendor")
        if not ip:
            continue
        hn = host.find("hostnames/hostname")
        if hn is not None:
            fields["hostname"] = hn.get("name")
        osm = host.find("os/osmatch")
        if osm is not None:
            fields["os_guess"] = f'{osm.get("name")} ({osm.get("accuracy")}%)'
            cpes = [c.text for c in host.findall("os/osmatch/osclass/cpe")]
            fields["os_cpe"] = sorted(set(cpes))[:5]
        ports = []
        for p in host.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            entry = {"proto": p.get("protocol"), "port": int(p.get("portid")),
                     "state": st.get("state") if st is not None else "?"}
            if svc is not None:
                entry.update({k: svc.get(k) for k in ("name", "product", "version", "extrainfo", "tunnel", "devicetype", "ostype") if svc.get(k)})
                entry["service"] = entry.pop("name", "")
                entry["cpe"] = [c.text for c in svc.findall("cpe")]
            scripts = {s.get("id"): s.get("output", "")[:1500] for s in p.findall("script")}
            if scripts:
                entry["scripts"] = scripts
            ports.append(entry)
        g.merge_asset(ip, source, **fields)
        if ports:
            g.set_ports(ip, ports)


def nmap_scan(g, targets):
    g.log("collector", f"TCP service + OS scan of {len(targets)} hosts (top 1000 ports)")
    xml_out = run(["nmap", "-sS", "-sV", "--version-light", "-O", "--osscan-limit",
                   "-T4", "--top-ports", "1000", "-n", "-oX", "-", *targets], timeout=3600)
    parse_nmap_xml(g, xml_out, "nmap-tcp")
    g.log("collector", "TCP scan of extra admin/service ports")
    xml_out = run(["nmap", "-sS", "-sV", "--version-light", "-T4", "-p", EXTRA_TCP,
                   "-n", "-oX", "-", *targets], timeout=3600)
    parse_nmap_xml(g, xml_out, "nmap-tcp-extra")
    g.log("collector", f"UDP scan of key ports ({UDP_PORTS})")
    xml_out = run(["nmap", "-sU", "-sV", "--version-light", "-T4", "-p", UDP_PORTS,
                   "-n", "--max-retries", "1", "-oX", "-", *targets], timeout=3600)
    parse_nmap_xml(g, xml_out, "nmap-udp")


def broadcast_discovery(g, iface, network, me):
    g.log("collector", "Broadcast discovery (mDNS, UPnP, NetBIOS)")
    out = run(["nmap", "-e", iface, "--script",
               "broadcast-dns-service-discovery,broadcast-upnp-info,broadcast-netbios-master-browser",
               "-oX", "-"], timeout=300)
    try:
        root = ET.fromstring(out)
    except ET.ParseError:
        return
    for s in root.findall(".//prescript/script"):
        text = s.get("output", "")
        for block in re.split(r"\n(?=\s{2}\d+\.\d+\.\d+\.\d+)", text):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", block)
            if m and netutil.in_scope(m.group(1), network) and m.group(1) != me:
                a = g.asset(m.group(1))
                a.setdefault("broadcast", {})[s.get("id")] = block.strip()[:2000]


# -- UPnP device descriptions (model / firmware often live here) --------------
def ssdp(g, network):
    g.log("collector", "SSDP search for UPnP device descriptions")
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4)
    sock.sendto(msg, ("239.255.255.250", 1900))
    locations = set()
    try:
        while True:
            data, _ = sock.recvfrom(4096)
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m:
                locations.add(m.group(1).decode(errors="ignore"))
    except socket.timeout:
        pass
    for loc in locations:
        host = urllib.parse.urlparse(loc).hostname
        if not netutil.in_scope(host, network):
            continue
        try:
            body = urllib.request.urlopen(loc, timeout=4).read(200_000)
            root = ET.fromstring(body)
        except Exception:
            continue
        ns = {"u": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
        dev = root.find("u:device", ns) if ns else root.find("device")
        if dev is None:
            continue
        get = lambda t: (dev.findtext(f"u:{t}", namespaces=ns) if ns else dev.findtext(t))
        g.merge_asset(host, "upnp", upnp={
            "location": loc,
            "deviceType": get("deviceType"), "friendlyName": get("friendlyName"),
            "manufacturer": get("manufacturer"), "modelName": get("modelName"),
            "modelNumber": get("modelNumber"), "modelDescription": get("modelDescription"),
            "softwareVersion": get("softwareVersion") or get("firmwareVersion"),
        })


# -- HTTP / TLS banners -------------------------------------------------------
def web_banners(g):
    g.log("collector", "HTTP/TLS banner grab on web ports")
    for ip, a in list(g.data["assets"].items()):
        for p in a["ports"]:
            if p["proto"] != "tcp" or not p.get("state", "").startswith("open"):
                continue
            svc = (p.get("service") or "")
            if "http" not in svc and p["port"] not in (80, 443, 8080, 8443, 5000, 5001, 8006, 8007, 9000, 9443):
                continue
            tls = p.get("tunnel") == "ssl" or "https" in svc or p["port"] in (443, 8443, 5001, 8006, 8007, 9443)
            p["http"] = netutil.http_fetch(f'{"https" if tls else "http"}://{ip}:{p["port"]}/', max_bytes=4000)
            if tls:
                p["tls"] = netutil.tls_inspect(ip, p["port"])


# -- WAN (passive) ------------------------------------------------------------
def wan(g):
    g.log("collector", "Passive WAN lookup (public IP, Shodan InternetDB, UPnP port maps)")
    info = {}
    try:
        info["public_ip"] = urllib.request.urlopen(
            urllib.request.Request("https://api.ipify.org", headers=UA), timeout=10).read().decode().strip()
        r = urllib.request.urlopen(
            urllib.request.Request(f'https://internetdb.shodan.io/{info["public_ip"]}', headers=UA), timeout=15)
        info["internetdb"] = json.loads(r.read())
    except Exception as e:
        info["internetdb_error"] = str(e)
    info["upnp_port_mappings"] = [l for l in run(["upnpc", "-l"], timeout=60).splitlines()
                                  if re.match(r"^\s*\d+\s+(TCP|UDP)", l)]
    g.data["wan"] = info


def collect(g, iface="eth0"):
    network, me, gw = local_network(iface)
    g.data["site"] = {"network": network, "collector_ip": me, "gateway": gw}
    g.log("collector", f"Site network {network}, gateway {gw}, collector {me}")
    arp_sweep(g, iface)
    # also catch hosts that ignore ARP-scan but answer ping/TCP
    out = run(["nmap", "-sn", "-n", "-oX", "-", network], timeout=600)
    parse_nmap_xml(g, out, "nmap-ping")
    g.data["assets"].pop(me, None)
    targets = sorted(g.data["assets"], key=lambda s: tuple(map(int, s.split("."))))
    nmap_scan(g, targets)
    broadcast_discovery(g, iface, network, me)
    ssdp(g, network)
    web_banners(g)
    wan(g)
    g.save()
    g.log("collector", f"Collection done: {len(g.data['assets'])} assets")
