# Infrastructure agent: firewalls, VMware, Docker, Kubernetes

Reads firewalls, the VMware vSphere platform and container platforms from inside, through their own APIs, the way
Tenable and Qualys configuration audits, firewall analyzers and Kubernetes posture tools (Wiz, Sysdig, kube-bench) do.
Read-only: each connector has a fixed list of API paths or named queries, and anything else is refused. Passwords,
pre-shared keys, private keys and tokens in the answers are replaced by `[hidden]` before the agent sees them.

For a customer site, these checks run **at the customer through its collector**: the connector record is sealed to the
collector's key, and the collector refuses hosts outside the scope set there ([ONSITE-COLLECTOR.md](ONSITE-COLLECTOR.md)).

## Firewall (OPNsense, pfSense, FortiGate, UniFi)

| Vendor | Account | What Guardian reads |
|---|---|---|
| OPNsense | A user with only read pages (status, firmware, firewall rules, VPN status) and an API key + secret | Firmware status and version, system status, filter rules, aliases, services, OpenVPN, IPsec, WireGuard, certificates, interfaces |
| pfSense | The REST API package (pfSense-pkg-RESTAPI), a read-only user and its API key | Version, firewall rules, port forwards, users, web GUI and SSH settings, OpenVPN and IPsec, interfaces, packages |
| FortiGate | A REST API admin with an admin profile set to **Read** everywhere, trusted hosts limited to Guardian / the collector | System status, firmware, licences, policies, VIPs (port forwards), interfaces (admin access on WAN), global settings, admins, password policy, SSL VPN and IPsec, log settings |
| UniFi (UniFi OS) | An API key for the Network application | Application info, sites, devices (firmware, updates) |

The agent looks for firmware with known exploited CVEs, any-to-any rules, inbound rules and port forwards open to the
internet, admin access on the WAN side, admin accounts without two-factor, weak VPN settings and logging off.

## VMware vSphere (vCenter 7.0 or later)

A vSphere SSO user (e.g. `guardian@vsphere.local`) with the **Read-only** role as a global permission. Guardian signs in
to the vCenter REST API, reads, and signs out. Reads: appliance version and health, SSH / shell / console access, NTP,
local password policy, appliance firewall, ESXi hosts, clusters, datastores, VMs, guest identity and VMware Tools state.
Standalone ESXi hosts without vCenter aren't supported.

## Docker

Docker's API has no read-only mode: any access to it is root on the host. Guardian therefore reads through a **socket
proxy** that only allows reading:

```
docker run -d --name guardian-dockerproxy --restart unless-stopped -p <LAN address>:2375:2375 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CONTAINERS=1 -e IMAGES=1 -e INFO=1 -e VERSION=1 -e POST=0 tecnativa/docker-socket-proxy
```

Allow the port only from Guardian or the collector. Reads: version, info (security options), containers (privileged,
host network or PID namespace, user, Docker socket mounted, host paths mounted, published ports, restart policy) and
images (tags, age). The scan also suggests this connector when it finds an open Docker API (port 2375 / 2376), which is
a serious finding on its own.

## Kubernetes

A service account bound to a read-only cluster role that **can't read Secrets or ConfigMaps** (the commands are on the
connector card). The test asks the API what the token may do (SelfSubjectAccessReview, which changes nothing) and warns
if it could create or delete pods, read secrets or bind roles.

| Query | Looks for |
|---|---|
| version, nodes | End-of-life Kubernetes, old kubelets, nodes not ready |
| namespaces | Namespaces without Pod Security labels |
| pods_security | Privileged pods, host network / PID / IPC, containers that may run as root, privilege escalation, added capabilities, hostPath mounts, service-account tokens mounted |
| services_exposed, ingresses | LoadBalancer and NodePort services, ingresses without TLS |
| network_policies | Namespaces without any network policy |
| cluster_admin_bindings | cluster-admin bindings; anything bound to anonymous or all authenticated users |
| rbac_wildcards | Roles with `*` verbs or resources, or that can read secrets |

## Code and tests

Code: `guardian/access.py` (firewall_get, vmware_get, docker_query, k8s_query), connection tests in
`guardian/connectors.py`, the agent brief in `guardian/agents.py`. Tested against stand-in servers (path allow-lists,
secret hiding, summaries, refusal of other paths and queries, on-site job parameters); not yet against real devices.
