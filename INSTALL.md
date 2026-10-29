# Installing AI IT Guardian, end to end

This guide takes you from an empty Proxmox server to a working Guardian console with a trusted
certificate, your admin passkey, an API key, and a first assessment. Follow the steps in order. Each step
says **where** you type things (Proxmox web UI, the container's console, your Mac) and **how to check** it worked.

It takes about 45 minutes, most of it waiting for downloads, DNS and the first scan.

---

## 0. What you need before you start

| You need | Why | Example |
|---|---|---|
| A **Proxmox VE** server (8.x or 9.x) on the network you want to assess | Guardian runs in a small container on it | host `lab`, 192.168.1.252 |
| A free **IP address** on that network (or a DHCP reservation) | the console's address | 192.168.1.92 |
| A **domain name** whose DNS you can edit | passkeys and the trusted certificate need a real name | `hadife.com` at GoDaddy |
| An **e-mail address** | Let's Encrypt warns you there if renewal ever fails | |
| A device with **Touch ID, Face ID, Windows Hello** or a security key | you sign in with a passkey | your Mac / iPhone |
| An **Anthropic API key** with billing set up (can be added later) | the AI agents run on it | console.anthropic.com |
| Access to the **GitHub repository** `rph81/ai-it-guardian` (private) | to download the code | |

Nothing on your network needs to be opened to the internet. The console is reachable only on your LAN.

**Words used below**

- **Proxmox web UI**: `https://<proxmox-ip>:8006` in your browser.
- **Container console**: in the Proxmox web UI, click the container (e.g. `303 (ai-guardian)`) → **Console**.
  You log in as `root` with the password you set when creating it.
- Commands are shown in grey boxes. Type or paste them **exactly**, then press Return.

---

## 1. Create the container (Proxmox web UI)

### 1.1 Download the Debian 13 template (once per Proxmox server)

1. In the left tree, click your node (e.g. **lab**) → the storage that holds templates (usually **local**).
2. Click **CT Templates** → **Templates**.
3. Type `debian-13` in the search box, select **debian-13-standard** and click **Download**.
4. Wait until the task log says `TASK OK`, then close it.

### 1.2 Create the container

Click **Create CT** (blue button, top right) and fill in each tab:

| Tab | Field | Value |
|---|---|---|
| General | CT ID | a free number, e.g. `303` |
| | Hostname | `ai-guardian` |
| | Unprivileged container | **ticked** (safer; Guardian works unprivileged) |
| | Nesting | **ticked** (needed by Debian 13's systemd) |
| | Password / Confirm | a strong root password, save it in your password manager |
| Template | Template | `debian-13-standard_…` |
| Disks | Disk size | `16` GiB (8 is the minimum; runs and reports grow over time) |
| CPU | Cores | `2` |
| Memory | Memory / Swap | `2048` / `512` MiB |
| Network | Bridge | `vmbr0` (the bridge on your LAN) |
| | IPv4 | **Static**: `192.168.1.92/24`, Gateway `192.168.1.254` (yours will differ), **or** DHCP with a reservation in your router |
| | IPv6 | leave as is |
| DNS | | leave empty to use the host's settings |
| Confirm | Start after created | **ticked** |

Click **Finish** and wait for `TASK OK`.

### 1.3 Start it with the server, and back it up

1. Click the new container → **Options** → **Start at boot** → **Edit** → tick **Yes** → **OK**.
2. If you use Proxmox Backup Server: **Datacenter** → **Backup** → open your job and make sure the container is
   included (selection mode *All*, or tick it). Guardian's vault is encrypted, so backups don't expose secrets.

**Check:** the container's **Summary** shows *Status: running* and its IP address.

---

## 2. Prepare the container (container console)

Open the container's **Console** and log in as `root`.

```bash
apt-get update && apt-get -y full-upgrade
```

```bash
apt-get install -y git
```

Set the time zone (reports and logs use it). Replace `Europe/Zurich` with yours:

```bash
timedatectl set-timezone Europe/Zurich
```

**Check:** `ip -br a` shows `eth0` with the address you chose. Note the interface name: it's almost always `eth0`.

---

## 3. Get the code (container console)

The repository is private, so the container needs read access to it. Use a **read-only deploy key**:
it can only read this one repository, and you can revoke it at any time.

### 3.1 Create a key in the container

```bash
ssh-keygen -t ed25519 -N "" -C "ai-guardian deploy key" -f /root/.ssh/guardian_deploy
```

```bash
cat /root/.ssh/guardian_deploy.pub
```

Copy the line it prints (starts with `ssh-ed25519`).

### 3.2 Add it to GitHub (browser)

1. Open **github.com/rph81/ai-it-guardian** → **Settings** → **Deploy keys** → **Add deploy key**.
2. Title: `ai-guardian container`. Key: paste the line. **Leave "Allow write access" unticked.**
3. Click **Add key**.

### 3.3 Download the code

```bash
printf 'Host github.com\n  IdentityFile /root/.ssh/guardian_deploy\n  IdentitiesOnly yes\n' >> /root/.ssh/config
```

```bash
git clone git@github.com:rph81/ai-it-guardian.git /root/ai-it-guardian
```

Answer `yes` when asked to trust github.com's key.

**Check:** `ls /root/ai-it-guardian` lists `install.sh`, `console.py`, `guardian`, …

> **No GitHub access from the container?** Download the repository as a ZIP on your Mac
> (GitHub → **Code** → **Download ZIP**), copy it to the Proxmox host with
> `scp ai-it-guardian-main.zip root@<proxmox-ip>:/root/`, then on the host (**lab** → **Shell**):
> `pct push 303 /root/ai-it-guardian-main.zip /root/guardian.zip`, and in the container:
> `apt-get install -y unzip && unzip /root/guardian.zip -d /root && mv /root/ai-it-guardian-main /root/ai-it-guardian`.

---

## 4. Install Guardian (container console)

Replace the hostname and e-mail with yours. The hostname is the name you'll type in the browser;
it must be inside a domain whose DNS you control.

```bash
cd /root/ai-it-guardian
```

```bash
./install.sh --hostname guardian.hadife.com --email you@example.com
```

It installs the system packages (nmap, lego, Python…), copies Guardian to `/opt/ai-guardian`, creates a
Python environment, saves the hostname and e-mail in `/etc/default/ai-guardian`, and starts the console
service. It takes 2–5 minutes. At the end it prints:

```
Installed. Console service: active
First-time setup code: 3f9a1c-77b2e0-c41d8a
Next: get a trusted certificate with  /opt/ai-guardian/guardian-cert-setup.sh
```

**Write down the setup code.** You need it once, in step 6. (You can show it again with
`cat /opt/ai-guardian/console/setup-code` until the first admin is created; then it disappears.)

**Check:** `systemctl status ai-guardian-console` shows `active (running)`.

---

## 5. DNS records and trusted certificate

Passkeys only work on a page with a real hostname and a certificate your browser trusts. Guardian gets a
free Let's Encrypt certificate using a **DNS check**, so nothing has to be reachable from the internet.

### 5.1 Ask Guardian which records to create (container console)

```bash
/opt/ai-guardian/guardian-cert-setup.sh
```

It registers a free account at acme-dns.io (used only to answer Let's Encrypt's check) and prints a table like:

```
Type   Name                        Value                                                   TTL
CNAME  _acme-challenge.guardian    aa65f650-cc87-4c60-b6ac-2e904f9a66bd.auth.acme-dns.io   1 hour
A      guardian                    192.168.1.92                                            1 hour
```

### 5.2 Create the two records at your DNS provider (browser)

GoDaddy example: **My Products** → your domain → **DNS** → **Add New Record**.

1. **Type** `CNAME`, **Name** `_acme-challenge.guardian`, **Value** the long `….auth.acme-dns.io` name, TTL 1 hour → **Save**.
2. **Type** `A`, **Name** `guardian`, **Value** the container's IP (e.g. `192.168.1.92`), TTL 1 hour → **Save**.

Why an A record with a private address: it lets every device on your network find the console by name.
From the internet the address leads nowhere, so nothing is exposed.

### 5.3 Get the certificate (container console)

Wait 5 minutes (DNS needs time to update), then run the same script again:

```bash
/opt/ai-guardian/guardian-cert-setup.sh
```

- If it prints the table again with `Currently seen: CNAME=none`, the record isn't visible yet: wait a few
  more minutes and retry.
- When the records are found it requests the certificate (up to 3 minutes), restarts the console with it and
  turns on the daily renewal check. It ends with `Done. Open https://guardian.hadife.com:8443`.

**Check:** `systemctl list-timers guardian-cert.timer` shows the next run, and
`journalctl -u ai-guardian-console -n 5` contains `with Let's Encrypt certificate`.

---

## 6. Create the first admin (browser)

1. On your computer, open **https://guardian.hadife.com:8443** (your hostname). There must be no certificate warning.
   *If the page doesn't load:* your computer may not see the new A record yet; wait, or flush DNS
   (Mac: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`).
2. The page asks for the **setup code**: paste it from step 4. Enter your **name** and **e-mail**.
3. Your browser asks to create a **passkey**: confirm with Touch ID / Face ID / Windows Hello.
   Use a device that supports passkey PRF (current Safari, Chrome, Edge, iCloud Keychain, 1Password, Windows Hello,
   recent YubiKeys); the page tells you if yours doesn't.
4. Guardian shows your **recovery key** once. **Save it in your password manager or print it.** It's the only way
   back in if you lose every passkey; nobody, not even someone with root on the container, can recover the vault without it.
5. You land on the console, signed in as **Admin**, with the vault unlocked.

**Add a second passkey now** (Settings → My account → *Add a passkey*), e.g. your phone or a YubiKey, so losing one
device never locks you out.

---

## 7. Add the API keys (browser)

1. **Settings** → **AI agents**.
2. **Anthropic API key**: create one at **console.anthropic.com → Settings → API Keys** (billing must be set up),
   paste it, click **Save**. The field shows *✓ set*; the key is stored encrypted in the vault and never shown again.
3. Optional, **NVD API key**: free at nvd.nist.gov/developers/request-an-api-key; makes vulnerability lookups ~8× faster.
4. Optional: model (Opus 5.5 is the default; Fable 5.1 is stronger and ~2.5× the cost), effort, rounds,
   how many agents work at the same time, and which specialists are on.

The vault locks itself after 30 minutes idle (Settings → Security & vault). Unlocking takes one Touch ID.

---

## 8. First assessment (browser)

1. In the console, click **Scan only** first (about 7 minutes, free). Follow it in **Live log**.
2. When it's done, open **Settings → Connectors**: Guardian suggests read-only connectors for what it found
   (Synology, Proxmox, Linux servers, …). Optional for now.
3. Click **Run AI** on that scan (or **Scan + AI assessment** for a fresh scan). Typical cost on Opus 5.5:
   **$4–7** for ~35 devices.
4. While it runs:
   - **Agents** tab: one card per agent, with what it is doing right now, rounds, findings and cost so far.
   - **Map & chat** tab: the Orchestrator in the centre, the agents around it, and every order, check, finding
     and note between agents as it happens. A purple line stays between two agents once they've exchanged a note;
     click it to read the notes and what the receiving agent did.
   - **Chat**: ask the Orchestrator about the run, or ask for a re-check. It proposes an order; nothing is sent until
     you click **Send order**.
5. When it finishes, the **Report** tab opens: score, executive summary, fix-first list, every finding with evidence.
   After the run, **Replay run** on the map plays the whole run again.

---

## 9. Add people (optional)

### 9.1 Roles

| Role | Can |
|---|---|
| Viewer | read reports, the agent map, and ask the chat questions (when the vault is unlocked) |
| Operator | + start and stop scans, send orders to agents, manage connectors |
| Admin | + users, API keys, security settings, audit log |

### 9.2 Invite

**Settings → Users & access → Invite someone**: their e-mail and role. Guardian shows a one-time link
(valid 7 days, only for that e-mail). Send it to them yourself. They open it, sign in, and create their passkey.

### 9.3 Google / Microsoft sign-in (optional)

Without this, people sign in with a passkey only. To let them sign in with their Google or Microsoft account:

- **Google**: console.cloud.google.com → **APIs & Services** → **Credentials** → **Create credentials** →
  **OAuth client ID** → *Web application*. Authorised redirect URI:
  `https://guardian.hadife.com:8443/auth/callback/google`. Copy the client ID and secret.
- **Microsoft**: entra.microsoft.com → **App registrations** → **New registration**. Supported account types:
  *Accounts in any organizational directory and personal Microsoft accounts*. Redirect URI (*Web*):
  `https://guardian.hadife.com:8443/auth/callback/microsoft`. Then **Certificates & secrets** → **New client secret**.
  Copy the Application (client) ID and the secret value.

Paste them in **Settings → Security & vault → Sign-in providers** and save. The exact redirect URI to register is shown
there too.

---

## 10. Keeping it up to date

When new code is pushed to GitHub, in the container console:

```bash
cd /root/ai-it-guardian && git pull && ./install.sh
```

`install.sh` without options keeps your hostname, e-mail, settings, vault, users, runs and certificate.
**Check:** `systemctl status ai-guardian-console` is `active (running)` and the console loads.

---

## 11. Command line (optional)

Everything is in the console, but runs can also be started in the container console:

```bash
cd /opt/ai-guardian
```

| Command | What it does |
|---|---|
| `./venv/bin/python run.py --collect-only` | scan only, no AI (free) |
| `./venv/bin/python run.py --report runs/<run>` | rebuild a report |

AI runs from the command line need the API key in the environment for that one command, because the key lives in the
vault, not on disk. Type it without it being shown or saved:

```bash
read -rsp "API key: " K && ANTHROPIC_API_KEY=$K ./venv/bin/python run.py; unset K
```

---

## 12. Where things are

| Path | What |
|---|---|
| `/opt/ai-guardian` | the installed program |
| `/opt/ai-guardian/console/guardian.db` | users, passkeys, encrypted vault (connectors, API keys, SSH key), audit log |
| `/opt/ai-guardian/console/acme/` | certificate and acme-dns account |
| `/opt/ai-guardian/runs/<date-time>/` | each run: `graph.json` (all data), `events.jsonl` (agent map), `chat.json`, `report.html` |
| `/opt/ai-guardian/.env` | non-secret settings (model, effort, agents on/off) |
| `/etc/default/ai-guardian` | hostname and certificate e-mail |
| services | `ai-guardian-console` (the console), `guardian-cert.timer` (daily renewal check) |

---

## 13. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Browser can't reach the page | `systemctl status ai-guardian-console`; if stopped, `journalctl -u ai-guardian-console -n 50` shows why. Check the A record resolves to the container: `nslookup guardian.hadife.com`. |
| Certificate warning | the certificate wasn't issued yet: run step 5.3 again and read its message. |
| `guardian-cert-setup.sh` keeps saying `CNAME=none` | the record name must be `_acme-challenge.guardian` (your provider adds the domain). Wait 10 minutes; check with `nslookup -type=CNAME _acme-challenge.guardian.hadife.com 1.1.1.1`. |
| "This passkey can't unlock the vault" | the device or password manager doesn't support PRF. Use another one, then add it under My account. |
| Lost all passkeys | sign-in page → *Use recovery key*. Then add a new passkey and replace the recovery key (Settings → Security & vault). |
| Setup code lost before the first admin | `cat /opt/ai-guardian/console/setup-code` |
| "Unlock the vault" when starting an AI run | the vault auto-locked; click **Unlock** (Touch ID). |
| AI run fails immediately | Live log shows the reason: no key, wrong key, or no API credit (console.anthropic.com → Billing). |
| Scan finds nothing | the interface name: `ip -br a`, then set `GUARDIAN_IFACE=` in `/opt/ai-guardian/.env`. |

---

## 14. Removing it

1. Proxmox web UI → the container → **Shutdown**, then **More** → **Remove** (tick *Purge from job configurations*).
2. GitHub → repository **Settings** → **Deploy keys** → delete `ai-guardian container`.
3. Your DNS provider: delete the `guardian` A record and the `_acme-challenge.guardian` CNAME.
4. Anthropic console: delete the API key Guardian used.
5. Google / Microsoft: delete the OAuth app, if you created one.

---

## Security, in short

- **Read-only.** Agents have no shell and no credentials for your devices; they run fixed, non-intrusive checks
  on your own network only. The chat proposes orders; a person confirms each one. Nothing on the network is changed.
- **Secrets are encrypted** with a key that is only in memory while someone with a passkey has unlocked the vault.
  Reading the files on disk, or a backup of them, gives nothing usable.
- **No inbound internet access** is needed or opened. Outbound: Anthropic API, NVD, CISA, endoflife.date,
  Shodan InternetDB, Let's Encrypt, acme-dns.io.
- Every sign-in, setting change, secret use and agent order is in the tamper-evident audit log
  (Settings → Security & vault → Audit log).
