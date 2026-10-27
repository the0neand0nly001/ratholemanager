# 🚀 Rathole Manager

Rathole Manager is a lightweight, web-based control panel built with Flask and Python for managing an existing Rathole server/client pair.

It manages the public relay and local gateway from one dashboard, without manually keeping two TOML files in sync.

- 🌐 View configured TCP and UDP tunnels.
- ➕ Add, edit and rename matching tunnel entries.
- ⏸️ Disable and re-enable tunnels without losing their saved settings.
- 🔍 Preview redacted configuration changes before applying them.
- 🖥️ Check both hosts and restart Rathole on either host separately.
- 📜 View recent service logs and configuration activity.
- 🔐 Sign in with a local administrator username and password.
- 🔔 Optionally enable Discord notifications or Authentik sign-in.

---

# 🖥️ Requirements

The dashboard is designed to run in an existing Debian/Ubuntu LXC or Linux host with:

- Python 3.11 or newer.
- systemd.
- An existing Rathole client configuration and service.
- SSH access to the remote Rathole server.

The remote agent supports Python 3.8 or newer. Rathole must already be installed and working on both hosts; the manager does not install or replace it.

---

# 🏗️ Architecture

```text
Web browser
    │
    ▼
Rathole Manager — local gateway / LXC
    │
    ├── Restricted local agent
    │       └── /etc/rathole/client.toml
    │
    └── SSH using a dedicated manager key
            └── Restricted remote agent — VPS
                    └── /etc/rathole/server.toml
```

The dashboard runs only on the gateway. The VPS needs the small restricted agent, not another dashboard or publicly exposed management API.

Existing tokens, Noise keys and transport settings are retained. Adding a new tunnel generates a matching token for both ends.

---

# 📦 Installation

Copy the repository source to both hosts. Keep real configuration files and SSH keys outside the repository.

### 1. Prepare the Gateway

From the repository directory:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends openssh-client sudo

sudo python3 install.py agent \
  --role client \
  --config-path /etc/rathole/client.toml \
  --service rathole-client.service

sudo install -d -m 700 -o rathole-manager -g rathole-manager \
  /var/lib/rathole-manager

sudo -u rathole-manager ssh-keygen -t ed25519 -N '' \
  -f /var/lib/rathole-manager/identity
```

This creates a dedicated identity for the manager. The private key stays on the gateway. Transfer only `identity.pub` to the VPS.

### 2. Install the VPS Agent

On the VPS, from the repository directory:

```bash
sudo python3 install.py agent \
  --role server \
  --config-path /etc/rathole/server.toml \
  --service rathole-server.service \
  --public-key-file /path/to/identity.pub
```

The dedicated SSH account uses a forced command and narrowly scoped sudo permission. It does not receive a general administrative shell through the manager connection.

> **Note:** Agent installation does not rewrite either Rathole configuration or restart the existing tunnels.

### 3. Configure the Remote Connection

Independently verify the VPS SSH host key through its authenticated console. Put the matching trusted entry in:

```text
/var/lib/rathole-manager/known_hosts
```

Give this file to `rathole-manager` with mode `600`. Do not disable host verification or automatically trust a discovery scan.

Create a private `remote-connection.json` outside the repository:

```json
{
  "address": "relay.example.com",
  "port": 22,
  "user": "rathole-manager",
  "identity_file": "/var/lib/rathole-manager/identity",
  "known_hosts": "/var/lib/rathole-manager/known_hosts"
}
```

Replace the address with your actual VPS endpoint.

### 4. Install the Dashboard

On the gateway:

```bash
sudo sh install.sh \
  --config-path /etc/rathole/client.toml \
  --service rathole-client.service \
  --remote-settings /path/to/remote-connection.json \
  --listen 10.0.0.20 \
  --port 8094
```

Replace `10.0.0.20` with the gateway's actual private address. The installer creates the application service and installs its dependencies. It does not configure public forwarding or change firewall rules.

### 5. Create the Administrator

Open the dashboard's `/setup` page. Retrieve its one-time setup token locally on the gateway:

```bash
sudo cat /var/lib/rathole-manager/setup-token
```

Choose an administrator username and a password of at least 12 characters. The setup token is removed after successful setup. There is no default password.

> **Security:** Keep the dashboard private. Use a trusted HTTPS reverse proxy before sending credentials across an untrusted network. Never include the setup token, private keys or database in a public repository.

---

# ⚙️ Configuration

The dashboard's installation settings are stored in:

```text
/etc/rathole-manager.json
```

Each host has its own fixed agent configuration:

```text
/etc/rathole-manager-agent.json
```

| Setting | Purpose |
|---|---|
| `--config-path` | Existing Rathole TOML file on that host |
| `--service` | Existing Rathole systemd unit on that host |
| `--listen` | Specific private address for the dashboard |
| `--port` | Dashboard port; default `8094` |
| `--base-url` | Optional existing HTTPS dashboard URL |
| `--relay-name` | Display name for the VPS relay |
| `--gateway-name` | Display name for the local gateway |
| `--allowed-host` | Additional exact dashboard hostname; repeat for multiple domains |

Restart the dashboard after changing its installation settings. Do not use the browser to supply arbitrary commands or alternative configuration paths.

### 🌐 Cloudflare & Internal Caddy Domains

The same dashboard can be accessed through a Cloudflare Tunnel hostname and an internal Caddy hostname.

```bash
sudo sh install.sh \
  --config-path /etc/rathole/client.toml \
  --service rathole-client.service \
  --listen 10.0.0.20 --port 8094 \
  --base-url https://rathole.example.com \
  --allowed-host ratholemanager.home.lab
```

On the first installation, also include the private `--remote-settings` file. Replace the example private address and public hostname with your own. Keep these options when updating.

Configure the Cloudflare Tunnel origin as `http://10.0.0.20:8094`. Preserve the hostname and require HTTPS at the public edge. No public port forwarding is needed.

For Caddy:

```caddyfile
ratholemanager.home.lab {
    reverse_proxy 10.0.0.20:8094
    tls internal
}
```

The internal hostname must resolve to Caddy, and your device must trust Caddy's internal root certificate.

Both HTTPS hostnames support the local login, with a separate browser session on each. The HTTPS base URL enables secure session cookies, so the plain-HTTP IP address is no longer suitable for staying signed in. Optional Authentik uses the canonical base URL's `/auth/callback` route.

> **Security:** Hostname support does not publish the dashboard by itself. Keep the origin private and do not disable authentication. An additional Cloudflare Access policy is optional.

---

# 🔍 Preview & Apply

1. Add or edit a tunnel in **Tunnels**.
2. Choose **Save to draft**.
3. Review the per-host differences in **Preview**.
4. Confirm **Apply** when a short interruption is acceptable.
5. Check **Activity**, host state and the destination application afterwards.

Saving a draft does **not** change live configurations. The preview hides tokens and private keys and identifies which hosts will change.

On Apply, the manager checks that neither live file changed since the draft was created, validates the pair, stages all changed hosts, then activates the changed configurations. Only affected Rathole units restart.

If a later step fails, it attempts to restore every host whose activation was attempted. Recovery can still fail if a host becomes unreachable or a configuration was independently changed; check **Activity** for the actual result.

> **Warning:** Applying changes may interrupt existing connections. A two-host update is not a single atomic network-wide switch.

Use **Discard draft** to abandon unapplied edits. If a preview becomes stale, refresh and review a new draft instead of overwriting an independent edit.

---

# 🌐 Managing Tunnels

| Action | Result |
|---|---|
| Add | Creates matching server/client entries and a shared token |
| Edit | Changes the name, protocol, public listener or local destination |
| Disable | Removes live entries while retaining their definition privately |
| Enable | Restores a previously disabled definition |
| Delete | Removes the tunnel and its saved definition |

A tunnel has a public listener such as `0.0.0.0:25565` and a local destination such as `10.0.0.30:25565`. These are examples, not predefined routes.

**Listening** means Rathole owns the expected server listener. It does not prove the destination application is healthy. UDP destination health is not tested.

---

# 🔔 Optional Integrations

### Discord

In **Settings**, enter a Discord webhook and enable notifications. A test button checks delivery.

Notifications cover apply results and sustained changes in host/service or expected-listener availability. They do not replace destination application monitoring.

### Authentik

Configure an HTTPS issuer, client ID, client secret and an explicit administrator email allowlist in **Settings**. The dashboard also needs a correctly configured base URL.

The OIDC callback path is:

```text
/auth/callback
```

Local username/password sign-in remains available. An Authentik account is not automatically granted administrator access.

---

# 🖥️ Systemd Service

Rathole Manager runs as:

```text
rathole-manager.service
```

▶️ Start

```bash
sudo systemctl start rathole-manager.service
```

⏹️ Stop

```bash
sudo systemctl stop rathole-manager.service
```

🔄 Restart the Dashboard

```bash
sudo systemctl restart rathole-manager.service
```

📊 Check Status

```bash
sudo systemctl status rathole-manager.service
```

📜 View Logs

```bash
sudo journalctl -u rathole-manager.service -n 100 --no-pager
sudo journalctl -u rathole-manager.service -f
```

Restarting this service restarts the **dashboard**, not Rathole. The **Hosts** page separately restarts Rathole on the selected host; it does not reboot the VPS or gateway.

---

# 🔄 Updating

Preserve the current application code, installation settings and private manager database before updating.

1. Obtain the reviewed updated source on both hosts.
2. Rerun the agent installer on the VPS with its existing config path and service.
3. Rerun the gateway installer using the existing bind address, port and optional base URL/display names.
4. On an existing installation, omit `--remote-settings` to reuse the stored connection if desired.
5. Verify `/healthz`, administrator sign-in and both host connections.

Keep the dashboard and agents on matching versions. The installer restarts the dashboard, not the Rathole services.

---

# 📂 File & Directory Reference

| Resource | Location |
|---|---|
| 📦 Production application | `/opt/rathole-manager` |
| ⚙️ Dashboard configuration | `/etc/rathole-manager.json` |
| 🛡️ Restricted host agent | `/opt/rathole-manager-agent/host_agent.py` |
| ⚙️ Agent configuration, on each host | `/etc/rathole-manager-agent.json` |
| 🔐 Accounts, drafts, disabled tunnels and integration settings | `/var/lib/rathole-manager/manager.sqlite3` |
| 🔑 Dedicated gateway identity | `/var/lib/rathole-manager/identity` |
| 🔒 Trusted VPS host key | `/var/lib/rathole-manager/known_hosts` |
| 🌐 Server configuration, typical | `/etc/rathole/server.toml` |
| 🌐 Client configuration, typical | `/etc/rathole/client.toml` |
| ♻️ Per-host transaction recovery data | `/var/lib/rathole-manager-agent/<transaction>/` |
| 📋 Pre-install app configuration copies | `/var/backups/rathole-manager-install/<timestamp>/` |
| 📋 Pre-install agent configuration copies | `/opt/rathole-manager-agent/installation-backups/<timestamp>/` |
| ⚙️ Dashboard systemd unit | `/etc/systemd/system/rathole-manager.service` |

The private database contains credentials and disabled-tunnel definitions. It is not disposable cache. Configuration recovery copies are small, not whole-host backups.

---

# 🛠️ Troubleshooting

### ❌ Dashboard Will Not Start

```bash
sudo systemctl status rathole-manager.service
sudo journalctl -u rathole-manager.service -n 100 --no-pager
```

Check the configured private bind address and whether the chosen port is already in use.

### 🔌 A Host Is Unreachable

Check its existing Rathole unit, SSH reachability, trusted host key, dedicated public-key entry and fixed agent settings. Never bypass a changed SSH fingerprint to clear an error.

### 📄 Configuration Changes Are Not Applied

Saving only creates a draft. Review **Preview**, confirm **Apply**, then inspect **Activity**. A stale-file warning requires refreshing and reviewing the changes again.

### 📜 Check Rathole Directly

On the VPS:

```bash
sudo systemctl status rathole-server.service
sudo journalctl -u rathole-server.service -n 100 --no-pager
```

On the gateway:

```bash
sudo systemctl status rathole-client.service
sudo journalctl -u rathole-client.service -n 100 --no-pager
```

These are typical unit names; use the actual names configured during installation.

---

# ⏹️ Stop Using the Manager

```bash
sudo systemctl disable --now rathole-manager.service
```

Existing Rathole tunnels continue running. There is no destructive uninstall script. Keep the database and recovery files until any disabled tunnels and retained configuration versions have been accounted for.

---

# 🎯 Summary

Rathole Manager keeps the two ends of an existing Rathole setup together: edit once, review both configurations, then apply deliberately. The interface follows Caddy Manager's dark layout with an inverted accent colour.
