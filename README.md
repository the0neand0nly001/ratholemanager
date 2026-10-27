# Rathole Manager

A self-hosted control panel for an existing Rathole server/client pair. The interface follows the existing Caddy Manager layout, with charcoal surfaces and rose accents. Its adapted icon retains the original dark badge and branching mark, with rose nodes and **RATHOLE MANAGER** lettering. It is also used as the browser-tab icon.

## Included

- Import both existing TOML files without rewriting them.
- Add, edit, rename, disable, enable and delete matching TCP/UDP tunnels.
- Preserve existing service tokens, Noise keys, transport settings, comments and unrelated tunnel settings.
- Keep edits in a private draft and preview redacted differences per host before applying.
- Stage both changed hosts before activation, reject stale previews, verify installed configuration and attempt rollback on partial failure.
- Show host service state, Rathole listener ports, memory and service logs; restart Rathole on either host independently.
- Local username/password login with hashed passwords, CSRF protection and login throttling.
- Optional Authentik OIDC with an explicit administrator email allowlist; local login remains available.
- Optional Discord notifications for apply results and sustained host/listener state changes.

The current version manages one server/client pair. Host connections are installation settings, not arbitrary commands editable through the browser. Applying config changes restarts Rathole on changed hosts and may interrupt existing connections. A listening port is not proof that its destination application is healthy. UDP application checks are outside this version.

## Local preview

Use Python 3.11+ and an isolated environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:RM_PREVIEW_DIR = 'C:\path\to\private\configuration-copies'
.\.venv\Scripts\python.exe app.py
```

The private folder must contain `server.toml` and `client.toml`. The preview binds to `127.0.0.1:8094`, bypasses login only for loopback, and cannot apply changes or restart services. Drafts and preview settings are stored under `preview-state` inside that private folder. Never put real configurations, tokens, private keys or databases in this source directory or a public repository.

## Install in an existing LXC

The dashboard requires Debian/Ubuntu, systemd and Python 3.11+. It does not replace or install Rathole. The remote agent supports Python 3.8+.

1. Copy the source to both hosts. On the gateway, prepare its restricted local agent and a dedicated manager identity:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends openssh-client sudo
sudo python3 install.py agent \
  --role client \
  --config-path /etc/rathole/client.toml \
  --service rathole-client.service
sudo install -d -m 700 -o rathole-manager -g rathole-manager /var/lib/rathole-manager
sudo -u rathole-manager ssh-keygen -t ed25519 -N '' \
  -f /var/lib/rathole-manager/identity
```

Transfer only `identity.pub` to the VPS. Independently verify its SSH **host** key using its authenticated console, then place the matching trusted entry in `/var/lib/rathole-manager/known_hosts` on the gateway. Give that file to `rathole-manager` with mode 600. Do not blindly trust `ssh-keyscan` output, disable host verification, or distribute a personal/root administration key with this application. The manager's private identity stays on the gateway.
2. On the VPS, install the restricted server agent using the manager's **public** key:

```sh
sudo python3 install.py agent \
  --role server \
  --config-path /etc/rathole/server.toml \
  --service rathole-server.service \
  --public-key-file /path/to/manager.pub
```

This creates a dedicated `rathole-manager` SSH account with a forced command and narrowly scoped sudo access to the root-owned agent. It does not alter the existing Rathole configuration or restart Rathole. On Python versions older than 3.11, its root-owned virtual environment uses tomli 2.2.1 to parse TOML.

3. On the LXC, prepare a private remote-connection JSON file. Example values below are placeholders:

```json
{
  "address": "your-vps-address",
  "port": 22,
  "user": "rathole-manager",
  "identity_file": "/var/lib/rathole-manager/identity",
  "known_hosts": "/var/lib/rathole-manager/known_hosts"
}
```

Both files must be readable by `rathole-manager`; the private identity must have mode 600 and its directory mode 700. Keep the server host key verified. The SSH connection uses the forced agent command; it does not grant a general remote shell.

4. Run the dashboard installer from the source directory. Replace the example bind address with the gateway's actual private address:

```sh
sudo sh install.sh \
  --config-path /etc/rathole/client.toml \
  --service rathole-client.service \
  --remote-settings /path/to/remote-connection.json \
  --listen 10.0.0.20 \
  --port 8094
```

It installs missing Python virtual-environment, SSH-client or sudo packages when needed, creates the root-owned application/agent code and an unprivileged dashboard service, and binds only to the chosen specific private address. No public forwarding, firewall changes or tunnel exposure are configured. Existing local Rathole configuration is not rewritten.

5. Open `/setup` and create a username/password using the private one-time token at `/var/lib/rathole-manager/setup-token`. Passwords must be at least 12 characters. The token is removed after setup. There is no built-in default administrator password.

Optional `--base-url https://your-existing-private-hostname` sets the OIDC callback base URL and secure session cookies. The reverse proxy must already be configured. Authentik also needs its HTTPS issuer, client ID/secret and approved administrator emails in Settings. No Authentik account is automatically granted administrative access.

Optional `--relay-name` and `--gateway-name` set the displayed host names. Installation does not create a public endpoint. Use an existing trusted HTTPS reverse proxy before sending credentials across an untrusted network.

### Multiple domains: Cloudflare and internal Caddy

Both domains can serve the same dashboard. For example, a Cloudflare Tunnel hostname `rathole.example.com` and an internal Caddy hostname `ratholemanager.home.lab` can both proxy to the gateway's private port `8094`. The manager does not create either proxy or a public endpoint.

Include both exact hostnames in the installation settings. One HTTPS base URL is canonical for the optional OIDC callback; other allowed hosts still support local username/password login:

```sh
sudo sh install.sh \
  --config-path /etc/rathole/client.toml \
  --service rathole-client.service \
  --listen 10.0.0.20 --port 8094 \
  --base-url https://rathole.example.com \
  --allowed-host ratholemanager.home.lab
```

For the first installation, also supply `--remote-settings` as described above. `--allowed-host` can be repeated. When updating, keep the same host options. Without an HTTPS base URL, this example's public hostname can instead be added with another `--allowed-host`, but configure secure cookies before public use.

An internal Caddy route would be:

```caddyfile
ratholemanager.home.lab {
    reverse_proxy 10.0.0.20:8094
    tls internal
}
```

The internal hostname must resolve to Caddy and the client device must trust Caddy's internal CA. Configure the Cloudflare Tunnel's origin as `http://10.0.0.20:8094`, preserve the requested hostname and redirect public HTTP to HTTPS. Use the manager login; an additional Cloudflare Access policy is optional. Do not open port 8094 publicly or disable certificate verification to hide a trust problem.

Setting an HTTPS base URL enables `Secure` session cookies for **both** domains. Use the HTTPS domains for sign-in afterwards; the plain-HTTP IP address will no longer retain a login session. Each hostname has its own browser session. Register only the canonical `<base-url>/auth/callback` with Authentik unless intentionally configuring additional callbacks.

## Using the manager

1. Open **Tunnels** and add or edit a TCP/UDP route.
2. Save to draft. Nothing live changes at this point.
3. Review **Preview**: it shows redacted per-host TOML differences and which services will restart.
4. Confirm **Apply** when a brief interruption is acceptable. Only changed hosts are restarted.
5. Check **Activity**, **Hosts** and the destination application after applying.

Disabling a tunnel removes its live entries from both hosts while retaining its definition privately in the manager database. Enabling restores it. Deleting removes its saved definition too. Use **Discard draft** to abandon unapplied changes. Never edit the same live configuration manually while an apply is running.

**Hosts** provides independent Rathole restarts; it does not reboot either machine. **Logs** shows recent redacted service output. Optional Discord and Authentik settings are disabled until configured.

## Updating

Review the new source and preserve `/etc/rathole-manager.json`, `/var/lib/rathole-manager` and a copy of the currently deployed application before updating. The database contains disabled-tunnel definitions and credentials, not just disposable cache.

Run the remote agent installer again from the updated source on the VPS, then rerun the gateway installer using the same bind address, port and optional base URL/display names. On an existing installation, `--remote-settings` may be omitted to retain the stored connection. The installer updates Python dependencies and restarts the **dashboard**, not the existing Rathole units. Verify `/healthz`, sign-in and both hosts afterwards. Keep matching dashboard/agent versions.

## Troubleshooting

```sh
sudo systemctl status rathole-manager.service
sudo journalctl -u rathole-manager.service -n 100 --no-pager
```

If the remote host is unavailable, check SSH reachability, the dedicated public-key entry, trusted host key and restricted agent configuration. Do not work around a changed SSH fingerprint by disabling verification. A stale preview means a live file changed: discard the draft, refresh and review a new one.

To stop using the manager without stopping any tunnels:

```sh
sudo systemctl disable --now rathole-manager.service
```

Do not delete the database, disabled-tunnel definitions or transaction recovery files without first deciding how to preserve them. There is no destructive uninstall script.

## State and recovery

- Application configuration: `/etc/rathole-manager.json`.
- Agent's fixed role, service and config path: `/etc/rathole-manager-agent.json`.
- Private accounts, drafts, disabled-tunnel definitions and optional integration secrets: `/var/lib/rathole-manager/manager.sqlite3`.
- Pre-apply config versions and transaction data: `/var/lib/rathole-manager-agent/<transaction>/` on each affected host, root-only.
- Pre-install configuration copies: `/var/backups/rathole-manager-install/<timestamp>/` and `/opt/rathole-manager-agent/installation-backups/<timestamp>/`.

Staging does not change live configs. Activation replaces the fixed config file atomically, preserves owner/group/mode, restarts the selected Rathole unit and checks its active state. If a later step fails, the coordinator attempts to restore every host whose activation was attempted. An unreachable host or independent configuration edit can prevent automatic recovery; Activity reports that limitation. A cross-host update cannot guarantee an atomic network-wide switch.

Installation rollback is to stop/disable `rathole-manager.service` and restore any pre-install application configuration/service files as appropriate. Agents and their dedicated SSH account can remain unused. Original Rathole configs remain unchanged unless an authenticated administrator explicitly applies a draft. A successful apply's small per-host previous config remains available for recovery.

## Validation

```sh
python -m unittest discover -s tests -v
node --check static/app.js
```

Tests cover preserved tokens/transport, generated matching tokens, redacted previews, authentication/CSRF, stale-config rejection, staged application, partial-failure rollback and protected agent file changes. Linux-only agent file/ownership behaviour is tested on the VPS build host. Live tunnel restarts, live configuration writes, real Discord delivery and a real Authentik round trip require explicit integration testing and are not implied by passing unit tests.

## Design reference

Layout and icon reference: [Caddy Manager](https://github.com/the0neand0nly001/caddymanager). The icon has been adapted with rose accents and Rathole Manager lettering; the Rathole application is implemented separately. See `THIRD_PARTY_NOTICES.md`.
