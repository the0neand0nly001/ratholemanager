import argparse
import grp
import importlib.util
import ipaddress
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
AGENT_ROOT = Path("/opt/rathole-manager-agent")
APP_ROOT = Path("/opt/rathole-manager")
DATA_ROOT = Path("/var/lib/rathole-manager")


def run(command):
    subprocess.run(command, check=True)


def save_before(path, backup):
    if path.exists():
        backup.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(str(path), str(backup / path.name))


def write_root(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    os.chown(str(path), 0, 0)


def ensure_packages(packages):
    if packages:
        run(["apt-get", "update"])
        run(["apt-get", "install", "-y", "--no-install-recommends"] + packages)


def ensure_user(name, home):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        run(["useradd", "--system", "--create-home", "--home-dir", str(home), "--shell", "/bin/sh", name])
        return pwd.getpwnam(name)


def secure_code(path):
    for target in [path] + list(path.rglob("*")):
        if target.is_symlink() or not (target.is_dir() or target.is_file()):
            raise RuntimeError("Application code must contain only regular files and directories.")
        os.chown(str(target), 0, 0)
        target.chmod(0o755 if target.is_dir() else 0o644)


def install_agent(arguments):
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", arguments.service):
        raise RuntimeError("Invalid service name.")
    config_path = Path(arguments.config_path)
    if not config_path.is_absolute() or config_path.is_symlink() or not config_path.is_file():
        raise RuntimeError("Point --config-path at the existing regular Rathole config file.")
    run(["systemctl", "show", arguments.service, "--property", "LoadState", "--value"])
    AGENT_ROOT.mkdir(parents=True, exist_ok=True)
    AGENT_ROOT.chmod(0o755)
    os.chown(str(AGENT_ROOT), 0, 0)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = AGENT_ROOT / "installation-backups" / timestamp
    save_before(AGENT_ROOT / "host_agent.py", backup)
    save_before(Path("/etc/rathole-manager-agent.json"), backup)
    save_before(Path("/etc/sudoers.d/rathole-manager"), backup)
    if sys.version_info >= (3, 11):
        interpreter = Path(sys.executable).resolve()
    else:
        if not importlib.util.find_spec("ensurepip"):
            ensure_packages(["python3-venv"])
        venv = AGENT_ROOT / "venv"
        if not (venv / "bin/python").exists():
            run([sys.executable, "-m", "venv", str(venv)])
        interpreter = venv / "bin/python"
        run([str(interpreter), "-m", "pip", "install", "--disable-pip-version-check", "tomli==2.2.1"])
    shutil.copy2(str(ROOT / "host_agent.py"), str(AGENT_ROOT / "host_agent.py"))
    os.chown(str(AGENT_ROOT / "host_agent.py"), 0, 0)
    (AGENT_ROOT / "host_agent.py").chmod(0o644)
    write_root(Path("/etc/rathole-manager-agent.json"), json.dumps({"role": arguments.role, "config_path": str(config_path), "service": arguments.service, "state_dir": "/var/lib/rathole-manager-agent"}, indent=2))
    helper_command = str(interpreter) + " " + str(AGENT_ROOT / "host_agent.py")
    account = ensure_user("rathole-manager", DATA_ROOT)
    write_root(Path("/etc/sudoers.d/rathole-manager"), "rathole-manager ALL=(root) NOPASSWD: " + helper_command + "\n", 0o440)
    run(["visudo", "-cf", "/etc/sudoers.d/rathole-manager"])
    if arguments.public_key_file:
        key = Path(arguments.public_key_file).read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?", key):
            raise RuntimeError("Supply a single public Ed25519 manager key.")
        ssh_directory = DATA_ROOT / ".ssh"
        ssh_directory.mkdir(parents=True, exist_ok=True)
        ssh_directory.chmod(0o700)
        os.chown(str(ssh_directory), account.pw_uid, account.pw_gid)
        authorized = ssh_directory / "authorized_keys"
        save_before(authorized, backup)
        existing = authorized.read_text(encoding="utf-8") if authorized.exists() else ""
        entry = 'restrict,command="sudo -n ' + helper_command + '" ' + key
        if key.split()[1] not in existing:
            existing = existing.rstrip() + ("\n" if existing.strip() else "") + entry + "\n"
        authorized.write_text(existing, encoding="utf-8")
        authorized.chmod(0o600)
        os.chown(str(authorized), account.pw_uid, account.pw_gid)
    print("Installed the restricted " + arguments.role + " agent. Existing Rathole configuration and service were not changed or restarted.")
    return ["sudo", "-n", str(interpreter), str(AGENT_ROOT / "host_agent.py")]


def install_app(arguments):
    if sys.version_info < (3, 11):
        raise RuntimeError("The dashboard needs Python 3.11 or newer. Use a current Debian/Ubuntu LXC; the remote agent supports Python 3.8+.")
    address = ipaddress.ip_address(arguments.listen)
    if not address.is_private or address.is_unspecified:
        raise RuntimeError("Choose a specific private/LAN bind address, not a public or wildcard address.")
    if not 1024 <= arguments.port <= 65535:
        raise RuntimeError("Choose a non-privileged dashboard port between 1024 and 65535.")
    allowed_hosts = [arguments.listen]
    if arguments.base_url:
        from urllib.parse import urlsplit
        base = urlsplit(arguments.base_url)
        if base.scheme not in ("http", "https") or not base.hostname or base.username or base.password or base.query or base.fragment or base.path not in ("", "/"):
            raise RuntimeError("Use an HTTP/HTTPS dashboard base URL without credentials, a path, query or fragment.")
        allowed_hosts.append(base.hostname)
    for hostname in arguments.allowed_host:
        hostname = hostname.strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname):
            raise RuntimeError("Allowed hosts must be exact hostnames without a scheme, port, path or wildcard.")
        allowed_hosts.append(hostname)
    packages = []
    if not importlib.util.find_spec("ensurepip"):
        packages.append("python3-venv")
    if not shutil.which("ssh"):
        packages.append("openssh-client")
    if not shutil.which("sudo"):
        packages.append("sudo")
    ensure_packages(packages)
    account = ensure_user("rathole-manager", DATA_ROOT)
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    DATA_ROOT.chmod(0o700)
    os.chown(str(DATA_ROOT), account.pw_uid, account.pw_gid)
    if arguments.remote_settings:
        remote = json.loads(Path(arguments.remote_settings).read_text(encoding="utf-8"))
        required = ("address", "user", "identity_file", "known_hosts")
        if any(not remote.get(key) for key in required):
            raise RuntimeError("Remote settings need address, user, identity_file and known_hosts.")
    elif Path("/etc/rathole-manager.json").exists():
        remote = json.loads(Path("/etc/rathole-manager.json").read_text())["hosts"]["server"]
    else:
        raise RuntimeError("Provide --remote-settings with the existing remote SSH connection details.")
    for key in ("identity_file", "known_hosts"):
        if not Path(remote[key]).is_file():
            raise RuntimeError("The remote " + key + " file does not exist.")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = Path("/var/backups/rathole-manager-install") / timestamp
    save_before(Path("/etc/rathole-manager.json"), backup)
    save_before(Path("/etc/systemd/system/rathole-manager.service"), backup)
    APP_ROOT.mkdir(parents=True, exist_ok=True)
    APP_ROOT.chmod(0o755)
    os.chown(str(APP_ROOT), 0, 0)
    for directory in ("rathole_manager", "templates", "static"):
        if (APP_ROOT / directory).exists() or (APP_ROOT / directory).is_symlink():
            secure_code(APP_ROOT / directory)
        shutil.copytree(str(ROOT / directory), str(APP_ROOT / directory), dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        secure_code(APP_ROOT / directory)
    for filename in ("requirements.txt", "app.py"):
        if (APP_ROOT / filename).is_symlink():
            raise RuntimeError("Application code must not be a symlink.")
        shutil.copy2(str(ROOT / filename), str(APP_ROOT / filename))
        secure_code(APP_ROOT / filename)
    venv = APP_ROOT / "venv"
    if not (venv / "bin/python").exists():
        run([sys.executable, "-m", "venv", str(venv)])
    run([str(venv / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(APP_ROOT / "requirements.txt")])
    arguments.role = "client"
    arguments.public_key_file = None
    local_command = install_agent(arguments)
    config = {
        "data_dir": str(DATA_ROOT), "port": arguments.port,
        "base_url": arguments.base_url or "http://" + arguments.listen + ":" + str(arguments.port),
        "cookie_secure": bool(arguments.base_url and arguments.base_url.startswith("https://")),
        "monitor_enabled": True,
        "trusted_hosts": list(dict.fromkeys(allowed_hosts)),
        "hosts": {
            "server": {**remote, "role": "server", "name": arguments.relay_name, "transport": "ssh"},
            "client": {"role": "client", "name": arguments.gateway_name, "transport": "local", "command": local_command},
        },
    }
    write_root(Path("/etc/rathole-manager.json"), json.dumps(config, indent=2), 0o644)
    service = """[Unit]
Description=Rathole Manager dashboard
After=network-online.target
Wants=network-online.target

[Service]
User=rathole-manager
Group=rathole-manager
WorkingDirectory=/opt/rathole-manager
Environment=RM_CONFIG=/etc/rathole-manager.json
ExecStart=/opt/rathole-manager/venv/bin/gunicorn --workers 1 --threads 8 --timeout 120 --bind LISTEN_ADDRESS:LISTEN_PORT app:app
Restart=on-failure
RestartSec=3
UMask=0077
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rathole-manager /var/lib/rathole-manager-agent /etc/rathole
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
""".replace("LISTEN_ADDRESS", arguments.listen).replace("LISTEN_PORT", str(arguments.port))
    Path("/var/lib/rathole-manager-agent").mkdir(parents=True, exist_ok=True, mode=0o700)
    write_root(Path("/etc/systemd/system/rathole-manager.service"), service, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "rathole-manager.service"])
    run(["systemctl", "restart", "rathole-manager.service"])
    if subprocess.run(["systemctl", "is-active", "--quiet", "rathole-manager.service"]).returncode:
        raise RuntimeError("The dashboard service did not start. Inspect its journal.")
    print("Dashboard installed at " + config["base_url"] + "/setup")
    print("The one-time setup token is stored privately at /var/lib/rathole-manager/setup-token. Existing tunnel configurations were not rewritten.")


def main():
    parser = argparse.ArgumentParser(description="Install Rathole Manager into an existing Debian/Ubuntu LXC, or its restricted remote host agent.")
    parser.add_argument("mode", choices=("app", "agent"))
    parser.add_argument("--config-path", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--role", choices=("server", "client"), default="server")
    parser.add_argument("--public-key-file")
    parser.add_argument("--remote-settings")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8094)
    parser.add_argument("--base-url")
    parser.add_argument("--relay-name", default="VPS relay")
    parser.add_argument("--gateway-name", default="Local gateway")
    parser.add_argument("--allowed-host", action="append", default=[])
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run this installer as root.")
    if arguments.mode == "agent":
        install_agent(arguments)
    else:
        install_app(arguments)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Installation stopped: " + str(error), file=sys.stderr)
        sys.exit(1)
