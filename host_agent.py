import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib


class AgentError(Exception):
    pass


def checksum(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def parse_config(content, role):
    try:
        data = tomllib.loads(content)
    except Exception:
        raise AgentError("Invalid TOML configuration.")
    if role not in data or not isinstance(data[role], dict):
        raise AgentError("The expected Rathole section is missing.")
    return data


def validate_candidate(current, candidate, role):
    before = parse_config(current, role)
    after = parse_config(candidate, role)
    before_without_services = json.loads(json.dumps(before))
    after_without_services = json.loads(json.dumps(after))
    before_without_services[role].pop("services", None)
    after_without_services[role].pop("services", None)
    if before_without_services != after_without_services:
        raise AgentError("Only tunnel entries can be changed through this agent.")
    allowed = {"type", "token", "nodelay", "bind_addr"} if role == "server" else {"type", "token", "nodelay", "local_addr", "retry_interval"}
    for name, service in after[role].get("services", {}).items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", name) or not isinstance(service, dict):
            raise AgentError("Invalid tunnel entry.")
        if set(service) - allowed or service.get("type", "tcp") not in ("tcp", "udp"):
            raise AgentError("Unsupported tunnel settings.")
        address = service.get("bind_addr" if role == "server" else "local_addr", "")
        if not isinstance(address, str) or not re.fullmatch(r"(?:\[[0-9A-Fa-f:%.]+\]|[A-Za-z0-9_.-]+):\d+", address):
            raise AgentError("Invalid tunnel address.")
        if not 1 <= int(address.rsplit(":", 1)[1]) <= 65535:
            raise AgentError("Invalid tunnel port.")
        if not isinstance(service.get("token", after[role].get("default_token")), str) or not service.get("token", after[role].get("default_token")):
            raise AgentError("A tunnel token is required.")


def redacted_logs(text, config):
    def mask(value, text):
        if isinstance(value, dict):
            for key, child in value.items():
                if any(part in key.lower() for part in ("token", "password", "private_key", "secret")) and isinstance(child, str) and child:
                    text = text.replace(child, "[redacted]")
                text = mask(child, text)
        return text

    text = mask(config, text)
    text = re.sub(r"(?im)(\b(?:token|password|private_key|secret)\s*[=:]\s*)[^\r\n]+", r"\1[redacted]", text)
    return text


class Agent:
    def __init__(self, settings):
        self.settings = settings
        self.role = settings["role"]
        if self.role not in ("server", "client"):
            raise AgentError("Invalid agent role.")
        self.path = Path(settings["config_path"])
        self.state = Path(settings.get("state_dir", "/var/lib/rathole-manager-agent"))
        self.service = settings["service"]
        if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", self.service):
            raise AgentError("Invalid service configuration.")
        self.state.mkdir(parents=True, exist_ok=True)
        self.state.chmod(0o700)

    def read(self):
        if self.path.is_symlink() or not self.path.is_file():
            raise AgentError("The configured Rathole file must be a regular file.")
        return self.path.read_text(encoding="utf-8")

    def transaction_dir(self, transaction):
        if not isinstance(transaction, str) or not re.fullmatch(r"[a-f0-9]{32}", transaction):
            raise AgentError("Invalid transaction identifier.")
        return self.state / transaction

    def active(self):
        result = subprocess.run(["systemctl", "is-active", self.service], capture_output=True, text=True, timeout=8)
        return result.stdout.strip() or "unknown"

    def restart(self):
        result = subprocess.run(["systemctl", "restart", self.service], capture_output=True, text=True, timeout=25)
        if result.returncode:
            raise AgentError("Rathole restart failed. Check the host's service logs.")
        for attempt in range(15):
            if self.active() == "active":
                return {"state": "active"}
            time.sleep(0.2)
        raise AgentError("Rathole did not become active after restart.")

    def atomic_write(self, content):
        metadata = self.path.stat()
        descriptor, temporary_name = tempfile.mkstemp(prefix=".rathole-manager-", dir=str(self.path.parent))
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary_name, metadata.st_mode & 0o777)
            os.chown(temporary_name, metadata.st_uid, metadata.st_gid)
            os.replace(temporary_name, str(self.path))
            directory_descriptor = os.open(str(self.path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

    def status(self):
        content = self.read()
        properties = subprocess.run(
            ["systemctl", "show", self.service, "-p", "MainPID", "-p", "ActiveEnterTimestamp"],
            capture_output=True, text=True, timeout=8,
        )
        values = dict(line.split("=", 1) for line in properties.stdout.splitlines() if "=" in line)
        process_id = int(values.get("MainPID", "0"))
        listeners = []
        if process_id:
            sockets = subprocess.run(["ss", "-H", "-lntup"], capture_output=True, text=True, timeout=8)
            for line in sockets.stdout.splitlines():
                if "pid=" + str(process_id) + "," not in line:
                    continue
                fields = line.split()
                if len(fields) >= 5:
                    address = fields[4]
                    try:
                        listeners.append({"protocol": fields[0], "port": int(address.rsplit(":", 1)[1]), "address": address})
                    except ValueError:
                        pass
        memory = {}
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                key, value = line.split(":", 1)
                if key in ("MemTotal", "MemAvailable"):
                    memory[key] = int(value.strip().split()[0]) * 1024
        except (OSError, ValueError):
            pass
        disk = shutil.disk_usage(str(self.path.parent))
        return {
            "hostname": socket.gethostname(), "role": self.role, "service": self.service,
            "state": self.active(), "pid": process_id, "active_since": values.get("ActiveEnterTimestamp", ""),
            "config_hash": checksum(content), "listeners": listeners,
            "memory_total": memory.get("MemTotal", 0), "memory_available": memory.get("MemAvailable", 0),
            "disk_total": disk.total, "disk_free": disk.free, "load": os.getloadavg()[0],
        }

    def handle(self, request):
        action = request.get("action")
        if action == "read":
            content = self.read()
            return {"content": content, "hash": checksum(content), "role": self.role}
        if action == "status":
            return self.status()
        if action == "logs":
            limit = max(1, min(500, int(request.get("limit", 150))))
            try:
                result = subprocess.run(["journalctl", "-u", self.service, "-n", str(limit), "--no-pager", "-o", "short-iso"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=25)
            except subprocess.TimeoutExpired as error:
                raise AgentError("The service journal took too long to respond. Try again after the host's disk activity settles.") from error
            if result.returncode:
                raise AgentError("Could not read the Rathole service journal.")
            return {"text": redacted_logs(result.stdout, parse_config(self.read(), self.role))}
        if action == "restart":
            return self.restart()
        if action not in ("stage", "activate", "rollback", "discard"):
            raise AgentError("Unsupported agent action.")
        transaction = self.transaction_dir(request.get("transaction"))
        if action == "stage":
            current = self.read()
            if checksum(current) != request.get("expected_hash"):
                raise AgentError("Configuration changed since preview. Refresh and preview again.")
            candidate = request.get("content", "")
            if not isinstance(candidate, str) or len(candidate.encode("utf-8")) > 524288:
                raise AgentError("Configuration is too large.")
            validate_candidate(current, candidate, self.role)
            transaction.mkdir(mode=0o700, exist_ok=False)
            for filename, content in (("before.toml", current), ("candidate.toml", candidate)):
                target = transaction / filename
                target.write_text(content, encoding="utf-8")
                target.chmod(0o600)
            return {"staged": True, "changed": candidate != current}
        if not transaction.is_dir():
            raise AgentError("The staged transaction was not found.")
        before = (transaction / "before.toml").read_text(encoding="utf-8")
        candidate = (transaction / "candidate.toml").read_text(encoding="utf-8")
        current = self.read()
        if action == "activate":
            if checksum(current) != checksum(before):
                raise AgentError("The live configuration changed after staging.")
            if current != candidate:
                validate_candidate(current, candidate, self.role)
                self.atomic_write(candidate)
                self.restart()
            return {"applied": True, "hash": checksum(self.read()), "state": self.active()}
        if action == "rollback":
            if checksum(current) not in (checksum(before), checksum(candidate)):
                raise AgentError("Live configuration changed independently; automatic rollback stopped.")
            if current != before:
                self.atomic_write(before)
                self.restart()
            return {"restored": True, "hash": checksum(self.read()), "state": self.active()}
        if action == "discard":
            for target in transaction.iterdir():
                if target.name not in ("before.toml", "candidate.toml") or not target.is_file():
                    raise AgentError("Unexpected transaction file; cleanup stopped.")
            for target in transaction.iterdir():
                target.unlink()
            transaction.rmdir()
            return {"discarded": True}


def main():
    try:
        settings = json.loads(Path("/etc/rathole-manager-agent.json").read_text(encoding="utf-8"))
        raw = sys.stdin.buffer.read(1048577)
        if len(raw) > 1048576:
            raise AgentError("Request is too large.")
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict):
            raise AgentError("Request must be an object.")
        result = Agent(settings).handle(request)
        print(json.dumps({"ok": True, "result": result}))
    except AgentError as error:
        print(json.dumps({"ok": False, "error": str(error)}))
    except Exception:
        print(json.dumps({"ok": False, "error": "The host operation failed. Check agent installation and service access."}))


if __name__ == "__main__":
    main()
