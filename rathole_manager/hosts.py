import json
import subprocess
from pathlib import Path

from .model import ManagerError, digest


class Host:
    def __init__(self, settings):
        self.settings = settings
        self.role = settings["role"]
        self.name = settings.get("name", "VPS relay" if self.role == "server" else "Local gateway")

    def request(self, action, **payload):
        transport = self.settings["transport"]
        if transport == "fixture":
            if action == "read":
                content = Path(self.settings["fixture_path"]).read_text(encoding="utf-8")
                return {"content": content, "hash": digest(content), "role": self.role}
            if action == "status":
                return {"hostname": self.name, "state": "preview", "role": self.role, "listeners": [], "pid": None}
            if action == "logs":
                return {"text": "Local design preview. Live service logs will appear after connecting the host agent."}
            raise ManagerError("This local preview cannot modify or restart live hosts.")
        agent_command = self.settings.get("command", ["sudo", "-n", "/usr/bin/python3", "/opt/rathole-manager-agent/host_agent.py"])
        if transport == "local":
            command = agent_command
        elif transport == "ssh":
            command = [
                "ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no", "-o", "IdentityAgent=none",
                "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
                "-o", "UserKnownHostsFile=" + self.settings["known_hosts"],
                "-i", self.settings["identity_file"], "-p", str(self.settings.get("port", 22)),
                self.settings["user"] + "@" + self.settings["address"],
            ]
        else:
            raise ManagerError("Unsupported host transport.")
        request = {"action": action, **payload}
        try:
            process = subprocess.run(command, input=json.dumps(request), capture_output=True, text=True, timeout=45, encoding="utf-8")
            if process.returncode:
                raise ManagerError(self.name + " could not be reached. Check its SSH or agent connection.")
            response = json.loads(process.stdout)
            if not response.get("ok"):
                raise ManagerError(self.name + ": " + response.get("error", "Host operation failed."))
            return response["result"]
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            raise ManagerError(self.name + " did not return a valid agent response.") from error
