import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tomlkit
from werkzeug.security import generate_password_hash

from rathole_manager import create_app
from rathole_manager.coordinator import Coordinator
from rathole_manager.model import ManagerError, digest, edit_pair, preview_diff, route_rows, secret_values, validate_pair
from rathole_manager.notifications import availability, validate_webhook
from rathole_manager.storage import Store


SERVER = '''# Keep this comment
[server]
bind_addr = "0.0.0.0:2333"
[server.transport]
type = "noise"
[server.transport.noise]
local_private_key = "synthetic-private-value"
[server.services.minecraft]
type = "tcp"
bind_addr = "0.0.0.0:25565"
token = "synthetic-shared-token"
nodelay = true
'''
CLIENT = '''[client]
remote_addr = "relay.example.com:2333"
[client.transport]
type = "noise"
[client.transport.noise]
remote_public_key = "synthetic-public-value"
[client.services.minecraft]
type = "tcp"
local_addr = "192.168.1.100:25565"
token = "synthetic-shared-token"
retry_interval = 3
'''


class MemoryHost:
    def __init__(self, role, content):
        self.role = role
        self.name = role
        self.content = content
        self.stages = {}
        self.calls = []
        self.fail = None
        self.mutate_on_activate = False

    def request(self, action, **payload):
        self.calls.append(action)
        if action == "read":
            return {"content": self.content, "hash": digest(self.content)}
        if action == "status":
            return {"state": "active", "listeners": [], "role": self.role}
        if action == "stage":
            if digest(self.content) != payload["expected_hash"]:
                raise ManagerError("conflict")
            self.stages[payload["transaction"]] = (self.content, payload["content"])
        if action == "activate" and self.mutate_on_activate:
            self.content = self.stages[payload["transaction"]][1]
        if self.fail == action:
            raise ManagerError("Synthetic operation failure")
        if action == "activate":
            self.content = self.stages[payload["transaction"]][1]
        if action == "rollback":
            self.content = self.stages[payload["transaction"]][0]
        return {"ok": True}


class ModelTests(unittest.TestCase):
    def test_edit_preserves_authentication_transport_and_unknown_untouched_fields(self):
        server, client, disabled = edit_pair(SERVER, CLIENT, {}, {"name": "minecraft", "local_addr": "192.168.1.100:25566", "bind_addr": "0.0.0.0:25565", "protocol": "tcp"})
        before_server, before_client = tomlkit.parse(SERVER), tomlkit.parse(CLIENT)
        after_server, after_client = tomlkit.parse(server), tomlkit.parse(client)
        self.assertEqual(before_server["server"]["transport"], after_server["server"]["transport"])
        self.assertEqual(before_client["client"]["transport"], after_client["client"]["transport"])
        self.assertEqual(before_server["server"]["services"]["minecraft"]["token"], after_server["server"]["services"]["minecraft"]["token"])
        self.assertEqual(after_client["client"]["services"]["minecraft"]["retry_interval"], 3)
        self.assertIn("# Keep this comment", server)
        self.assertFalse(disabled)

    def test_disable_and_reenable_retains_both_tokens(self):
        server, client, disabled = edit_pair(SERVER, CLIENT, {}, {"operation": "disable", "name": "minecraft"})
        self.assertEqual(len(validate_pair(server, client)), 0)
        self.assertFalse(route_rows(server, client, disabled)[0]["enabled"])
        server, client, disabled = edit_pair(server, client, disabled, {"operation": "enable", "name": "minecraft"})
        self.assertEqual(len(validate_pair(server, client)), 1)
        self.assertEqual(secret_values(SERVER, CLIENT), secret_values(server, client))

    def test_new_tunnel_receives_matching_generated_token(self):
        server, client, disabled = edit_pair(SERVER, CLIENT, {}, {"name": "voice", "create": True, "protocol": "udp", "bind_addr": "0.0.0.0:24454", "local_addr": "192.168.1.100:24454"})
        server_token = tomlkit.parse(server)["server"]["services"]["voice"]["token"]
        self.assertGreaterEqual(len(server_token), 32)
        self.assertEqual(server_token, tomlkit.parse(client)["client"]["services"]["voice"]["token"])
        self.assertEqual(len(validate_pair(server, client)), 2)

    def test_client_destination_edit_leaves_server_byte_for_byte_unchanged(self):
        server, client, disabled = edit_pair(SERVER, CLIENT, {}, {"name": "minecraft", "protocol": "tcp", "bind_addr": "0.0.0.0:25565", "local_addr": "192.168.1.100:25566"})
        self.assertEqual(server, SERVER)
        self.assertEqual(client.count("[client.services.minecraft]"), 1)
        self.assertEqual(secret_values(CLIENT), secret_values(client))

    def test_preview_never_exposes_tokens_or_noise_private_keys(self):
        changed = SERVER.replace("25565", "25566")
        difference = preview_diff(SERVER, changed)
        self.assertNotIn("synthetic-shared-token", difference)
        self.assertNotIn("synthetic-private-value", difference)
        self.assertIn("25566", difference)

    def test_pair_mismatch_and_invalid_inputs_are_rejected(self):
        with self.assertRaises(ManagerError):
            validate_pair(SERVER, CLIENT.replace("synthetic-shared-token", "different"))
        for name, address in (("bad;command", "192.168.1.1:80"), ("valid", "example.com:99999"), ("valid", "$(id):80")):
            with self.assertRaises(ManagerError):
                edit_pair(SERVER, CLIENT, {}, {"name": name, "bind_addr": "0.0.0.0:4444", "local_addr": address})


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.store = Store(self.folder.name)
        self.hosts = {"server": MemoryHost("server", SERVER), "client": MemoryHost("client", CLIENT)}
        self.manager = Coordinator(self.hosts, self.store)
        server, client, disabled = edit_pair(SERVER, CLIENT, {}, {"name": "new-route", "create": True, "bind_addr": "0.0.0.0:4444", "local_addr": "192.168.1.100:4444"})
        self.draft = {"id": "test", "server": server, "client": client, "disabled": disabled, "base_hashes": {"server": digest(SERVER), "client": digest(CLIENT)}}

    def tearDown(self):
        self.folder.cleanup()

    def test_both_hosts_are_staged_before_any_activation(self):
        self.hosts["client"].fail = "stage"
        with self.assertRaises(ManagerError):
            self.manager.apply(self.draft)
        self.assertNotIn("activate", self.hosts["server"].calls)
        self.assertEqual(self.hosts["server"].content, SERVER)

    def test_second_activation_failure_rolls_back_both_attempted_hosts(self):
        self.hosts["client"].fail = "activate"
        self.hosts["client"].mutate_on_activate = True
        with self.assertRaisesRegex(ManagerError, "restored"):
            self.manager.apply(self.draft)
        self.assertEqual(self.hosts["server"].content, SERVER)
        self.assertEqual(self.hosts["client"].content, CLIENT)

    def test_stale_preview_cannot_overwrite_external_change(self):
        self.hosts["server"].content = SERVER + "\n# an independent edit\n"
        with self.assertRaises(ManagerError):
            self.manager.apply(self.draft)
        self.assertNotIn("stage", self.hosts["server"].calls)

    def test_apply_verifies_files_and_clears_draft(self):
        self.store.save_draft("test", {key: value for key, value in self.draft.items() if key != "id"})
        result = self.manager.apply(self.draft)
        self.assertTrue(result["applied"])
        self.assertIsNone(self.store.draft())
        self.assertEqual(self.hosts["server"].content, self.draft["server"])

    def test_a_draft_replaced_in_another_session_is_not_applied(self):
        self.store.save_draft("another-session", {key: value for key, value in self.draft.items() if key != "id"})
        with self.assertRaisesRegex(ManagerError, "another session"):
            self.manager.apply(self.draft)
        self.assertNotIn("stage", self.hosts["server"].calls)

    def test_unchanged_host_is_not_restarted(self):
        self.draft["server"] = SERVER
        self.draft["client"] = CLIENT.replace("25565", "25566")
        result = self.manager.apply(self.draft)
        self.assertEqual(result["changed_hosts"], ["client"])
        self.assertNotIn("activate", self.hosts["server"].calls)


class AppTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        root = Path(self.folder.name)
        (root / "server.toml").write_text(SERVER)
        (root / "client.toml").write_text(CLIENT)
        self.app = create_app({"data_dir": str(root / "state"), "preview_directory": str(root), "testing": True})
        self.client = self.app.test_client()

    def tearDown(self):
        self.folder.cleanup()

    def token(self):
        self.client.get("/")
        with self.client.session_transaction() as session:
            from flask_wtf.csrf import generate_csrf
        with self.app.test_request_context():
            token = generate_csrf()
            from flask import session as request_session
            value = request_session["csrf_token"]
        with self.client.session_transaction() as session:
            session["csrf_token"] = value
        return token

    def test_dashboard_and_json_do_not_expose_secrets(self):
        for path in ("/", "/api/overview", "/api/settings"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(b"synthetic-shared-token", response.data)
            self.assertNotIn(b"synthetic-private-value", response.data)

    def test_dashboard_and_sign_in_use_rathole_logo_and_tab_icon(self):
        normal = create_app({"data_dir": str(Path(self.folder.name) / "branding"), "testing": True})
        responses = (self.client.get("/"), normal.test_client().get("/setup"))
        for response in responses:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'rel="icon" type="image/png"', response.data)
            self.assertIn(b"/static/rathole-icon.png?v=2", response.data)
            self.assertNotIn(b"caddy-icon.png", response.data)
        with self.client.get("/static/rathole-icon.png") as image:
            self.assertEqual(image.status_code, 200)
            self.assertEqual(image.mimetype, "image/png")

    def test_mutations_require_csrf_and_preview_cannot_apply(self):
        self.assertEqual(self.client.post("/api/tunnels", json={}).status_code, 400)
        response = self.client.post("/api/apply", json={"confirmed": True}, headers={"X-CSRFToken": self.token()})
        self.assertEqual(response.status_code, 409)
        self.assertIn("preview", response.json["error"])

    def test_preview_is_loopback_only(self):
        response = self.client.get("/", environ_base={"REMOTE_ADDR": "192.168.1.5"})
        self.assertEqual(response.status_code, 403)

    def test_local_login_required_on_normal_install(self):
        app = create_app({"data_dir": str(Path(self.folder.name) / "normal"), "testing": True})
        store = app.extensions["rm_store"]
        store.set("admin", {"username": "test-admin", "password_hash": generate_password_hash("test-only-long-password")})
        client = app.test_client()
        self.assertEqual(client.get("/api/settings").status_code, 401)
        self.assertEqual(client.get("/").status_code, 302)

    def test_configured_discord_secret_is_not_returned(self):
        self.app.extensions["rm_store"].set("notifications", {"enabled": True, "webhook": "https://discord.com/api/webhooks/123/synthetic-secret"})
        response = self.client.get("/api/settings")
        self.assertTrue(response.json["webhook_configured"])
        self.assertNotIn(b"synthetic-secret", response.data)

    def test_both_https_domains_work_but_unknown_hosts_are_rejected(self):
        hosts = ["manager.example.com", "ratholemanager.home.lab"]
        app = create_app({"data_dir": str(Path(self.folder.name) / "domains"), "testing": True, "trusted_hosts": hosts, "cookie_secure": True})
        for hostname in hosts:
            client = app.test_client()
            with client.session_transaction(base_url="https://" + hostname) as session:
                session["user"] = "test-admin"
            self.assertEqual(client.get("/", base_url="https://" + hostname).status_code, 200)
            self.assertTrue(client.get_cookie("session", domain=hostname).secure)
        self.assertEqual(app.test_client().get("/", base_url="https://untrusted.example.com").status_code, 400)


class AgentTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Linux installation permissions")
    def test_installer_normalizes_windows_archive_permissions_and_rejects_symlinks(self):
        spec = importlib.util.spec_from_file_location("manager_installer", Path(__file__).parents[1] / "install.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder) / "application"
            directory.mkdir(mode=0o777)
            script = directory / "app.py"
            script.write_text("fixture")
            script.chmod(0o666)
            with patch.object(module.os, "chown"):
                module.secure_code(directory)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
            self.assertEqual(script.stat().st_mode & 0o777, 0o644)
            (directory / "linked.py").symlink_to(script)
            with patch.object(module.os, "chown"):
                with self.assertRaisesRegex(RuntimeError, "regular files"):
                    module.secure_code(directory)

    def test_logs_are_bounded_and_redact_existing_secrets(self):
        spec = importlib.util.spec_from_file_location("host_agent", Path(__file__).parents[1] / "host_agent.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        agent = object.__new__(module.Agent)
        agent.role = "server"
        agent.service = "fixture.service"
        agent.read = lambda: SERVER
        result = module.subprocess.CompletedProcess([], 0, stdout="synthetic-shared-token synthetic-private-value", stderr="")
        with patch.object(module.subprocess, "run", return_value=result) as command:
            logs = agent.handle({"action": "logs", "limit": 99999})
        self.assertNotIn("synthetic-shared-token", logs["text"])
        self.assertNotIn("synthetic-private-value", logs["text"])
        self.assertIn("500", command.call_args.args[0])
        self.assertEqual(command.call_args.kwargs["timeout"], 25)
        self.assertEqual(command.call_args.kwargs["errors"], "replace")

    def test_slow_journal_returns_an_actionable_error(self):
        spec = importlib.util.spec_from_file_location("host_agent", Path(__file__).parents[1] / "host_agent.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        agent = object.__new__(module.Agent)
        agent.service = "fixture.service"
        with patch.object(module.subprocess, "run", side_effect=module.subprocess.TimeoutExpired("journalctl", 25)):
            with self.assertRaisesRegex(module.AgentError, "journal took too long"):
                agent.handle({"action": "logs"})

    @unittest.skipIf(os.name == "nt", "Linux file ownership is exercised on the VPS build host")
    def test_real_staging_activation_and_rollback_only_touch_the_fixture_file(self):
        spec = importlib.util.spec_from_file_location("host_agent", Path(__file__).parents[1] / "host_agent.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            config_path = Path(folder) / "server.toml"
            config_path.write_text(SERVER)
            agent = module.Agent({"role": "server", "config_path": str(config_path), "service": "fixture.service", "state_dir": str(Path(folder) / "state")})
            agent.restart = lambda: {"state": "active"}
            agent.active = lambda: "active"
            transaction = "a" * 32
            candidate = SERVER.replace("25565", "25566")
            agent.handle({"action": "stage", "transaction": transaction, "content": candidate, "expected_hash": digest(SERVER)})
            self.assertEqual(config_path.read_text(), SERVER)
            agent.handle({"action": "activate", "transaction": transaction})
            self.assertEqual(config_path.read_text(), candidate)
            agent.handle({"action": "rollback", "transaction": transaction})
            self.assertEqual(config_path.read_text(), SERVER)
            config_path.write_text(SERVER + "\n# independent edit\n")
            with self.assertRaises(module.AgentError):
                agent.handle({"action": "rollback", "transaction": transaction})

    def test_agent_refuses_transport_and_key_changes(self):
        spec = importlib.util.spec_from_file_location("host_agent", Path(__file__).parents[1] / "host_agent.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaises(module.AgentError):
            module.validate_candidate(SERVER, SERVER.replace("synthetic-private-value", "another-private-value"), "server")
        module.validate_candidate(SERVER, SERVER.replace("25565", "25566"), "server")

    def test_discord_rejects_non_discord_destinations(self):
        for url in ("http://discord.com/api/webhooks/a/b", "https://localhost/api/webhooks/a/b", "https://discord.com.evil.example/api/webhooks/a/b"):
            with self.assertRaises(ManagerError):
                validate_webhook(url)
        validate_webhook("https://discord.com/api/webhooks/a/b")

    def test_listener_state_does_not_claim_application_health(self):
        status = {"server": {"state": "active", "name": "relay", "listeners": [{"protocol": "tcp", "port": 25565}]}, "client": {"state": "active", "name": "gateway"}}
        self.assertEqual(availability(status, route_rows(SERVER, CLIENT)), "healthy")
        status["server"]["listeners"] = []
        self.assertIn("listener", availability(status, route_rows(SERVER, CLIENT)))


if __name__ == "__main__":
    unittest.main()
