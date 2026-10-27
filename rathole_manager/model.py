import copy
import difflib
import hashlib
import ipaddress
import json
import re
import secrets

import tomlkit


class ManagerError(Exception):
    pass


def digest(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def address_parts(address):
    address = str(address).strip()
    if address.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d+)", address)
        if not match:
            raise ManagerError("Use [IPv6 address]:port for IPv6 destinations.")
        hostname, port = match.groups()
        try:
            ipaddress.IPv6Address(hostname)
        except ValueError as error:
            raise ManagerError("Invalid IPv6 address.") from error
    else:
        if address.count(":") != 1:
            raise ManagerError("Enter an address in hostname:port format.")
        hostname, port = address.rsplit(":", 1)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", hostname) or hostname.startswith("-"):
            raise ManagerError("Invalid hostname or IPv4 address.")
    if not str(port).isdigit() or not 1 <= int(port) <= 65535:
        raise ManagerError("Ports must be between 1 and 65535.")
    return hostname, int(port)


def parse_document(content, role):
    try:
        document = tomlkit.parse(content)
    except Exception as error:
        raise ManagerError("The " + role + " configuration is not valid TOML.") from error
    if role not in document:
        raise ManagerError("The configuration is missing its [" + role + "] section.")
    document[role].setdefault("services", tomlkit.table())
    return document


def secret_values(*contents):
    values = set()

    def visit(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if any(word in key.lower() for word in ("token", "password", "private_key", "secret")):
                    if isinstance(child, str) and child:
                        values.add(child)
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for content in contents:
        try:
            visit(tomlkit.parse(content).unwrap())
        except Exception:
            pass
    return values


def redact(content, values=()):
    for value in sorted(values, key=len, reverse=True):
        if value:
            content = content.replace(value, "[redacted]")
    content = re.sub(
        r"(?im)(\b(?:token|default_token|local_private_key|pkcs12_password|client_secret|password)\s*[=:]\s*)([^\r\n]+)",
        r"\1[redacted]",
        content,
    )
    content = re.sub(r"https://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/[^\s\"']+", "[Discord webhook]", content)
    content = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----", "[private key redacted]", content)
    return content


def effective_token(document, role, service):
    return service.get("token", document[role].get("default_token", ""))


def route_rows(server_content, client_content, disabled=None):
    server = parse_document(server_content, "server")
    client = parse_document(client_content, "client")
    server_services = server["server"]["services"]
    client_services = client["client"]["services"]
    disabled = disabled or {}
    rows = []
    for name in sorted(set(server_services) | set(client_services) | set(disabled)):
        saved = disabled.get(name, {})
        server_entry = server_services.get(name, saved.get("server", {}))
        client_entry = client_services.get(name, saved.get("client", {}))
        enabled = name not in disabled or name in server_services or name in client_services
        problems = []
        if enabled:
            if name not in server_services or name not in client_services:
                problems.append("Missing on " + ("VPS" if name not in server_services else "local client"))
            elif effective_token(server, "server", server_entry) != effective_token(client, "client", client_entry):
                problems.append("Token mismatch")
            if server_entry.get("type", "tcp") != client_entry.get("type", "tcp"):
                problems.append("Protocol mismatch")
        rows.append({
            "name": name,
            "protocol": server_entry.get("type", client_entry.get("type", "tcp")),
            "bind_addr": server_entry.get("bind_addr", ""),
            "local_addr": client_entry.get("local_addr", ""),
            "enabled": enabled,
            "problems": problems,
        })
    return rows


def validate_pair(server_content, client_content):
    server = parse_document(server_content, "server")
    client = parse_document(client_content, "client")
    rows = route_rows(server_content, client_content)
    listeners = set()
    control_address = server["server"].get("bind_addr", "")
    if control_address:
        address_parts(control_address)
    for row in rows:
        if row["problems"]:
            raise ManagerError(row["name"] + ": " + ", ".join(row["problems"]))
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", row["name"]):
            raise ManagerError("Tunnel names may contain letters, numbers, underscores and hyphens.")
        if row["protocol"] not in ("tcp", "udp"):
            raise ManagerError("Tunnel protocol must be TCP or UDP.")
        address_parts(row["bind_addr"])
        address_parts(row["local_addr"])
        listener = (row["protocol"], row["bind_addr"])
        if listener in listeners:
            raise ManagerError("Two tunnels cannot use the same listening address and protocol.")
        if row["protocol"] == "tcp" and row["bind_addr"] == control_address:
            raise ManagerError("A tunnel cannot use Rathole's control listening address.")
        listeners.add(listener)
        service = server["server"]["services"][row["name"]]
        if not effective_token(server, "server", service):
            raise ManagerError("Each tunnel needs an authentication token.")
    return rows


def edit_pair(server_content, client_content, disabled, change):
    server = parse_document(server_content, "server")
    client = parse_document(client_content, "client")
    disabled = copy.deepcopy(disabled or {})
    operation = change.get("operation", "save")
    name = str(change.get("name", "")).strip()
    original = str(change.get("original_name") or name).strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", name):
        raise ManagerError("Give the tunnel a name using letters, numbers, underscores or hyphens.")
    server_services = server["server"]["services"]
    client_services = client["client"]["services"]
    exists = original in server_services or original in client_services or original in disabled
    if operation != "save" and not exists:
        raise ManagerError("That tunnel no longer exists.")
    if operation == "save":
        if name != original and (name in server_services or name in client_services or name in disabled):
            raise ManagerError("A tunnel with that name already exists.")
        if change.get("create") and (name in server_services or name in client_services or name in disabled):
            raise ManagerError("A tunnel with that name already exists.")
        protocol = str(change.get("protocol", "tcp")).lower()
        if protocol not in ("tcp", "udp"):
            raise ManagerError("Choose TCP or UDP.")
        bind_addr = str(change.get("bind_addr", "")).strip()
        local_addr = str(change.get("local_addr", "")).strip()
        address_parts(bind_addr)
        address_parts(local_addr)
        saved = disabled.get(original, {})
        server_entry = copy.deepcopy(server_services.get(original, saved.get("server", tomlkit.table())))
        client_entry = copy.deepcopy(client_services.get(original, saved.get("client", tomlkit.table())))
        token = effective_token(server, "server", server_entry) or effective_token(client, "client", client_entry) or secrets.token_urlsafe(32)
        for entry in (server_entry, client_entry):
            if "type" in entry or protocol != "tcp":
                entry["type"] = protocol
            if not exists:
                entry["token"] = token
        server_entry["bind_addr"] = bind_addr
        client_entry["local_addr"] = local_addr
        was_disabled = original in disabled
        if was_disabled:
            disabled.pop(original, None)
            disabled[name] = {"server": dict(server_entry), "client": dict(client_entry)}
        elif name == original and original in server_services and original in client_services:
            for existing, proposed in ((server_services[original], server_entry), (client_services[original], client_entry)):
                for key, value in proposed.items():
                    if existing.get(key) != value:
                        existing[key] = value
        else:
            for services in (server_services, client_services):
                services.pop(original, None)
            disabled.pop(original, None)
            server_services[name] = server_entry
            client_services[name] = client_entry
    elif operation == "disable":
        if original not in disabled:
            if original not in server_services or original not in client_services:
                raise ManagerError("Repair the missing side before disabling this tunnel.")
            server_entry = copy.deepcopy(dict(server_services[original]))
            client_entry = copy.deepcopy(dict(client_services[original]))
            server_entry["token"] = effective_token(server, "server", server_entry)
            client_entry["token"] = effective_token(client, "client", client_entry)
            disabled[original] = {"server": server_entry, "client": client_entry}
            del server_services[original]
            del client_services[original]
    elif operation == "enable":
        if original in disabled:
            saved = disabled.pop(original)
            server_services[original] = saved["server"]
            client_services[original] = saved["client"]
    elif operation == "delete":
        server_services.pop(original, None)
        client_services.pop(original, None)
        disabled.pop(original, None)
    else:
        raise ManagerError("Unsupported tunnel action.")
    candidates = (tomlkit.dumps(server), tomlkit.dumps(client))
    validate_pair(*candidates)
    return candidates[0], candidates[1], disabled


def preview_diff(before, after):
    values = secret_values(before, after)
    return "\n".join(difflib.unified_diff(
        redact(before, values).splitlines(), redact(after, values).splitlines(),
        fromfile="Current configuration", tofile="Proposed configuration", lineterm="",
    ))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
