import json
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .model import ManagerError, address_parts, route_rows


def validate_webhook(url):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ("discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com") or not parts.path.startswith("/api/webhooks/") or parts.username or parts.password or parts.port not in (None, 443):
        raise ManagerError("Use an HTTPS Discord webhook URL.")


def notify(store, message):
    settings = store.get("notifications", {})
    if not settings.get("enabled") or not settings.get("webhook"):
        return False
    validate_webhook(settings["webhook"])
    payload = json.dumps({"content": "**Rathole Manager**\n" + message[:1800], "allowed_mentions": {"parse": []}}).encode("utf-8")
    request = urllib.request.Request(settings["webhook"], data=payload, headers={"Content-Type": "application/json", "User-Agent": "RatholeManager/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=6):
            pass
        return True
    except (OSError, urllib.error.URLError):
        store.event("DISCORD_FAILED", "Discord could not receive the notification. Check the webhook and outbound connection.", "warning")
        return False


def availability(status, rows):
    failed_hosts = [value["name"] for value in status.values() if value.get("state") != "active"]
    if failed_hosts:
        return "Host unavailable: " + ", ".join(failed_hosts)
    listening = {(entry["protocol"], entry["port"]) for entry in status["server"].get("listeners", [])}
    missing = [row["name"] for row in rows if row["enabled"] and (row["protocol"], address_parts(row["bind_addr"])[1]) not in listening]
    if missing:
        return str(len(missing)) + " tunnel listener(s) unavailable: " + ", ".join(missing[:5]) + ("…" if len(missing) > 5 else "")
    return "healthy"


def start_monitor(coordinator, store, stop_event):
    def monitor():
        previous = None
        pending = None
        repetitions = 0
        while not stop_event.wait(30):
            try:
                status = coordinator.status()
                configs = coordinator.read_pair()
                rows = route_rows(configs["server"], configs["client"], store.get("disabled", {}))
                state = availability(status, rows)
            except Exception:
                state = "A host could not be checked."
            if previous is None:
                previous = state
                continue
            if state == previous:
                pending, repetitions = None, 0
                continue
            repetitions = repetitions + 1 if pending == state else 1
            pending = state
            if repetitions >= 2:
                if state == "healthy":
                    message, level = "Both hosts and configured tunnel listeners have recovered.", "info"
                else:
                    message, level = state, "warning"
                store.event("AVAILABILITY_CHANGED", message, level)
                try:
                    notify(store, message)
                except Exception:
                    pass
                previous, pending, repetitions = state, None, 0

    thread = threading.Thread(target=monitor, name="rathole-monitor", daemon=True)
    thread.start()
    return thread
