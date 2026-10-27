import secrets
import threading
from concurrent.futures import ThreadPoolExecutor

from .model import ManagerError, digest, preview_diff, route_rows, validate_pair


class Coordinator:
    def __init__(self, hosts, store):
        self.hosts = hosts
        self.store = store
        self.lock = threading.Lock()

    def read_pair(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda role: self.hosts[role].request("read"), ("server", "client")))
        return {"server": results[0]["content"], "client": results[1]["content"]}

    def status(self):
        def read_status(role):
            host = self.hosts[role]
            try:
                return role, {"name": host.name, "reachable": True, **host.request("status")}
            except ManagerError as error:
                return role, {"name": host.name, "state": "unreachable", "reachable": False, "error": str(error), "listeners": []}

        with ThreadPoolExecutor(max_workers=2) as pool:
            return dict(pool.map(read_status, ("server", "client")))

    def preview(self, draft):
        validate_pair(draft["server"], draft["client"])
        current = self.read_pair()
        for role in ("server", "client"):
            if digest(current[role]) != draft["base_hashes"][role]:
                raise ManagerError("A live configuration changed since this draft began. Discard the draft and refresh.")
        diffs = {role: preview_diff(current[role], draft[role]) for role in ("server", "client")}
        changes = [role for role in ("server", "client") if current[role] != draft[role]]
        return {
            "id": draft["id"], "diffs": diffs, "affected_hosts": changes,
            "routes": route_rows(draft["server"], draft["client"], draft.get("disabled", {})),
            "status": self.status(),
            "notice": "Applying restarts Rathole on each changed host. Connections through those hosts may reconnect. Unchanged hosts are not restarted.",
        }

    def apply(self, draft):
        if not self.lock.acquire(blocking=False):
            raise ManagerError("Another configuration operation is already running.")
        transaction = secrets.token_hex(16)
        staged = []
        attempted = []
        try:
            latest = self.store.draft()
            if latest and latest["id"] != draft["id"]:
                raise ManagerError("The draft changed in another session. Preview the latest draft before applying.")
            validate_pair(draft["server"], draft["client"])
            current = self.read_pair()
            changes = [role for role in ("server", "client") if current[role] != draft[role]]
            for role in ("server", "client"):
                if digest(current[role]) != draft["base_hashes"][role]:
                    raise ManagerError("The live configuration changed after preview. Nothing was applied.")
            for role in changes:
                self.hosts[role].request("stage", transaction=transaction, content=draft[role], expected_hash=draft["base_hashes"][role])
                staged.append(role)
            for role in changes:
                attempted.append(role)
                self.hosts[role].request("activate", transaction=transaction)
            verified = self.read_pair()
            if any(verified[role] != draft[role] for role in ("server", "client")):
                raise ManagerError("The applied configuration could not be verified.")
            self.store.set("disabled", draft.get("disabled", {}))
            self.store.clear_draft()
            self.store.event("CONFIG_APPLIED", "Applied reviewed changes to " + (", ".join(changes) or "saved disabled-tunnel settings") + ".")
            return {"applied": True, "changed_hosts": changes}
        except Exception as error:
            failed_restores = []
            for role in reversed(attempted):
                try:
                    self.hosts[role].request("rollback", transaction=transaction)
                except Exception:
                    failed_restores.append(role)
            detail = "Apply failed. "
            if failed_restores:
                detail += "Recovery could not be verified on " + ", ".join(failed_restores) + "; inspect those hosts before retrying."
            elif attempted:
                detail += "Previous configurations were restored on the affected hosts."
            else:
                detail += "No live configuration was changed."
            self.store.event("APPLY_FAILED", detail, "error")
            if isinstance(error, ManagerError):
                detail += " " + str(error)
            raise ManagerError(detail) from error
        finally:
            for role in staged:
                if role not in attempted:
                    try:
                        self.hosts[role].request("discard", transaction=transaction)
                    except Exception:
                        pass
            self.lock.release()
