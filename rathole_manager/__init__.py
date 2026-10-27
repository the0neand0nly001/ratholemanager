import hmac
import json
import os
import secrets
import threading
from datetime import timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from authlib.integrations.flask_client import OAuth
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from .coordinator import Coordinator
from .hosts import Host
from .model import ManagerError, digest, edit_pair, redact, route_rows, secret_values
from .notifications import notify, start_monitor, validate_webhook
from .storage import Store


def create_app(test_settings=None):
    settings_path = os.environ.get("RM_CONFIG", "/etc/rathole-manager.json")
    settings = json.loads(Path(settings_path).read_text(encoding="utf-8")) if Path(settings_path).is_file() else {}
    if test_settings is not None:
        settings = dict(test_settings)
    preview_directory = os.environ.get("RM_PREVIEW_DIR") if test_settings is None else settings.get("preview_directory")
    preview = bool(preview_directory)
    if preview:
        settings.setdefault("data_dir", str(Path(preview_directory) / "preview-state"))
        settings["hosts"] = {
            "server": {"role": "server", "name": "VPS relay", "transport": "fixture", "fixture_path": str(Path(preview_directory) / "server.toml")},
            "client": {"role": "client", "name": "Local gateway", "transport": "fixture", "fixture_path": str(Path(preview_directory) / "client.toml")},
        }
    store = Store(settings.get("data_dir", "/var/lib/rathole-manager"))
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    session_key = store.get("session_key")
    if not session_key:
        session_key = secrets.token_hex(32)
        store.set("session_key", session_key)
    app.config.update(
        SECRET_KEY=session_key, PORT=int(os.environ.get("RM_PORT", settings.get("port", 8094))),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool(settings.get("cookie_secure", False)),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=1048576,
        WTF_CSRF_TIME_LIMIT=28800, TESTING=bool(settings.get("testing", False)),
    )
    if settings.get("trusted_hosts"):
        app.config["TRUSTED_HOSTS"] = settings["trusted_hosts"]
    csrf = CSRFProtect(app)
    limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["300 per minute"], storage_uri="memory://")
    oauth = OAuth(app)
    hosts = {role: Host({**value, "role": role}) for role, value in settings.get("hosts", {}).items()}
    coordinator = Coordinator(hosts, store) if set(hosts) == {"server", "client"} else None
    app.extensions.update(rm_store=store, rm_coordinator=coordinator, rm_preview=preview)
    if not store.get("admin") and not preview:
        setup_path = store.directory / "setup-token"
        if not setup_path.exists():
            setup_path.write_text(secrets.token_urlsafe(32), encoding="utf-8")
            if os.name != "nt":
                setup_path.chmod(0o600)

    def authenticated(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not preview and not session.get("user"):
                if request.path.startswith("/api/"):
                    return jsonify(error="Sign in to continue."), 401
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def require_hosts():
        if coordinator is None:
            raise ManagerError("Host connections have not been configured by the installer.")
        return coordinator

    def require_live():
        if preview:
            raise ManagerError("This is a local design preview. Live changes and restarts are disabled.")

    @app.before_request
    def restrict_preview():
        if preview and request.remote_addr not in ("127.0.0.1", "::1"):
            return "Local preview is only available on this computer.", 403

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ManagerError)
    def manager_error(error):
        return jsonify(error=str(error)), 409

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        if request.path.startswith("/api/"):
            return jsonify(error="Your session expired. Refresh the page and try again."), 400
        return render_template("login.html", error="Your session expired. Refresh and try again.", setup=False, authentik=False), 400

    @app.get("/healthz")
    @limiter.exempt
    def health():
        return jsonify(status="ok", version="0.1.0", preview=preview)

    @app.route("/setup", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def setup():
        if store.get("admin") or preview:
            return redirect(url_for("login"))
        error = None
        if request.method == "POST":
            setup_path = store.directory / "setup-token"
            supplied = request.form.get("setup_token", "")
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not setup_path.exists() or not hmac.compare_digest(supplied, setup_path.read_text().strip()):
                error = "The setup token is incorrect."
            elif not 1 <= len(username) <= 80 or len(password) < 12:
                error = "Choose a username and a password of at least 12 characters."
            else:
                store.set("admin", {"username": username, "password_hash": generate_password_hash(password)})
                setup_path.unlink()
                session.clear()
                session["user"] = username
                session.permanent = True
                store.event("SETUP_COMPLETE", "Local administrator account created.")
                return redirect(url_for("index"))
        return render_template("login.html", setup=True, error=error, authentik=False)

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def login():
        if preview or session.get("user"):
            return redirect(url_for("index"))
        admin = store.get("admin")
        if not admin:
            return redirect(url_for("setup"))
        error = None
        if request.method == "POST":
            if hmac.compare_digest(request.form.get("username", "").encode("utf-8"), admin["username"].encode("utf-8")) and check_password_hash(admin["password_hash"], request.form.get("password", "")):
                session.clear()
                session["user"] = admin["username"]
                session.permanent = True
                store.event("LOGIN", "Local administrator signed in.")
                return redirect(url_for("index"))
            error = "Username or password is incorrect."
        return render_template("login.html", setup=False, error=error, authentik=store.get("oidc", {}).get("enabled", False))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    def oidc_client():
        oidc = store.get("oidc", {})
        if not oidc.get("enabled"):
            raise ManagerError("Authentik sign-in is not enabled.")
        return oauth.register(
            "authentik", client_id=oidc["client_id"], client_secret=oidc["client_secret"],
            server_metadata_url=oidc["issuer"].rstrip("/") + "/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"}, overwrite=True,
        )

    @app.get("/auth/login")
    def authentik_login():
        base_url = settings.get("base_url", "").rstrip("/")
        if not base_url:
            raise ManagerError("Configure the dashboard base URL before enabling Authentik.")
        return oidc_client().authorize_redirect(base_url + "/auth/callback")

    @app.get("/auth/callback")
    def authentik_callback():
        try:
            token = oidc_client().authorize_access_token()
            user = token.get("userinfo", {})
            email = str(user.get("email", "")).casefold()
            allowed = store.get("oidc", {}).get("allowed_emails", [])
            if email not in allowed or user.get("email_verified") is not True:
                raise ManagerError("This Authentik account is not allowed to administer Rathole.")
            session.clear()
            session["user"] = email
            session.permanent = True
            store.event("LOGIN", "An approved Authentik administrator signed in.")
            return redirect(url_for("index"))
        except ManagerError:
            raise
        except Exception:
            return render_template("login.html", setup=False, authentik=True, error="Authentik sign-in failed. You can still use your local account."), 400

    @app.get("/")
    @authenticated
    def index():
        return render_template("dashboard.html", preview=preview, user=session.get("user", "Local preview"), version="0.1.0")

    @app.get("/api/overview")
    @authenticated
    def overview():
        manager = require_hosts()
        current = manager.read_pair()
        draft = store.draft()
        shown = draft or current
        rows = route_rows(shown["server"], shown["client"], shown.get("disabled", store.get("disabled", {})))
        return jsonify(routes=rows, draft=bool(draft), draft_id=draft["id"] if draft else None, status=manager.status(), preview=preview)

    @app.post("/api/tunnels")
    @authenticated
    def save_tunnel():
        manager = require_hosts()
        change = request.get_json(silent=True) or {}
        with manager.lock:
            draft = store.draft()
            if draft:
                source = draft
            else:
                current = manager.read_pair()
                source = {**current, "disabled": store.get("disabled", {}), "base_hashes": {role: digest(current[role]) for role in ("server", "client")}}
            server, client, disabled = edit_pair(source["server"], source["client"], source.get("disabled", {}), change)
            draft_id = secrets.token_hex(16)
            store.save_draft(draft_id, {"server": server, "client": client, "disabled": disabled, "base_hashes": source["base_hashes"]})
        return jsonify(saved=True, draft_id=draft_id)

    @app.get("/api/preview")
    @authenticated
    def preview_changes():
        draft = store.draft()
        if not draft:
            raise ManagerError("There are no draft changes to preview.")
        return jsonify(require_hosts().preview(draft))

    @app.post("/api/apply")
    @authenticated
    @limiter.limit("5 per minute")
    def apply_changes():
        require_live()
        draft = store.draft()
        payload = request.get_json(silent=True) or {}
        if not draft or payload.get("preview_id") != draft["id"] or not payload.get("confirmed"):
            raise ManagerError("Preview the latest draft before applying it.")
        try:
            result = require_hosts().apply(draft)
        except ManagerError:
            notify(store, "A configuration change failed. Check Activity for the result and any recovery actions.")
            raise
        notify(store, "Reviewed tunnel changes were applied successfully.")
        return jsonify(result)

    @app.post("/api/draft/discard")
    @authenticated
    def discard_draft():
        manager = require_hosts()
        with manager.lock:
            store.clear_draft()
        return jsonify(discarded=True)

    @app.post("/api/hosts/<role>/restart")
    @authenticated
    @limiter.limit("3 per minute")
    def restart_host(role):
        require_live()
        manager = require_hosts()
        if role not in hosts or not (request.get_json(silent=True) or {}).get("confirmed"):
            raise ManagerError("Confirm which host you want to restart Rathole on.")
        if not manager.lock.acquire(blocking=False):
            raise ManagerError("Another configuration operation is running.")
        try:
            result = hosts[role].request("restart")
            store.event("SERVICE_RESTARTED", "Rathole restarted on " + hosts[role].name + ".")
            return jsonify(result)
        finally:
            manager.lock.release()

    @app.get("/api/hosts/<role>/logs")
    @authenticated
    def logs(role):
        if role not in hosts:
            raise ManagerError("Unknown host.")
        values = secret_values(hosts[role].request("read")["content"])
        return jsonify(text=redact(hosts[role].request("logs")["text"], values))

    @app.get("/api/activity")
    @authenticated
    def activity():
        return jsonify(events=store.events())

    @app.route("/api/settings", methods=["GET", "POST"])
    @authenticated
    def preferences():
        notification = store.get("notifications", {})
        oidc = store.get("oidc", {})
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
            webhook = str(payload.get("webhook", "")).strip() or notification.get("webhook", "")
            if webhook:
                validate_webhook(webhook)
            notification = {"enabled": bool(payload.get("discord_enabled")), "webhook": webhook}
            if notification["enabled"] and not webhook:
                raise ManagerError("Add a Discord webhook before enabling notifications.")
            issuer = str(payload.get("issuer", "")).strip().rstrip("/")
            oidc = {"enabled": bool(payload.get("oidc_enabled")), "issuer": issuer, "client_id": str(payload.get("client_id", "")).strip(), "client_secret": str(payload.get("client_secret", "")).strip() or oidc.get("client_secret", ""), "allowed_emails": [email.strip().casefold() for email in str(payload.get("allowed_emails", "")).split(",") if email.strip()]}
            if oidc["enabled"] and (urlsplit(issuer).scheme != "https" or not oidc["client_id"] or not oidc["client_secret"] or not oidc["allowed_emails"] or not settings.get("base_url")):
                raise ManagerError("Authentik needs an HTTPS issuer, client details, approved email addresses and a configured dashboard base URL.")
            store.set("notifications", notification)
            store.set("oidc", oidc)
            store.event("SETTINGS_UPDATED", "Notification and optional sign-in settings updated.")
        return jsonify(discord_enabled=notification.get("enabled", False), webhook_configured=bool(notification.get("webhook")), oidc_enabled=oidc.get("enabled", False), issuer=oidc.get("issuer", ""), client_id=oidc.get("client_id", ""), client_secret_configured=bool(oidc.get("client_secret")), allowed_emails=", ".join(oidc.get("allowed_emails", [])), base_url=settings.get("base_url", ""))

    @app.post("/api/settings/test-discord")
    @authenticated
    @limiter.limit("3 per minute")
    def test_discord():
        require_live()
        notification = store.get("notifications", {})
        if not notification.get("enabled") or not notification.get("webhook"):
            raise ManagerError("Save and enable a Discord webhook first.")
        if not notify(store, "Your notification connection is working."):
            raise ManagerError("Discord did not accept the test notification. Check the webhook and Activity.")
        return jsonify(sent=True)

    if coordinator and not preview and settings.get("monitor_enabled", True) and not app.testing:
        app.extensions["rm_monitor_stop"] = threading.Event()
        start_monitor(coordinator, store, app.extensions["rm_monitor_stop"])
    return app
