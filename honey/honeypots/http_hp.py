"""HTTP honeypot — a fake Apache server with decoy "vulnerable" paths.

Attracts web scanners / SQLi probes / credential-stuffing bots and records
every request: method, path, query string, headers, user-agent and POST
body.  Login-form submissions (``user``/``pass`` style fields) are parsed
and captured as credentials.  Sensitive paths return convincing decoy
content so scanners keep digging; everything else gets an Apache-style 404.
"""

from __future__ import annotations

import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .base import BaseHoneypot

_FIELD_RE = re.compile(
    r"(?:user|username|login|email|log|name|pass|passwd|password|pwd)"
    r"[\s=:'\"\[\]]{0,5}([^\s&\"'<>]{3,64})", re.IGNORECASE)


class _HTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30
    server_version = "Apache/2.4.52 (Ubuntu)"
    sys_version = ""

    # -- BaseHTTPRequestHandler API -----------------------------------
    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_HEAD(self):
        self._dispatch()

    def do_PUT(self):
        self._dispatch()

    def do_OPTIONS(self):
        self._dispatch()

    def log_message(self, *args):  # silence default access log
        pass

    # -- Core ----------------------------------------------------------
    def _dispatch(self) -> None:
        hp: HTTPHoneypot = self.server.hp
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        addr = (self.client_address[0], self.client_address[1])

        details = {
            "method": self.command,
            "path": parsed.path,
            "query": parsed.query or None,
            "user_agent": self.headers.get("User-Agent", ""),
            "referer": self.headers.get("Referer") or None,
            "auth": self.headers.get("Authorization") or None,
            "body": body or None,
        }
        hp.emit_connection(addr, details)

        self._capture_credentials(hp, addr, parsed.path, query, body)
        self._respond(hp, parsed.path, query, body)

    def _capture_credentials(self, hp, addr, path, query, body) -> None:
        # 1) Basic Auth header
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("basic "):
            import base64
            try:
                raw = base64.b64decode(auth.split(None, 1)[1]).decode("utf-8", "replace")
                if ":" in raw:
                    user, pwd = raw.split(":", 1)
                    hp.emit_credential(addr, user, pwd, "attempted")
            except Exception:
                pass
        # 2) GET query params (wp-login.php?log=admin&pwd=x)
        fields = []
        for key, values in query.items():
            if key.lower() in ("user", "username", "login", "log", "name", "email"):
                fields.append(values[0])
            elif key.lower() in ("pass", "pwd", "password", "passwd"):
                fields.append(values[0])
        if len(fields) >= 1:
            user = fields[0]
            pwd = fields[1] if len(fields) >= 2 else ""
            hp.emit_credential(addr, user, pwd, "attempted")
        # 3) POST body field pairs
        if body:
            self._capture_form(hp, addr, body)

    def _capture_form(self, hp, addr, body: str) -> None:
        """Pull user/password pairs out of form-encoded / JSON bodies."""
        # Normalise common separators so our regex can see key=value pairs.
        norm = body.replace("&", " ").replace(",", " ")
        pairs = re.findall(r"([\w.@-]+)\s*=\s*([^\s]{1,128})", norm)
        credentials = {}
        for key, value in pairs:
            lk = key.lower()
            if lk in ("user", "username", "login", "email", "log", "name", "account"):
                credentials["user"] = value
            elif lk in ("pass", "passwd", "password", "pwd", "user_pass"):
                credentials["pass"] = value
        if "user" in credentials:
            hp.emit_credential(addr, credentials["user"], credentials.get("pass", ""), "attempted")

    def _respond(self, hp: HTTPHoneypot, path: str, query, body) -> None:
        page, status = hp.decoy_page(path)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8" if page.startswith("<") else "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(page.encode("utf-8"))))
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))


class HTTPHoneypot(BaseHoneypot):
    name = "http"

    def __init__(self, config=None):
        super().__init__(config)
        self.decoy_paths = self.cfg.get("http_decoy_paths", ["/"])
        self._server: ThreadingHTTPServer | None = None

    # ------------------------------------------------------------------
    def run(self) -> None:
        self._running.set()
        try:
            self._server = ThreadingHTTPServer((self.host, self.port), _HTTPHandler)
            self._server.hp = self
        except OSError as exc:
            self.log.error(f"cannot bind {self.host}:{self.port} — {exc}")
            self._running.clear()
            return
        self.log.ok(f"listening on {self.host}:{self.port}")
        self._server.serve_forever(poll_interval=0.1)

    def shutdown(self) -> None:
        self._running.clear()
        if self._server is not None:
            threading.Thread(target=self._server.shutdown, daemon=True).start()
            self._server.server_close()

    # ------------------------------------------------------------------
    def decoy_page(self, path: str) -> tuple[str, int]:
        p = path.split("?", 1)[0].lower()
        if p in ("/", "/index.html", "/index.php"):
            return self._html_index(), 200
        if p in ("/wp-login.php", "/wp-login", "/login", "/admin/login.php", "/signin"):
            return self._html_login(), 200
        if p.startswith("/phpmyadmin"):
            return self._html_phpmyadmin(), 200
        if p in ("/.env", "/env"):
            return ("APP_ENV=production\nDB_HOST=localhost\nDB_USER=root\n"
                    "DB_PASS=S3cr3t_Pa55!\nSECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"), 200
        if p in ("/.git/config", "/.git/HEAD"):
            return ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                    "\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n"
                    "\turl = git@github.com:internal-app.git\n"), 200
        if p in ("/admin", "/admin/", "/administrator", "/manager", "/manager/html"):
            return self._html_admin(), 200
        if p in ("/api/v1/users", "/api/users", "/api/v1/user"):
            return ('[{"id":1,"email":"admin@corp.local","role":"admin","token":"eyJhbGciOiJSUzI1NiJ9"},'
                    '{"id":2,"email":"ops@corp.local","role":"ops"}]'), 200
        if p in ("/backup.zip", "/db.sql", "/config.php.bak", "/config.old"):
            return "PK\x03\x04" + "backup...", 200
        if p in ("/old/", "/test/", "/dev/", "/temp/"):
            return self._html_index(), 200
        return ("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                "<html><head><title>404 Not Found</title></head><body>\n"
                f"<h1>Not Found</h1>\n<p>The requested URL {path} was not found on this server.</p>\n"
                "<address>Apache/2.4.52 (Ubuntu) Server at localhost Port 80</address></body></html>\n"), 404

    @staticmethod
    def _html_login() -> str:
        return """<!DOCTYPE html><html><head><title>Sign In</title></head><body style="font-family:sans-serif">
<h2>Welcome Back</h2><form method="post" action="/login">
<label>Username <input type="text" name="log" required></label><br>
<label>Password <input type="password" name="pwd" required></label><br>
<input type="submit" value="Log In"></form></body></html>"""

    @staticmethod
    def _html_phpmyadmin() -> str:
        return """<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body style="font-family:sans-serif">
<h1>phpMyAdmin</h1><form method="post"><label>Username <input name="pma_username"></label><br>
<label>Password <input name="pma_password" type="password"></label><br>
<input type="submit" value="Go"></form></body></html>"""

    @staticmethod
    def _html_admin() -> str:
        return """<!DOCTYPE html><html><head><title>Administration</title></head><body style="font-family:sans-serif">
<h1>System Administration</h1><form method="post"><label>User <input name="user"></label><br>
<label>Pass <input name="pass" type="password"></label><br><input type="submit" value="Login"></form>
<p>Status: Apache/2.4.52 (Ubuntu) PHP/8.1.2</p></body></html>"""

    @staticmethod
    def _html_index() -> str:
        return """<!DOCTYPE html><html><head><title>Corporate Intranet</title></head><body style="font-family:sans-serif">
<h1>Welcome to the Corporate Intranet</h1><p>This is an internal web application.</p>
<p><a href="/wp-login.php">Login</a> | <a href="/phpmyadmin/">DB Admin</a> | <a href="/admin/">Administration</a></p></body></html>"""
