"""Base class for every protocol honeypot.

A honeypot is a daemon thread that:

* opens a TCP listener on its configured port,
* accepts connections in a loop, spawning one handler thread per peer,
* emits a ``connection`` event for every peer (so the intel / alert /
  dashboard pipeline sees it immediately),
* delegates protocol-specific I/O to :meth:`handle`, and
* shuts down cleanly on :meth:`shutdown` (close the listener so the
  blocking ``accept`` returns).

Subclasses set ``name`` and implement ``handle(conn, addr)``.
"""

from __future__ import annotations

import socket
import threading

from .. import eventlog
from ..config import DEFAULT_BANNERS, get_config


class BaseHoneypot(threading.Thread):
    name = "base"

    def __init__(self, config: dict | None = None):
        super().__init__(daemon=True)
        self.cfg = config or get_config()
        proto_cfg = self.cfg["protocols"][self.name]
        self.host = self.cfg["bind_host"]
        self.port = proto_cfg["port"]
        self.banner = proto_cfg.get("banner") or DEFAULT_BANNERS.get(self.name, "")
        self.log = eventlog.ConsoleOutput(self.name)
        self._running = threading.Event()
        self._sock: socket.socket | None = None
        self._clients: list[threading.Thread] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def run(self) -> None:
        self._running.set()
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.listen(64)
        except OSError as exc:
            self.log.error(f"cannot bind {self.host}:{self.port} — {exc}")
            self._running.clear()
            return
        self.log.ok(f"listening on {self.host}:{self.port}")
        self.on_listen()

        while self._running.is_set():
            try:
                conn, addr = self._sock.accept()
            except OSError:
                break
            conn.settimeout(60)
            t = threading.Thread(target=self._client, args=(conn, addr), daemon=True)
            self._clients.append(t)
            t.start()

    def shutdown(self) -> None:
        self._running.clear()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def on_listen(self) -> None:
        """Hook for post-bind setup (e.g. SSH host key)."""

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------
    def _client(self, conn: socket.socket, addr) -> None:
        self.emit_connection(addr, self._peer_details(conn))
        try:
            self.handle(conn, addr)
        except (socket.timeout, ConnectionError, OSError):
            pass
        except Exception as exc:  # noqa: BLE001 - keep the server alive
            self.log.debug(f"handler error from {addr[0]}: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def handle(self, conn: socket.socket, addr) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def emit_connection(self, addr, details: dict | None = None) -> None:
        eventlog.emit({
            "kind": "connection",
            "protocol": self.name,
            "src_ip": addr[0],
            "src_port": addr[1],
            "dst_port": self.port,
            "details": details,
        })

    def emit_credential(self, addr, username, password, outcome="failed") -> None:
        eventlog.emit({
            "kind": "credential",
            "protocol": self.name,
            "src_ip": addr[0],
            "src_port": addr[1],
            "username": username,
            "password": password,
            "outcome": outcome,
        })

    def emit_command(self, addr, command, response=None) -> None:
        eventlog.emit({
            "kind": "command",
            "protocol": self.name,
            "src_ip": addr[0],
            "src_port": addr[1],
            "command": command,
            "response": response,
        })

    def recv_line(self, conn: socket.socket) -> str:
        """Read a CRLF- or LF-terminated line (cap 4 KiB)."""
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk:
                break
            data += chunk
            if len(data) > 4096:
                break
        return data.decode("utf-8", errors="replace").strip()

    def send_text(self, conn: socket.socket, text: str) -> None:
        conn.sendall(text.encode("utf-8", errors="replace"))

    @staticmethod
    def _peer_details(conn: socket.socket) -> dict | None:
        try:
            return {"peer": f"{conn.getpeername()[0]}:{conn.getpeername()[1]}"}
        except OSError:
            return None
