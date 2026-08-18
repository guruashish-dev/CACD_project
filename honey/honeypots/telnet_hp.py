"""Telnet honeypot — a fake Linux telnet console.

Presents a realistic ``login:`` / ``Password:`` prompt, captures every
credential attempt, and drops successful logins into a fake shell that
records each command.  Handles raw telnet IAC negotiation bytes so real
``telnet`` clients and telnet brute-forcers behave naturally.
"""

from __future__ import annotations

from .base import BaseHoneypot


def _strip_iac(data: bytes) -> bytes:
    """Remove telnet IAC negotiation sequences from a byte buffer."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b == 0xFF:  # IAC
            if i + 1 < n:
                i += 2  # IAC <command>
            else:
                break
            continue
        out.append(b)
        i += 1
    return bytes(out)


class TelnetHoneypot(BaseHoneypot):
    name = "telnet"

    def _recv_line(self, conn) -> str:
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk:
                break
            data += chunk
            if len(data) > 4096:
                break
        return _strip_iac(data).decode("utf-8", errors="replace").strip()

    # ------------------------------------------------------------------
    def handle(self, conn, addr) -> None:
        self.send_text(conn, self.banner + "\r\n")
        self.send_text(conn, "login: ")
        username = self._recv_line(conn)
        if not username:
            return
        self.send_text(conn, "Password: ")
        password = self._recv_line(conn)
        self.emit_credential(addr, username, password, "success")
        self.send_text(conn, "\r\n")
        self.send_text(conn, "Linux honeypot 5.15.0-86-generic #94-Ubuntu SMP x86_64 GNU/Linux\r\n")
        self.send_text(conn, "Last login: Sun Aug 12 03:14:08 2026 from 10.0.0.7\r\n\r\n")

        while True:
            self.send_text(conn, f"{username}@honeypot:~$ ")
            line = self._recv_line(conn)
            if not line:
                return
            if line in ("exit", "logout"):
                self.send_text(conn, "logout\r\n")
                return
            response = self._respond(line)
            self.emit_command(addr, line, response)
            self.send_text(conn, response)

    def _respond(self, command: str) -> str:
        cmd = command.strip().lower()
        if cmd in ("ls", "ls -la"):
            return ("total 28\r\ndrwxr-xr-x 3 root root 4096 Jul 20 09:00 .\r\n"
                    "drwxr-xr-x 3 root root 4096 Jul 20 09:00 ..\r\n"
                    "-rw-r--r-- 1 root root  112 Jul 20 09:00 .bashrc\r\n")
        if cmd in ("whoami",):
            return "root\r\n"
        if cmd == "id":
            return "uid=0(root) gid=0(root) groups=0(root)\r\n"
        if cmd == "uname -a":
            return "Linux honeypot 5.15.0-86-generic #94-Ubuntu SMP x86_64 GNU/Linux\r\n"
        if cmd in ("pwd",):
            return "/root\r\n"
        return f"-bash: {command}: command not found\r\n"
