"""SMTP honeypot — a fake Postfix mail server.

Walks an attacker through a believable SMTP session (HELO / MAIL FROM /
RCPT TO / DATA / VRFY), accepts AUTH PLAIN and AUTH LOGIN to harvest
credentials, and swallows submitted mail as an open-relay trap.  Every
command and message is recorded; RCPT bursts are picked up by the
spam-relay detection rules.
"""

from __future__ import annotations

import base64
import secrets

from .base import BaseHoneypot

_AUTH_OK = "235 2.7.0 Authentication successful\r\n"
_AUTH_BAD = "535 5.7.8 Error: authentication failed\r\n"


class SMTPHoneypot(BaseHoneypot):
    name = "smtp"

    def handle(self, conn, addr) -> None:
        self.send_text(conn, self.banner + "\r\n")
        while True:
            line = self.recv_line(conn)
            if not line:
                return
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1].strip() if len(parts) > 1 else ""
            self.emit_command(addr, line)

            if cmd in ("HELO", "EHLO"):
                self.send_text(conn, "250 mail.example\r\n")
            elif cmd == "MAIL":
                self.send_text(conn, "250 2.1.0 Ok\r\n")
            elif cmd == "RCPT":
                self.send_text(conn, "250 2.1.5 Ok\r\n")
            elif cmd == "DATA":
                self.send_text(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
                body = self._read_message(conn)
                if body is not None:
                    self.emit_command(addr, "DATA <message>", f"{len(body)} bytes")
                    token = "".join(secrets.choice("0123456789ABCDEF") for _ in range(9))
                    self.send_text(conn, f"250 2.0.0 Ok: queued as {token}\r\n")
            elif cmd == "VRFY":
                self.send_text(conn, f"252 2.0.0 {arg}\r\n")
            elif cmd == "AUTH":
                self._handle_auth(conn, addr, arg)
            elif cmd == "RSET":
                self.send_text(conn, "250 2.0.0 Ok\r\n")
            elif cmd == "NOOP":
                self.send_text(conn, "250 2.0.0 Ok\r\n")
            elif cmd == "QUIT":
                self.send_text(conn, "221 2.0.0 Bye\r\n")
                return
            else:
                self.send_text(conn, "500 5.5.2 Error: command not recognized\r\n")

    # ------------------------------------------------------------------
    def _read_message(self, conn) -> str | None:
        body = []
        while True:
            line = self.recv_line(conn)
            if line is None:
                return None
            if line == ".":
                return "\n".join(body)
            body.append(line)
            if len(body) > 200:
                return "\n".join(body)

    def _handle_auth(self, conn, addr, arg: str) -> None:
        if arg.upper().startswith("PLAIN"):
            encoded = arg.split(None, 1)[1] if len(arg.split()) > 1 else ""
            try:
                raw = base64.b64decode(encoded).decode("utf-8", "replace")
                self._capture_plain(conn, addr, raw)
            except Exception:
                self.send_text(conn, _AUTH_BAD)
        elif arg.upper().startswith("LOGIN"):
            self._auth_login(conn, addr)
        else:
            self.send_text(conn, "504 5.5.4 Unrecognized authentication type\r\n")

    def _capture_plain(self, conn, addr, raw: str) -> None:
        # Format is either "\0user\0pass" or "user\0user\0pass"
        parts = raw.split("\x00")
        if len(parts) == 3:
            user, pwd = parts[1], parts[2]
        elif len(parts) == 2:
            user, pwd = parts[0], parts[1]
        else:
            self.send_text(conn, _AUTH_BAD)
            return
        self.emit_credential(addr, user, pwd, "success")
        self.send_text(conn, _AUTH_OK)

    def _auth_login(self, conn, addr) -> None:
        self.send_text(conn, "334 VXNlcm5hbWU6\r\n")   # base64("Username:")
        user_raw = self.recv_line(conn)
        if not user_raw:
            return
        self.send_text(conn, "334 UGFzc3dvcmQ6\r\n")   # base64("Password:")
        pass_raw = self.recv_line(conn)
        if not pass_raw:
            return
        try:
            user = base64.b64decode(user_raw).decode("utf-8", "replace")
            pwd = base64.b64decode(pass_raw).decode("utf-8", "replace")
        except Exception:
            self.send_text(conn, _AUTH_BAD)
            return
        self.emit_credential(addr, user, pwd, "success")
        self.send_text(conn, _AUTH_OK)
