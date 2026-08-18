"""FTP honeypot — a fake ProFTPD server.

Runs a plaintext FTP command loop (USER / PASS), captures every credential
attempt, and hands successful logins a fake filesystem (LIST, CWD, PWD,
SYST, FEAT).  Standard FTP brute-force tools (hydra, medusa, ncrack) work
against it unmodified.
"""

from __future__ import annotations

from .base import BaseHoneypot


class FTPHoneypot(BaseHoneypot):
    name = "ftp"

    def handle(self, conn, addr) -> None:
        self.send_text(conn, self.banner + "\r\n")
        username = ""
        while True:
            line = self.recv_line(conn)
            if not line:
                return
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd == "USER":
                username = arg
                self.emit_command(addr, line, "331")
                self.send_text(conn, f"331 Password required for {arg}\r\n")
            elif cmd == "PASS":
                self.emit_credential(addr, username, arg, "success")
                self.emit_command(addr, line, "230")
                self.send_text(conn, f"230 User {username} logged in\r\n")
            elif cmd in ("SYST",):
                self.send_text(conn, "215 UNIX Type: L8\r\n")
            elif cmd == "FEAT":
                self.send_text(conn, "211-Features:\r\n UTF8\r\n SIZE\r\n MLST type*;size*;\r\n211 End\r\n")
            elif cmd == "PWD":
                self.send_text(conn, '257 "/" is the current directory\r\n')
            elif cmd == "CWD":
                self.send_text(conn, "250 CWD command successful\r\n")
            elif cmd in ("LIST", "NLST", "MLSD"):
                self.emit_command(addr, line, "150/226")
                self.send_text(conn, "150 Here comes the directory listing.\r\n")
                self.send_text(conn, "226 Directory send OK.\r\n")
            elif cmd == "SIZE":
                self.send_text(conn, f"213 1024\r\n")
            elif cmd in ("QUIT", "LOGOUT"):
                self.send_text(conn, "221 Goodbye.\r\n")
                return
            elif cmd == "AUTH":
                # We do not do TLS — decline so the client falls back / stalls.
                self.send_text(conn, "502 AUTH not implemented\r\n")
            elif cmd == "TYPE":
                self.send_text(conn, "200 Type set to I\r\n")
            elif cmd == "PASV" or cmd == "EPSV":
                self.send_text(conn, "227 Entering Passive Mode (127,0,0,1,200,100).\r\n")
            else:
                self.emit_command(addr, line, "500")
                self.send_text(conn, "500 Unknown command.\r\n")
