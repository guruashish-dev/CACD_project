"""SSH honeypot built on paramiko.

Performs a genuine SSH handshake (host key + transport), accepts *any*
password, captures every credential, and drops the attacker into a fake
shell that records every command.  Because it is a real SSH server,
standard tooling — ``ssh``, ``hydra``, ``nmap -sV``, paramiko — works
against it unmodified.

The host key is generated once and cached in ``data/host.key``.
"""

from __future__ import annotations

import threading

from .base import BaseHoneypot

try:
    import paramiko
except ImportError:  # pragma: no cover - surfaced to the user at runtime
    paramiko = None  # type: ignore[assignment]

_HOST_KEY_PATH = "host.key"


class SSHHoneypot(BaseHoneypot):
    name = "ssh"

    def __init__(self, config=None):
        if paramiko is None:
            raise RuntimeError("paramiko is required for the SSH honeypot. "
                               "Install it with: python -m pip install paramiko")
        super().__init__(config)
        self._host_key = None

    # ------------------------------------------------------------------
    def on_listen(self) -> None:
        from ..config import data_path
        key_file = data_path(_HOST_KEY_PATH)
        if key_file.exists():
            self._host_key = paramiko.RSAKey(filename=str(key_file))
        else:
            self._host_key = paramiko.RSAKey.generate(2048)
            key_file.parent.mkdir(parents=True, exist_ok=True)
            self._host_key.write_private_key_file(str(key_file))
            self.log.ok(f"generated host key at {key_file}")

    # ------------------------------------------------------------------
    def handle(self, conn, addr) -> None:
        transport = paramiko.Transport(conn)
        banner = self.banner if self.banner.startswith("SSH-2.0-") else "SSH-2.0-" + self.banner
        transport.local_version = banner
        try:
            transport.add_server_key(self._host_key)
            server = _HoneypotServer(self, addr)
            transport.start_server(server=server)
            while True:
                # Drive the transport; closes the channel when the client goes away.
                channel = transport.accept(timeout=60)
                if channel is None:
                    break
        except (EOFError, ConnectionError, OSError, paramiko.SSHException):
            pass
        finally:
            try:
                transport.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Fake shell
    # ------------------------------------------------------------------
    def _respond(self, command: str) -> str:
        cmd = command.strip().lower()
        if cmd in ("ls", "ls -la", "ls -l"):
            return ("total 28\r\ndrwxr-xr-x 3 root root 4096 Jul 20 09:00 .\r\n"
                    "drwxr-xr-x 3 root root 4096 Jul 20 09:00 ..\r\n"
                    "-rw-r--r-- 1 root root  112 Jul 20 09:00 .bashrc\r\n"
                    "-rw-r--r-- 1 root root  220 Jul 20 09:00 .profile\r\n"
                    "-rw------- 1 root root 1024 Jul 20 09:00 .mysql_history\r\n"
                    "drwxr-xr-x 2 root root 4096 Jul 20 09:00 logs\r\n")
        if cmd in ("whoami",):
            return "root\r\n"
        if cmd in ("id",):
            return "uid=0(root) gid=0(root) groups=0(root)\r\n"
        if cmd in ("uname -a", "uname -r"):
            return "Linux honeypot 5.15.0-86-generic #94-Ubuntu SMP x86_64 GNU/Linux\r\n"
        if cmd.startswith("cat /etc/passwd"):
            return ("root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n")
        if cmd in ("pwd",):
            return "/root\r\n"
        if cmd in ("exit", "logout"):
            return ""
        return f"bash: {command}: command not found\r\n"

    def _shell_loop(self, channel, addr) -> None:
        channel.send("Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-86-generic x86_64)\r\n\r\n")
        channel.send("Last login: Sun Aug 12 03:14:08 2026 from 10.0.0.7\r\n\r\n")
        channel.send("root@honeypot:~# ")
        while True:
            try:
                data = channel.recv(4096).decode("utf-8", errors="replace")
            except (OSError, EOFError):
                return
            if not data:
                return
            for line in data.split("\r") if "\r" in data else data.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line in ("exit", "logout"):
                    try:
                        channel.send("logout\r\n")
                    except OSError:
                        pass
                    return
                response = self._respond(line)
                self.emit_command(addr, line, response)
                try:
                    channel.send(response)
                    channel.send("root@honeypot:~# ")
                except OSError:
                    return

    def _exec_request(self, channel, command, addr) -> None:
        if isinstance(command, (bytes, bytearray)):
            command = command.decode("utf-8", errors="replace")
        response = self._respond(command)
        self.emit_command(addr, command, response)
        try:
            channel.send(response)
            channel.send_exit_status(0)
            channel.close()
        except OSError:
            pass


class _HoneypotServer(paramiko.ServerInterface):
    """Accepts any auth and hands the client a fake shell."""

    def __init__(self, hp: SSHHoneypot, addr):
        self.hp = hp
        self.addr = addr

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_auth_none(self, username):
        self.hp.emit_credential(self.addr, username, "", "none")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        self.hp.emit_credential(self.addr, username, password, "success")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.hp.emit_credential(self.addr, username, key.get_name(), "publickey")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_interactive(self, username):
        return paramiko.INTERACTIVE_NOT_SUPPORTED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        threading.Thread(
            target=self.hp._shell_loop, args=(channel, self.addr), daemon=True).start()
        return True

    def check_channel_exec_request(self, channel, command):
        threading.Thread(
            target=self.hp._exec_request, args=(channel, command, self.addr), daemon=True).start()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_window_size_request(self, channel, width, height, pixelwidth, pixelheight):
        return True
