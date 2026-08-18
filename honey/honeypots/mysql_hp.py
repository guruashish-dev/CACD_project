"""MySQL honeypot — a protocol-faithful fake MySQL server.

Sends a genuine MySQL *HandshakeV10* packet and parses the client's
*HandshakeResponse41*, extracting the username and auth-response bytes it
sends.  Under a plaintext client (what our attack simulator uses) the
auth response is the password; real clients send the SHA1-scramble, which
is still captured (and is itself a useful intelligence artefact).

The server then returns ``ER_ACCESS_DENIED_ERROR`` exactly like a real
MySQL that rejected the login.
"""

from __future__ import annotations

import secrets

from .base import BaseHoneypot

# Capability flags the server advertises.
CAP_CLIENT_CONNECT_WITH_DB = 0x00000008
CAP_CLIENT_PROTOCOL_41 = 0x00000200
CAP_CLIENT_SECURE_CONNECTION = 0x00008000
CAP_CLIENT_PLUGIN_AUTH = 0x00080000
CAP_CLIENT_LENENC_AUTH_DATA = 0x00020000
CAP_CLIENT_SSL = 0x00000800

_SERVER_CAPS = (CAP_CLIENT_PROTOCOL_41 | CAP_CLIENT_SECURE_CONNECTION |
                CAP_CLIENT_PLUGIN_AUTH | CAP_CLIENT_CONNECT_WITH_DB)


def _packet(payload: bytes, seq: int) -> bytes:
    return len(payload).to_bytes(3, "little") + bytes([seq]) + payload


def _handshake(server_version: str, thread_id: int, auth1: bytes, auth2: bytes, plugin: str) -> bytes:
    cap_low = _SERVER_CAPS & 0xFFFF
    cap_high = (_SERVER_CAPS >> 16) & 0xFFFF
    payload = b""
    payload += bytes([0x0A])                                   # protocol version 10
    payload += server_version.encode() + b"\x00"               # server version
    payload += thread_id.to_bytes(4, "little")
    payload += auth1                                            # 8 bytes part 1
    payload += b"\x00"                                          # filler
    payload += cap_low.to_bytes(2, "little")
    payload += bytes([0x21])                                    # charset utf8_general_ci
    payload += (0x0002).to_bytes(2, "little")                   # status
    payload += cap_high.to_bytes(2, "little")
    payload += bytes([len(auth1) + len(auth2) + 1])             # auth plugin data length
    payload += b"\x00" * 10                                     # reserved
    payload += auth2 + b"\x00"
    payload += plugin.encode() + b"\x00"
    return payload


def _auth_error(message: str) -> bytes:
    payload = bytes([0xFF]) + (1045).to_bytes(2, "little") + b"#" + b"28000"
    payload += message.encode()
    return payload


def _lenenc(payload: bytes, i: int) -> tuple[int, int]:
    first = payload[i]
    if first < 0xFB:
        return first, i + 1
    if first == 0xFC:
        return int.from_bytes(payload[i + 1:i + 3], "little"), i + 3
    if first == 0xFD:
        return int.from_bytes(payload[i + 1:i + 4], "little"), i + 4
    if first == 0xFE:
        return int.from_bytes(payload[i + 1:i + 9], "little"), i + 9
    return 0, i + 1


def _parse_auth_response(payload: bytes) -> dict:
    """Extract username / auth bytes / db / plugin from a HandshakeResponse41."""
    if len(payload) < 32:
        return {}
    caps = int.from_bytes(payload[0:4], "little")
    i = 32
    username = b""
    while i < len(payload) and payload[i] != 0x00:
        username += payload[i:i + 1]
        i += 1
    i += 1
    if i >= len(payload):
        return {"capabilities": caps, "username": username.decode("latin-1", "replace")}

    auth_resp = b""
    if caps & CAP_CLIENT_LENENC_AUTH_DATA:
        length, i = _lenenc(payload, i)
        auth_resp = payload[i:i + length]
        i += length
    elif caps & CAP_CLIENT_SECURE_CONNECTION:
        length = payload[i]
        i += 1
        auth_resp = payload[i:i + length]
        i += length
    else:  # null-terminated
        start = i
        while i < len(payload) and payload[i] != 0x00:
            i += 1
        auth_resp = payload[start:i]
        i += 1

    db = None
    if caps & CAP_CLIENT_CONNECT_WITH_DB:
        start = i
        while i < len(payload) and payload[i] != 0x00:
            i += 1
        db = payload[start:i].decode("latin-1", "replace")

    plugin = None
    if caps & CAP_CLIENT_PLUGIN_AUTH:
        start = i
        while i < len(payload) and payload[i] != 0x00:
            i += 1
        plugin = payload[start:i].decode("latin-1", "replace")

    return {
        "capabilities": caps,
        "username": username.decode("latin-1", "replace"),
        "auth_response": auth_resp,
        "database": db,
        "plugin": plugin,
    }


class MySQLHoneypot(BaseHoneypot):
    name = "mysql"

    def _read_packet(self, conn) -> bytes:
        header = b""
        while len(header) < 4:
            chunk = conn.recv(4 - len(header))
            if not chunk:
                raise EOFError
            header += chunk
        length = int.from_bytes(header[0:3], "little")
        payload = b""
        while len(payload) < length:
            chunk = conn.recv(length - len(payload))
            if not chunk:
                raise EOFError
            payload += chunk
        return payload

    # ------------------------------------------------------------------
    def handle(self, conn, addr) -> None:
        auth1 = secrets.token_bytes(8)
        auth2 = secrets.token_bytes(12)
        thread_id = secrets.randbelow(2 ** 31)
        plugin = "mysql_native_password"
        server_version = self.banner.split(" ")[0] if self.banner else "MySQL 5.7.38"

        try:
            conn.sendall(_packet(_handshake(server_version, thread_id, auth1, auth2, plugin), 0))
            response = self._read_packet(conn)
        except (EOFError, OSError):
            return

        parsed = _parse_auth_response(response)
        if not parsed.get("username"):
            return

        details = {
            "client_capabilities": hex(parsed.get("capabilities", 0)),
            "database": parsed.get("database"),
            "plugin": parsed.get("plugin"),
        }
        self.emit_connection(addr, details)
        self.emit_credential(
            addr, parsed["username"], parsed.get("auth_response", b"").decode("latin-1", "replace"),
            "failed")

        user = parsed["username"]
        try:
            conn.sendall(_packet(
                _auth_error(f"Access denied for user '{user}'@'localhost' (using password: YES)"),
                2))
        except OSError:
            pass
