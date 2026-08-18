#!/usr/bin/env python3
"""Live attack simulator — fires *real* attacks at the *real* honeypots.

Run this while ``python main.py`` is running.  Each attacker persona binds
its client socket to a distinct loopback address (127.0.0.2 … 127.0.0.7), so
the threat-intel engine and dashboard see a genuine multi-source attack
landscape rather than a single 127.0.0.1.

    python demo/attack_simulator.py --plan sweep       # everyone attacks
    python demo/attack_simulator.py --plan targeted    # heavy, one focus
    python demo/attack_simulator.py --plan stealth     # slow, few probes
    python demo/attack_simulator.py --config data/test_config.json

All traffic is loopback and stays on this machine — no remote systems are
touched.
"""

from __future__ import annotations

import argparse
import base64
import secrets
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Windows consoles default to cp1252; force UTF-8 so arrows/bullets survive.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from honey.config import load_config  # noqa: E402
from honey.eventlog import colorize  # noqa: E402

# ---------------------------------------------------------------------------
# Attacker personas (source IP -> archetype)
# ---------------------------------------------------------------------------
PERSONAS = {
    "127.0.0.2": "botnet node (SSH brute-force)",
    "127.0.0.3": "web scanner / SQLi probe",
    "127.0.0.4": "credential stuffer (FTP)",
    "127.0.0.5": "telnet worm",
    "127.0.0.6": "database thief (MySQL)",
    "127.0.0.7": "spambot / open-relay",
}

# Realistic-looking login attempts, several matching default credentials so
# the credential-stuffing alerts fire.
SSH_WORDLIST = [
    ("root", "toor"), ("root", "password"), ("admin", "admin"),
    ("admin", "123456"), ("root", "root123"), ("ubuntu", "ubuntu"),
    ("root", "P@ssw0rd"), ("admin", "changeme"), ("root", "1qaz2wsx"),
    ("admin", "admin123"), ("root", "r00t"), ("test", "test"),
    ("postgres", "postgres"), ("admin", "password"), ("root", "123456"),
]
FTP_WORDLIST = [
    ("admin", "admin"), ("ftp", "ftp"), ("admin", "123456"),
    ("root", "toor"), ("anonymous", "guest"), ("admin", "password"),
]
TELNET_WORDLIST = [
    ("root", "root"), ("admin", "admin"), ("root", "12345"),
    ("admin", "123456"), ("root", "toor"),
]
MYSQL_WORDLIST = [
    ("root", "root"), ("admin", "admin"), ("root", "mysql"),
    ("root", "123456"), ("mysql", "mysql"),
]
WEB_PATHS = [
    "/", "/wp-login.php", "/wp-admin/", "/admin/", "/phpmyadmin/",
    "/manager/html", "/.env", "/.git/config", "/cgi-bin/test.cgi",
    "/api/v1/users", "/backup.zip", "/db.sql", "/config.php.bak",
    "/sql/", "/old/", "/login", "/admin/login.php", "/test.php",
]
HOSTILE_AGENTS = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]


def log(msg: str, color: str = "white") -> None:
    print(colorize(f"[simulator] {msg}", color), flush=True)


def _bound_socket(src_ip: str, host: str, port: int, timeout: float = 3.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.bind((src_ip, 0))
    s.connect((host, port))
    return s


def _recv_line(s: socket.socket) -> str:
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(1)
        if not chunk:
            break
        data += chunk
        if len(data) > 4096:
            break
    return data.decode("utf-8", errors="replace").strip()


def _recv_exact(s: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed early")
        data += chunk
    return data


# ---------------------------------------------------------------------------
# Attack primitives
# ---------------------------------------------------------------------------
def ssh_bruteforce(host: int, port: int, src_ip: str, creds) -> int:
    """Attempt ``creds`` via a genuine paramiko SSH client."""
    import paramiko
    n = 0
    for user, pwd in creds:
        sock = _bound_socket(src_ip, host, port, timeout=3.0)
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=user, password=pwd,
                           sock=sock, timeout=3, allow_agent=False,
                           look_for_keys=False, banner_timeout=3, auth_timeout=3)
            client.close()
            n += 1
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
        time.sleep(0.05)
    return n


def http_scan(host: int, port: int, src_ip: str, paths) -> dict:
    counts = {"sent": 0, "responses": 0}
    agent = HOSTILE_AGENTS[secrets.randbelow(len(HOSTILE_AGENTS))]
    for path in paths:
        try:
            s = _bound_socket(src_ip, host, port, timeout=3.0)
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: {agent}\r\nConnection: close\r\n\r\n")
            s.sendall(req.encode())
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            counts["sent"] += 1
            if resp:
                counts["responses"] += 1
            s.close()
        except (ConnectionError, OSError):
            pass
        time.sleep(0.03)
    # A web login POST that submits default credentials.
    try:
        s = _bound_socket(src_ip, host, port, timeout=3.0)
        body = "log=admin&pwd=admin"
        req = (f"POST /wp-login.php HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: {agent}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
        s.sendall(req.encode())
        s.recv(1024)
        counts["sent"] += 1
        s.close()
    except (ConnectionError, OSError):
        pass
    return counts


def ftp_bruteforce(host: int, port: int, src_ip: str, creds) -> int:
    n = 0
    for user, pwd in creds:
        try:
            s = _bound_socket(src_ip, host, port, timeout=3.0)
            s.recv(256)
            s.sendall(f"USER {user}\r\n".encode())
            s.recv(256)
            s.sendall(f"PASS {pwd}\r\n".encode())
            s.recv(256)
            s.sendall(b"QUIT\r\n")
            s.close()
            n += 1
        except (ConnectionError, OSError):
            pass
        time.sleep(0.05)
    return n


def telnet_login(host: int, port: int, src_ip: str, creds) -> int:
    n = 0
    for user, pwd in creds:
        try:
            s = _bound_socket(src_ip, host, port, timeout=2.0)
            time.sleep(0.1)
            s.recv(512)                                  # banner + "login: "
            s.sendall((user + "\n").encode())
            time.sleep(0.1)
            s.recv(512)                                  # "Password: "
            s.sendall((pwd + "\n").encode())
            time.sleep(0.1)
            s.recv(512)                                  # fake shell banner
            s.sendall(b"exit\n")
            s.close()
            n += 1
        except (ConnectionError, OSError):
            pass
        time.sleep(0.05)
    return n


def mysql_attempt(host: int, port: int, src_ip: str, creds) -> int:
    n = 0
    caps = 0x00088209  # CONNECT_WITH_DB | PROTOCOL_41 | SECURE | PLUGIN_AUTH
    for user, pwd in creds:
        try:
            s = _bound_socket(src_ip, host, port, timeout=3.0)
            header = _recv_exact(s, 4)                     # server handshake
            _recv_exact(s, int.from_bytes(header[:3], "little"))
            payload = (caps.to_bytes(4, "little") + (0).to_bytes(4, "little")
                       + bytes([0x21]) + (b"\x00" * 23))
            payload += user.encode() + b"\x00"
            pwd_bytes = pwd.encode()
            payload += bytes([len(pwd_bytes)]) + pwd_bytes
            payload += b"mysql_native_password\x00"
            s.sendall(len(payload).to_bytes(3, "little") + bytes([1]) + payload)
            s.recv(512)                                    # auth error packet
            s.close()
            n += 1
        except (ConnectionError, OSError):
            pass
        time.sleep(0.05)
    return n


def smtp_attack(host: int, port: int, src_ip: str) -> dict:
    counts = {"rcpt": 0}
    try:
        s = _bound_socket(src_ip, host, port, timeout=3.0)
        s.recv(256)                                     # banner
        # AUTH PLAIN to harvest credentials
        token = base64.b64encode(b"\x00sales\x00SpamBot99!").decode()
        s.sendall(f"AUTH PLAIN {token}\r\n".encode())
        s.recv(256)
        # open-relay spam attempt
        s.sendall(b"EHLO spammer.example\r\n")
        s.recv(256)
        s.sendall(b"MAIL FROM:<advert@spammer.example>\r\n")
        s.recv(256)
        for i in range(6):
            s.sendall(f"RCPT TO:<victim{i}@corp.local>\r\n".encode())
            s.recv(256)
            counts["rcpt"] += 1
        s.sendall(b"DATA\r\n")
        s.recv(256)
        s.sendall(b"Subject: Limited time offer!!\r\nBuy now!!\r\n.\r\n")
        s.recv(256)
        s.sendall(b"QUIT\r\n")
        s.close()
    except (ConnectionError, OSError):
        pass
    return counts


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------
def plan_sweep(host, ports):
    log("sweep plan: rotating through 6 attacker personas", "yellow")
    results = {}
    results["ssh"] = ssh_bruteforce(host, ports["ssh"], "127.0.0.2", SSH_WORDLIST)
    results["http"] = http_scan(host, ports["http"], "127.0.0.3", WEB_PATHS)
    results["ftp"] = ftp_bruteforce(host, ports["ftp"], "127.0.0.4", FTP_WORDLIST)
    results["telnet"] = telnet_login(host, ports["telnet"], "127.0.0.5", TELNET_WORDLIST)
    results["mysql"] = mysql_attempt(host, ports["mysql"], "127.0.0.6", MYSQL_WORDLIST)
    results["smtp"] = smtp_attack(host, ports["smtp"], "127.0.0.7")
    return results


def plan_targeted(host, ports):
    log("targeted plan: botnet node 127.0.0.2 hammers every protocol", "yellow")
    results = {}
    results["ssh"] = ssh_bruteforce(host, ports["ssh"], "127.0.0.2", SSH_WORDLIST * 2)
    results["http"] = http_scan(host, ports["http"], "127.0.0.2", WEB_PATHS * 2)
    results["ftp"] = ftp_bruteforce(host, ports["ftp"], "127.0.0.2", FTP_WORDLIST * 2)
    results["telnet"] = telnet_login(host, ports["telnet"], "127.0.0.2", TELNET_WORDLIST)
    results["mysql"] = mysql_attempt(host, ports["mysql"], "127.0.0.2", MYSQL_WORDLIST)
    results["smtp"] = smtp_attack(host, ports["smtp"], "127.0.0.2")
    return results


def plan_stealth(host, ports):
    log("stealth plan: slow, low-volume probing from 127.0.0.3", "yellow")
    results = {}
    results["http"] = http_scan(host, ports["http"], "127.0.0.3", WEB_PATHS[:4])
    results["ssh"] = ssh_bruteforce(host, ports["ssh"], "127.0.0.3", [("admin", "admin")])
    results["ftp"] = 0
    results["telnet"] = 0
    results["mysql"] = 0
    results["smtp"] = 0
    return results


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Live attack simulator for the honeypot network")
    parser.add_argument("--plan", default="sweep", choices=["sweep", "targeted", "stealth"],
                        help="attack scenario to run (default: sweep)")
    parser.add_argument("--host", default=None, help="target host (default: from config)")
    parser.add_argument("--config", default=None, help="path to an alternative config.json")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    host = args.host or cfg["bind_host"]
    if host == "0.0.0.0":
        host = "127.0.0.1"
    ports = {name: proto["port"] for name, proto in cfg["protocols"].items()}

    log(f"targeting {host} — honeypot ports: " +
        ", ".join(f"{name}={p}" for name, p in ports.items()), "cyan")
    print()
    for src, desc in PERSONAS.items():
        log(f"  attacker {src}  ->  {desc}", "dim")
    print()

    plans = {"sweep": plan_sweep, "targeted": plan_targeted, "stealth": plan_stealth}
    start = time.time()
    results = plans[args.plan](host, ports)
    elapsed = time.time() - start

    print()
    log(f"{args.plan} plan finished in {elapsed:.1f}s", "green")
    log("summary of requests sent:", "white")
    for proto, count in results.items():
        if isinstance(count, dict):
            sent = sum(count.values()) if proto != "http" else count["sent"]
            log(f"  {proto:7s}: {sent} requests", "cyan")
        else:
            log(f"  {proto:7s}: {count} login attempts", "cyan")
    print()
    log("Now open the dashboard:  http://127.0.0.1:8080  (or your dashboard port)", "green")
    log("and check data/honey.db for captured credentials.", "dim")
    return 0


if __name__ == "__main__":
    sys.exit(main())
