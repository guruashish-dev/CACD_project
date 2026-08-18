#!/usr/bin/env python3
"""Multi-Protocol Honeypot Network — main orchestrator.

Starts the configured protocol honeypots, wires up the database + intel +
alert pipeline, launches the live dashboard, and runs until Ctrl-C.

Examples
--------
    python main.py                          # all enabled protocols + dashboard
    python main.py --protocols ssh,http     # only SSH and HTTP honeypots
    python main.py --no-dashboard           # honeypots only
    python main.py --dashboard-port 9000
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time

from honey import eventlog
from honey.alerts import AlertEngine
from honey.config import get_config, load_config
from honey.database import Database
from honey.eventlog import ConsoleOutput
from honey.honeypots import PROTOCOL_ORDER, create
from honey.intel import IntelEngine

BANNER = r"""
  _   _   ___   _   _  __     __
 | | | | / _ \ | \ | | \ \   / /
 | |_| || | | ||  \| |  \ \ / /
 |  _  || |_| || |\  |   \ V /
 |_| |_| \___/ |_| \_|    \_/    Multi-Protocol Honeypot Network
"""


def port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Multi-Protocol Honeypot Network")
    parser.add_argument(
        "--protocols", "-p",
        help="comma-separated protocols to run (default: all enabled in config.json)")
    parser.add_argument("--config", default=None,
                        help="path to an alternative config.json")
    parser.add_argument("--no-dashboard", action="store_true",
                        help="do not start the web dashboard")
    parser.add_argument("--dashboard-port", type=int, default=None,
                        help="override the dashboard port")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    config = load_config(args.config)
    console = ConsoleOutput("main")

    db = Database()          # subscribes to the event bus
    IntelEngine(config)      # risk scoring / classification
    AlertEngine(config)      # alert rules
    eventlog.emit({"kind": "system", "message": "honeypot network started"})

    # Which protocols to run?
    if args.protocols:
        selected = [p.strip() for p in args.protocols.split(",") if p.strip()]
    else:
        selected = [name for name in PROTOCOL_ORDER
                    if config["protocols"].get(name, {}).get("enabled", True)]

    # Pre-flight: report port conflicts without crashing.
    conflicts = []
    for name in selected:
        port = config["protocols"][name]["port"]
        if not port_is_free(config["bind_host"], port):
            conflicts.append((name, port))
            console.warn(f"port {port} ({name}) is already in use — edit config.json "
                         f"to change it; honeypot will not start")
    if conflicts:
        console.warn(f"{len(conflicts)} port conflict(s). Override ports in config.json "
                     f"(e.g. set \"ssh\":{{\"port\": 2222}}).")

    honeypots = []
    for name in selected:
        try:
            hp = create(name, config)
            honeypots.append(hp)
        except Exception as exc:  # e.g. paramiko missing
            console.error(f"failed to create {name} honeypot: {exc}")

    for hp in honeypots:
        hp.start()

    time.sleep(0.5)
    dashboard_port = None
    if not args.no_dashboard:
        from dashboard.app import start_dashboard
        _, dashboard_port = start_dashboard(db, port=args.dashboard_port)

    running = [hp for hp in honeypots if hp.is_alive()]
    print(BANNER)
    console.ok(f"{len(running)}/{len(honeypots)} honeypot(s) listening:")
    for hp in running:
        console.ok(f"  • {hp.name:8s} on {hp.host}:{hp.port}")
    if dashboard_port:
        console.ok(f"  • dashboard   at http://127.0.0.1:{dashboard_port}")
    console.info("Press Ctrl-C to stop.")
    print()

    # Try to acquire a Windows console, keep printing nothing until Ctrl-C.
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        console.info("shutting down…")
        for hp in honeypots:
            hp.shutdown()
        for hp in honeypots:
            hp.join(timeout=3)
        eventlog.emit({"kind": "system", "message": "honeypot network stopped"})
        db.close()
        console.ok("stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
