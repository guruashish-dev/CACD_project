"""Threat-intelligence engine.

Consumes connection / credential / command events and maintains a per-source-IP
profile: attempt counts, protocols hit, usernames tried, and whether default
credentials were observed.  Each update produces an ``intel`` event carrying a
0-100 risk score and a single classification label:

    recon-scan        rapid, shallow probing (many web paths)
    brute-force       repeated login attempts within a short window
    credential-stuffing   default / common credentials tried
    multi-vector      the same host hit >=3 protocols
    spam-relay        SMTP mail relay / spam behaviour

The exact same engine drives the *real* honeypots and the *offline* demo
model — the demo model is a faithful model of the live detection pipeline.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Optional

from . import eventlog
from .config import get_config


def iso_to_epoch(ts: str) -> float:
    """Parse an ISO-8601 timestamp (as produced by eventlog) into epoch seconds."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0.0


class IntelEngine:
    def __init__(self, config: Optional[dict] = None):
        self.cfg = (config or {}).get("intel", get_config()["intel"])
        self.default_creds = {
            tuple(pair) for pair in (config or {}).get("default_credentials", get_config()["default_credentials"])
        }
        self._state: dict[str, dict] = {}
        self._lock = threading.Lock()
        eventlog.subscribe(self.on_event)

    # ------------------------------------------------------------------
    def on_event(self, event: dict) -> None:
        kind = event.get("kind")
        if kind not in ("connection", "credential", "command"):
            return
        src = event.get("src_ip", "")
        if not src:
            return
        ts = iso_to_epoch(event.get("ts", ""))
        with self._lock:
            st = self._state.setdefault(src, {
                "attempts": [], "protocols": set(), "usernames": set(),
                "passwords": set(), "default_hit": False, "spam": False,
                "first_seen": event.get("ts"), "last_seen": event.get("ts"),
            })
            st["last_seen"] = event.get("ts")
            st["attempts"].append(ts)
            st["protocols"].add(event.get("protocol", ""))

            if kind == "credential":
                uname = event.get("username") or ""
                pwd = event.get("password") or ""
                if uname:
                    st["usernames"].add(uname)
                if pwd:
                    st["passwords"].add(pwd)
                if (uname, pwd) in self.default_creds:
                    st["default_hit"] = True

            if kind == "command" and event.get("protocol") == "smtp" and \
                    str(event.get("command", "")).upper().startswith("RCPT"):
                st["spam"] = True

            score, classification = self._evaluate(st, ts)
            details = {
                "usernames": sorted(st["usernames"])[:20],
                "default_creds_used": st["default_hit"],
            }
            self._emit_intel(src, score, classification, st, details)

    # ------------------------------------------------------------------
    def _evaluate(self, st: dict, now: float) -> tuple[int, str]:
        cfg = self.cfg
        window = cfg.get("bruteforce_window_sec", 60)
        recent = [t for t in st["attempts"] if now - t <= window]
        n_total = len(st["attempts"])
        n_recent = len(recent)
        protocols = len(st["protocols"])
        n_users = len(st["usernames"])
        multivector_min = cfg.get("multivector_protocols", 3)
        bf_threshold = cfg.get("bruteforce_threshold", 5)
        recon_threshold = cfg.get("recon_probes_threshold", 10)

        score = 0
        score += min(n_recent * 5, 40)                  # burst pressure
        score += min(n_total, 30)                       # persistence
        score += min(max(protocols - 1, 0) * 10, 20)    # multi-vector reach
        score += min(n_users * 2, 10)                   # credential breadth
        if st["default_hit"]:
            score += 15
        if st["spam"]:
            score += 10
        if n_recent >= bf_threshold:
            score += 10
        score = min(100, score)

        classification = self._classify(st, n_recent, protocols, n_users, cfg)
        return score, classification

    @staticmethod
    def _classify(st: dict, n_recent: int, protocols: int, n_users: int, cfg: dict) -> str:
        if protocols >= cfg.get("multivector_protocols", 3):
            return "multi-vector"
        if st["default_hit"] or n_users >= 5:
            return "credential-stuffing"
        if st["spam"]:
            # SMTP command bursts inflate the attempt count, so check this
            # before the brute-force threshold.
            return "spam-relay"
        if n_recent >= cfg.get("bruteforce_threshold", 5):
            return "brute-force"
        return "recon-scan"

    # ------------------------------------------------------------------
    def _emit_intel(self, src: str, score: int, classification: str, st: dict, details: dict) -> None:
        eventlog.emit({
            "kind": "intel",
            "src_ip": src,
            "risk": score,
            "classification": classification,
            "attempts": len(st["attempts"]),
            "protocols": ",".join(sorted(st["protocols"])),
            "first_seen": st["first_seen"],
            "last_seen": st["last_seen"],
            "details": details,
        })

    def get_state(self, ip: str) -> dict | None:
        with self._lock:
            st = self._state.get(ip)
            if not st:
                return None
            return {**st, "protocols": sorted(st["protocols"]),
                    "usernames": sorted(st["usernames"]),
                    "attempts": list(st["attempts"])}

    def snapshot(self) -> dict[str, dict]:
        """Return a shallow copy of all tracked sources (for reports)."""
        with self._lock:
            return {ip: self._copy_state(st) for ip, st in self._state.items()}

    @staticmethod
    def _copy_state(st: dict) -> dict:
        return {
            "attempts": list(st["attempts"]),
            "protocols": sorted(st["protocols"]),
            "usernames": sorted(st["usernames"]),
            "passwords": sorted(st["passwords"]),
            "default_hit": st["default_hit"],
            "spam": st["spam"],
            "first_seen": st["first_seen"],
            "last_seen": st["last_seen"],
        }
