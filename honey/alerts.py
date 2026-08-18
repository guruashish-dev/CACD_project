"""Alert rules engine.

Subscribes to the event bus and raises ``alert`` events when behaviour
crosses a configured threshold.  Alerts are persisted by the database
subscriber, shown live on the dashboard, and included in the report.

Each rule keeps its own in-memory history and fires *once per episode*:
it arms when the condition is met and re-arms only after the activity
drops back below the threshold, so a long brute-force run produces one
alert, not a hundred.
"""

from __future__ import annotations

import threading
from typing import Optional

from . import eventlog
from .config import get_config
from .intel import iso_to_epoch


class _BruteForceRule:
    name = "bruteforce"

    def __init__(self, cfg: dict, severity: str):
        self.threshold = cfg["intel"].get("bruteforce_threshold", 5)
        self.window = cfg["intel"].get("bruteforce_window_sec", 60)
        self.severity = severity
        self._recent: dict[str, list[float]] = {}
        self._fired: dict[str, bool] = {}

    def on_event(self, event: dict) -> list[dict]:
        # One TCP connection == one login attempt (the credential event is
        # separate), so count only connections to avoid double-counting.
        if event.get("kind") != "connection":
            return []
        if event.get("protocol") == "http":  # HTTP probes are recon, not brute-force
            return []
        key = f"{event.get('src_ip')}|{event.get('protocol')}"
        now = iso_to_epoch(event.get("ts", ""))
        bucket = self._recent.setdefault(key, [])
        bucket.append(now)
        bucket = [t for t in bucket if now - t <= self.window]
        self._recent[key] = bucket

        triggered = len(bucket) >= self.threshold and not self._fired.get(key)
        if len(bucket) < self.threshold:
            self._fired[key] = False
        if not triggered:
            return []
        self._fired[key] = True
        return [{
            "severity": self.severity,
            "title": f"Brute-force attack on {event.get('protocol').upper()}",
            "detail": (f"{len(bucket)} failed login attempts from {event.get('src_ip')} "
                       f"within {self.window}s"),
            "src_ip": event.get("src_ip"),
        }]


class _CredentialStuffingRule:
    name = "credential_stuffing"

    def __init__(self, cfg: dict, severity: str):
        self.defaults = {tuple(p) for p in cfg.get("default_credentials", [])}
        self.severity = severity
        self._seen: set[tuple] = set()

    def on_event(self, event: dict) -> list[dict]:
        if event.get("kind") != "credential":
            return []
        pair = (event.get("username") or "", event.get("password") or "")
        if pair not in self.defaults:
            return []
        key = (event.get("src_ip"),) + pair
        if key in self._seen:
            return []
        self._seen.add(key)
        return [{
            "severity": self.severity,
            "title": "Default / known credentials attempted",
            "detail": f"{event.get('src_ip')} tried '{pair[0]}' / '{pair[1]}' on {event.get('protocol').upper()}",
            "src_ip": event.get("src_ip"),
        }]


class _MultiVectorRule:
    name = "multivector"

    def __init__(self, cfg: dict, severity: str):
        self.min_protocols = cfg["intel"].get("multivector_protocols", 3)
        self.severity = severity
        self._protocols: dict[str, set] = {}
        self._fired: set[str] = set()

    def on_event(self, event: dict) -> list[dict]:
        if event.get("kind") != "connection":
            return []
        src = event.get("src_ip", "")
        prots = self._protocols.setdefault(src, set())
        prots.add(event.get("protocol", ""))
        if len(prots) < self.min_protocols or src in self._fired:
            return []
        self._fired.add(src)
        return [{
            "severity": self.severity,
            "title": f"Multi-protocol attack from {src}",
            "detail": f"Source {src} hit {len(prots)} protocols: {', '.join(sorted(prots))}",
            "src_ip": src,
        }]


class _ReconScanRule:
    name = "recon_scan"

    def __init__(self, cfg: dict, severity: str):
        self.threshold = cfg["intel"].get("recon_probes_threshold", 10)
        self.window = cfg["intel"].get("recon_window_sec", 30)
        self.severity = severity
        self._paths: dict[str, list[tuple[float, str]]] = {}
        self._fired: dict[str, bool] = {}

    def on_event(self, event: dict) -> list[dict]:
        if event.get("kind") != "connection" or event.get("protocol") != "http":
            return []
        path = (event.get("details") or {}).get("path", "/")
        src = event.get("src_ip", "")
        now = iso_to_epoch(event.get("ts", ""))
        bucket = self._paths.setdefault(src, [])
        bucket.append((now, path))
        bucket = [(t, p) for t, p in bucket if now - t <= self.window]
        self._paths[src] = bucket
        distinct = len({p for _, p in bucket})
        triggered = distinct >= self.threshold and not self._fired.get(src)
        if distinct < self.threshold:
            self._fired[src] = False
        if not triggered:
            return []
        self._fired[src] = True
        return [{
            "severity": self.severity,
            "title": f"Web reconnaissance scan from {src}",
            "detail": (f"{distinct} distinct paths probed within {self.window}s "
                       f"(e.g. {', '.join(list({p for _, p in bucket})[:4])})"),
            "src_ip": src,
        }]


class _SpamRelayRule:
    name = "spam_relay"

    def __init__(self, cfg: dict, severity: str):
        self.severity = severity
        self._counts: dict[str, int] = {}
        self._fired: set[str] = set()

    def on_event(self, event: dict) -> list[dict]:
        if event.get("kind") != "command" or event.get("protocol") != "smtp":
            return []
        cmd = str(event.get("command", "")).upper()
        if not cmd.startswith("RCPT"):
            return []
        src = event.get("src_ip", "")
        count = self._counts.get(src, 0) + 1
        self._counts[src] = count
        if count < 5 or src in self._fired:
            return []
        self._fired.add(src)
        return [{
            "severity": self.severity,
            "title": f"Spam / open-relay attempt from {src}",
            "detail": f"{count} recipients submitted via SMTP",
            "src_ip": src,
        }]


class AlertEngine:
    """Wires all rules to the event bus."""

    def __init__(self, config: Optional[dict] = None):
        self.cfg = config or get_config()
        self._rules = []
        for rule_cls in (_BruteForceRule, _CredentialStuffingRule,
                         _MultiVectorRule, _ReconScanRule, _SpamRelayRule):
            rule_cfg = self.cfg["alerts"].get(rule_cls.name, {})
            if rule_cfg.get("enabled", True):
                self._rules.append(rule_cls(self.cfg, rule_cfg.get("severity", "info")))
        eventlog.subscribe(self.on_event)

    def on_event(self, event: dict) -> None:
        for rule in self._rules:
            for alert in rule.on_event(event):
                eventlog.emit({
                    "kind": "alert",
                    **alert,
                })
