"""Event bus and console logging.

Every interesting thing that happens in the honeypot network is emitted as
an *event* dict of the form::

    {"kind": "...", "ts": "2026-08-12T10:00:00.000Z", "protocol": "ssh",
     "src_ip": "192.168.1.10", ...}

The bus fans each event out to every subscriber (the database, the intel
engine, the alert rules, and the dashboard live stream) in order.  ``emit``
is synchronous, so by the time a honeypot handler returns, the event has
been persisted and scored — this keeps a single attack trace reproducible.
"""

from __future__ import annotations

import ctypes
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Callable

# ---------------------------------------------------------------------------
# ANSI colour support (best-effort on Windows terminals)
# ---------------------------------------------------------------------------

_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
}

SEVERITY_COLORS = {
    "info": "cyan",
    "low": "green",
    "medium": "yellow",
    "high": "magenta",
    "critical": "red",
}


def _enable_windows_ansi() -> None:
    """Enable VT escape sequences on Windows consoles if possible."""
    if sys.platform != "win32":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:  # pragma: no cover - best-effort only
        pass


def colorize(text: str, color: str, bold: bool = False) -> str:
    """Wrap ``text`` in ANSI codes; degrades to plain text if colour is off."""
    if not console_colors_enabled():
        return text
    prefix = _COLORS["bold"] if bold else ""
    return f"{prefix}{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------

_console_enabled = True
_echo_enabled = True
_listeners: list[Callable[[dict], None]] = []
_listen_lock = threading.Lock()
_subscriber_lock = threading.Lock()

# One-line display colour per event kind.
_KIND_COLORS = {
    "connection": "dim",
    "credential": "yellow",
    "command": "cyan",
    "alert": "magenta",
    "intel": "blue",
    "system": "white",
}


class ConsoleOutput:
    """Thread-safe, coloured console logger bound to a prefix tag."""

    def __init__(self, tag: str = ""):
        self._tag = tag
        self._lock = threading.Lock()

    def _fmt(self, text: str, color: str, bold: bool = False) -> str:
        ts = datetime.now().strftime("%H:%M:%S")
        tag = f"[{self._tag}] " if self._tag else ""
        line = f"{colorize(ts, 'dim')} {tag}{colorize(text, color, bold)}"
        return line

    def info(self, text: str) -> None:
        self._write(self._fmt(text, "white"))

    def ok(self, text: str) -> None:
        self._write(self._fmt(text, "green"))

    def warn(self, text: str) -> None:
        self._write(self._fmt(text, "yellow"))

    def error(self, text: str) -> None:
        self._write(self._fmt(text, "red"))

    def debug(self, text: str) -> None:
        self._write(self._fmt(text, "dim"))

    def _write(self, line: str) -> None:
        with self._lock:
            print(line, flush=True)


# Global console used by the event bus when echoing events.
_console = ConsoleOutput("honey")


def console_colors_enabled() -> bool:
    return _console_enabled


def disable_console_colors() -> None:
    global _console_enabled
    _console_enabled = False


def emit(event: dict) -> None:
    """Publish an event dict to every subscriber in registration order."""
    event.setdefault("ts", _now_iso())
    with _subscriber_lock:
        listeners = list(_listeners)
    for listener in listeners:
        try:
            listener(event)
        except Exception as exc:  # a subscriber must never break the pipeline
            _console.error(f"subscriber error: {exc}")
    _echo(event)


def subscribe(listener: Callable[[dict], None]) -> None:
    """Register ``listener`` to receive every emitted event."""
    with _subscriber_lock:
        _listeners.append(listener)


def unsubscribe(listener: Callable[[dict], None]) -> None:
    with _subscriber_lock:
        if listener in _listeners:
            _listeners.remove(listener)


def clear_subscribers() -> None:
    """Remove all listeners (used by the offline demo model to start fresh)."""
    global _listeners
    with _subscriber_lock:
        _listeners = []


def set_echo(enabled: bool) -> None:
    """Enable/disable the automatic console echo of events.

    The offline demo model mutes the echo so it can render its own
    simulated-time timeline; the real honeypot network keeps it on.
    """
    global _echo_enabled
    _echo_enabled = enabled


def _echo(event: dict) -> None:
    """Print a compact, human-readable line for an event."""
    if not _console_enabled or not _echo_enabled:
        return
    kind = event.get("kind", "event")
    color = _KIND_COLORS.get(kind, "white")
    text = _render_event(event)
    _console._write(_console._fmt(text, color))


def _render_event(event: dict) -> str:
    kind = event.get("kind")
    src = event.get("src_ip", "?")
    proto = event.get("protocol", "")
    if kind == "connection":
        return f"CONN  {proto:6s} <- {src:>15}:{event.get('src_port', '?')}"
    if kind == "credential":
        uname = event.get("username", "?")
        pwd = event.get("password", "")
        shown = pwd if pwd else "«none»"
        return f"AUTH  {proto:6s} <- {src:>15}  {uname} / {shown}"
    if kind == "command":
        return f"CMD   {proto:6s} <- {src:>15}  {event.get('command', '')}"
    if kind == "alert":
        sev = event.get("severity", "info").upper()
        return f"ALERT [{sev}] {event.get('title', '')}  <- {src}"
    if kind == "intel":
        return f"INTEL {src:>15} risk={event.get('risk', 0):>3}  {event.get('classification', '')}"
    if kind == "system":
        return f"SYS   {event.get('message', '')}"
    return str(event)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def now_iso() -> str:
    return _now_iso()


def unix_now() -> float:
    return time.time()


_enable_windows_ansi()
