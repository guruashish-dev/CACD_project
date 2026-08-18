"""Configuration loader for the honeypot network.

Reads ``config.json`` from the project root (``D:\\honey``).  The root is
derived from this file's location so the same config works no matter which
entry point is used (``main.py``, ``demo/*``, ``dashboard/app.py``).  All
values fall back to sane defaults if the file is missing or a key is absent.
"""

from __future__ import annotations

import json
from pathlib import Path

# Project root = parent of the ``honey`` package directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Standard ports used by each protocol honeypot.
DEFAULT_PORTS = {
    "ssh": 22,
    "http": 80,
    "ftp": 21,
    "telnet": 23,
    "mysql": 3306,
    "smtp": 25,
}

# Realistic banners used when config.json leaves one empty.
DEFAULT_BANNERS = {
    "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "http": "Apache/2.4.52 (Ubuntu) Server at localhost",
    "ftp": "220 ProFTPD 1.3.5e Server (Debian) [::ffff:127.0.0.1]",
    "telnet": "Debian GNU/Linux 11",
    "mysql": "MySQL 5.7.38-0ubuntu0.18.04.1",
    "smtp": "220 mail.example ESMTP Postfix (Ubuntu)",
}

DEFAULTS: dict = {
    "bind_host": "0.0.0.0",
    "data_dir": "data",
    "protocols": {
        name: {"port": DEFAULT_PORTS[name], "enabled": True,
               "banner": DEFAULT_BANNERS[name]}
        for name in DEFAULT_PORTS
    },
    "http_decoy_paths": ["/"],
    "intel": {
        "bruteforce_threshold": 5,
        "bruteforce_window_sec": 60,
        "recon_probes_threshold": 10,
        "recon_window_sec": 30,
        "multivector_protocols": 3,
    },
    "alerts": {
        "bruteforce": {"enabled": True, "severity": "high"},
        "credential_stuffing": {"enabled": True, "severity": "medium"},
        "multivector": {"enabled": True, "severity": "critical"},
        "recon_scan": {"enabled": True, "severity": "low"},
        "spam_relay": {"enabled": True, "severity": "medium"},
    },
    "default_credentials": [
        ["admin", "admin"],
        ["root", "root"],
    ],
    "dashboard": {"host": "127.0.0.1", "port": 8080},
}

_config: dict | None = None


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge ``override`` into a copy of ``base`` (dicts recurse)."""
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | Path | None = None) -> dict:
    """Load and cache the configuration dictionary."""
    global _config
    cfg_path = Path(path) if path else PROJECT_ROOT / "config.json"
    loaded: dict = {}
    if cfg_path.exists():
        try:
            loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid config.json: {exc}") from exc
    _config = _deep_merge(DEFAULTS, loaded)
    # Resolve data_dir relative to the project root.
    _config["data_dir"] = str((PROJECT_ROOT / _config["data_dir"]).resolve())
    return _config


def get_config() -> dict:
    """Return the cached config, loading it on first use."""
    if _config is None:
        load_config()
    return _config


def protocol_ports() -> dict[str, int]:
    """Map enabled protocol name -> configured port."""
    cfg = get_config()
    return {
        name: proto["port"]
        for name, proto in cfg["protocols"].items()
        if proto.get("enabled", True)
    }


def data_path(*parts: str) -> Path:
    """Return a Path inside the configured data directory."""
    return Path(get_config()["data_dir"]).joinpath(*parts)
