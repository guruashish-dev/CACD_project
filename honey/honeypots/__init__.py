"""Protocol honeypot registry.

``REGISTRY`` maps each protocol name to its honeypot class.  The
orchestrator (``main.py``) and the demo tooling both enumerate this map,
so adding a honeypot is a matter of dropping a module in and registering
it here.
"""

from .base import BaseHoneypot
from .ssh_hp import SSHHoneypot
from .http_hp import HTTPHoneypot
from .ftp_hp import FTPHoneypot
from .telnet_hp import TelnetHoneypot
from .mysql_hp import MySQLHoneypot
from .smtp_hp import SMTPHoneypot

REGISTRY: dict[str, type[BaseHoneypot]] = {
    "ssh": SSHHoneypot,
    "http": HTTPHoneypot,
    "ftp": FTPHoneypot,
    "telnet": TelnetHoneypot,
    "mysql": MySQLHoneypot,
    "smtp": SMTPHoneypot,
}

PROTOCOL_ORDER = ["ssh", "http", "ftp", "telnet", "mysql", "smtp"]


def create(name: str, config: dict) -> BaseHoneypot:
    """Instantiate a honeypot by name."""
    if name not in REGISTRY:
        raise KeyError(f"unknown honeypot: {name}")
    return REGISTRY[name](config)


__all__ = ["BaseHoneypot", "REGISTRY", "PROTOCOL_ORDER", "create"]
