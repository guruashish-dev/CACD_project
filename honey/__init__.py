"""Multi-Protocol Honeypot Network — core engine package.

Provides configuration loading, SQLite persistence, an event bus,
threat-intelligence scoring, alert rules, and HTML reporting.  The
concrete protocol honeypots live in ``honey.honeypots`` and are
registered through ``honey.honeypots.REGISTRY``.
"""

__version__ = "1.0.0"
