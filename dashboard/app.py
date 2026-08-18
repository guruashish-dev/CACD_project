"""Live web dashboard for the honeypot network.

A small Flask app exposing:

* ``/``                  — the single-page dashboard UI
* ``/api/stats``         — KPI counts, protocol mix, top sources, timeline
* ``/api/connections``   — recent connection/probe events
* ``/api/credentials``   — captured credentials
* ``/api/commands``      — shell commands recorded by the fake consoles
* ``/api/alerts``        — alert log
* ``/api/intel``         — per-source threat intelligence
* ``/api/stream``        — Server-Sent-Events feed of live events

The dashboard subscribes to the shared event bus, so it renders activity
from the real honeypots *and* from the offline demo model identically.
"""

from __future__ import annotations

import json
import queue
import sys
import threading
from pathlib import Path

# Make `honey` importable regardless of the current working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, Response, jsonify, request, send_from_directory  # noqa: E402

from honey import eventlog  # noqa: E402
from honey.config import data_path  # noqa: E402
from honey.database import Database  # noqa: E402

# ---------------------------------------------------------------------------
# Live event hub (fan-out to every connected SSE stream)
# ---------------------------------------------------------------------------
class _Hub:
    def __init__(self):
        self._subs: list[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, event: dict) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass


_hub = _Hub()
eventlog.subscribe(_hub.publish)

_db: Database | None = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database(data_path("honey.db"))
    return _db


def _limit() -> int:
    try:
        return min(int(request.args.get("limit", 100)), 1000)
    except (TypeError, ValueError):
        return 100


def create_app(db: Database | None = None) -> Flask:
    global _db
    _db = db or get_db()

    app = Flask(__name__, static_folder="static", static_url_path="/static")

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.get("/api/stats")
    def stats():
        database = get_db()
        return jsonify({
            "counts": database.counts(),
            "protocols": database.protocol_counts(),
            "top_sources": database.top_sources(8),
            "classifications": database.classification_counts(),
            "timeline": database.timeline("minute", minutes=10),
            "status": "ok",
        })

    @app.get("/api/connections")
    def connections():
        return jsonify(get_db().recent_connections(_limit()))

    @app.get("/api/credentials")
    def credentials():
        return jsonify(get_db().recent_credentials(_limit()))

    @app.get("/api/commands")
    def commands():
        return jsonify(get_db().recent_commands(_limit()))

    @app.get("/api/alerts")
    def alerts():
        return jsonify(get_db().recent_alerts(_limit()))

    @app.get("/api/intel")
    def intel():
        return jsonify(get_db().intel_table(_limit()))

    @app.get("/api/stream")
    def stream():
        def generate():
            q = _hub.subscribe()
            try:
                while True:
                    try:
                        event = q.get(timeout=15)
                        yield f"data: {json.dumps(event)}\n\n"
                    except queue.Empty:
                        yield ": keepalive\n\n"
            finally:
                _hub.unsubscribe(q)

        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    return app


def start_dashboard(db: Database | None = None, host: str | None = None,
                    port: int | None = None):
    """Run the dashboard in a background thread; returns (thread, port)."""
    from honey.config import get_config
    dash = get_config()["dashboard"]
    host = host or dash["host"]
    port = port or dash["port"]
    app = create_app(db)

    server = threading.Thread(
        target=lambda: app.run(host=host, port=port, threaded=True,
                               use_reloader=False, debug=False),
        daemon=True)
    server.start()
    return server, port


if __name__ == "__main__":
    # Standalone launch: python -m dashboard.app
    from honey.config import load_config
    load_config()
    create_app().run(host="127.0.0.1", port=8080, threaded=True, debug=False)
