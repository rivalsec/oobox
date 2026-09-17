"""Orchestrator: bring up every listener under one asyncio event loop.

`Server.start()` starts DNS + HTTP(S) + SMTP + control API and a periodic TTL sweeper,
and returns with the live listeners recorded (their bound ports are readable, which the
selftest and CLI rely on). `Server.stop()` tears everything down. The process lifecycle
(signal handling) lives in `__main__.cmd_serve`.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from .acme import AcmeStore
from .alerts import Alerter
from .config import Config
from .control_api import start_api
from .dns_server import start_dns
from .http_server import start_http
from .smtp_server import start_smtp
from .store import Store

log = logging.getLogger("oobox")

_PKG = Path(__file__).parent


def _read_asset(rel: str, fallback: str) -> str:
    try:
        return (_PKG / rel).read_text(encoding="utf-8")
    except OSError:
        return fallback


def load_collector_js() -> str:
    return _read_asset("payloads/collector.js", "/* oobox: collector.js missing */")


def load_html2canvas_js() -> str:
    return _read_asset("payloads/html2canvas.min.js", "/* oobox: html2canvas.min.js missing */")


def load_dashboard_html() -> str:
    return _read_asset("static/dashboard.html", "<h1>oobox</h1><p>dashboard.html missing</p>")


class Server:
    def __init__(self, config: Config):
        self.c = config
        self.store = Store(config.db_path)
        self.alerter = Alerter(config)
        self.store.on_event = self.alerter.notify
        self.acme = AcmeStore()
        self.collector_js = load_collector_js()
        self.html2canvas_js = load_html2canvas_js()
        self.dashboard_html = load_dashboard_html()
        self.dns = None
        self.http = None
        self.smtp = None
        self.api = None
        self._sweeper: asyncio.Task | None = None

    async def start(self) -> None:
        self.dns = await start_dns(self.c, self.store, self.acme)
        self.http = await start_http(self.c, self.store, self.collector_js,
                                     self.html2canvas_js)
        self.smtp = await start_smtp(self.c, self.store)
        self.api = await start_api(self.c, self.store, self.acme, self.dashboard_html)
        self._sweeper = asyncio.create_task(self._sweep_loop())
        if self.alerter.enabled:
            log.info("Telegram alerts on (window=%ss, kinds=%s, proxy=%s)",
                     self.alerter.window, ",".join(sorted(self.alerter.kinds)),
                     self.c.tg_proxy or "none")

    async def _sweep_loop(self) -> None:
        # Sweep hourly. Removes captures older than ttl_days and their on-disk files.
        while True:
            try:
                removed = self.store.sweep(self.c.ttl_days)
                stale = self.store.expired_files(self.c.ttl_days)
                for f in stale:
                    try:
                        Path(f["disk_path"]).unlink(missing_ok=True)
                    except OSError:
                        pass
                self.store.delete_files([f["id"] for f in stale])
                if any(removed.values()) or stale:
                    log.info("sweep removed=%s files=%s", removed, len(stale))
            except Exception as e:  # never let the sweeper kill the process
                log.warning("sweep error: %s", e)
            await asyncio.sleep(3600)

    async def stop(self) -> None:
        if self._sweeper:
            self._sweeper.cancel()
        for lst in (self.api, self.smtp, self.http, self.dns):
            if lst:
                try:
                    await lst.close()
                except Exception:
                    pass
        await self.alerter.close()
        self.store.close()
