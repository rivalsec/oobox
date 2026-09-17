"""Telegram alerts with burst-coalescing and an optional proxy.

Every incoming capture (DNS/HTTP/file/mail/XSS) calls :meth:`Alerter.notify`. Instead of
firing one Telegram message per hit — a scanner or a chatty target could produce dozens a
second — events are collected in a **hold window** (``OOB_ALERT_WINDOW``, default 5s): the
first event of a burst schedules a flush ``window`` seconds later, every event in between
is folded in, and the flush sends a **single** summary ("23 OOB hits in 5s — dns×10 …").
Sparse events (one per window) each get their own message.

Delivery uses the Telegram Bot API over aiohttp. A proxy is optional: ``http(s)://…`` is
handled natively; ``socks5://…`` needs ``aiohttp_socks`` (if it is not installed, alerts
are disabled with a clear log line rather than crashing). ``OOB_TG_API_BASE`` can point at
a self-hosted Bot API / reverse proxy where api.telegram.org is blocked.
"""
from __future__ import annotations

import asyncio
import logging

import aiohttp

from .config import Config

log = logging.getLogger("oobox.alerts")

_EMOJI = {"dns": "🌐", "http": "📡", "file": "📁", "mail": "✉️", "xss": "🎯"}


class Alerter:
    def __init__(self, config: Config):
        self.c = config
        self.enabled = bool(config.tg_token and config.tg_chat)
        self.window = max(0.1, float(config.alert_window))
        self.kinds = set(config.alert_kinds)
        self._counts: dict[str, int] = {}
        self._tokens: list[str] = []
        self._total = 0
        self._last: tuple[str, str, str] | None = None
        self._flush_handle: asyncio.TimerHandle | None = None
        self._session: aiohttp.ClientSession | None = None
        self._proxy_kw: dict = {}

    # -------------------------------------------------------- event intake
    def notify(self, kind: str, token: str | None, summary: str) -> None:
        """Record one capture. Cheap and non-blocking; safe to call from any listener
        callback (all run on the event loop). Bursts are coalesced by the hold window."""
        if not self.enabled or kind not in self.kinds:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no running loop (e.g. unit context) — nothing to schedule
        self._total += 1
        self._counts[kind] = self._counts.get(kind, 0) + 1
        if token and token not in self._tokens:
            self._tokens.append(token)
        self._last = (kind, token or "?", summary or "")
        if self._flush_handle is None:
            self._flush_handle = loop.call_later(self.window, self._on_window)

    def _on_window(self) -> None:
        self._flush_handle = None
        asyncio.create_task(self._flush())

    async def _flush(self) -> None:
        if self._total == 0:
            return
        text = self._format()
        self._total = 0
        self._counts = {}
        self._tokens = []
        self._last = None
        await self._send(text)

    def _format(self) -> str:
        if self._total == 1 and self._last:
            kind, token, summary = self._last
            e = _EMOJI.get(kind, "•")
            return f"{e} oobox: {kind} hit on {token}\n{summary}".strip()
        parts = " ".join(f"{_EMOJI.get(k,'•')}{k}×{n}" for k, n in sorted(self._counts.items()))
        toks = ", ".join(self._tokens[:5]) + (f" (+{len(self._tokens)-5})" if len(self._tokens) > 5 else "")
        msg = f"🛰 oobox: {self._total} OOB hits in {self.window:g}s\n{parts}\ntokens: {toks}"
        if self._last:
            kind, token, summary = self._last
            msg += f"\nlatest: {kind} {token} {summary}"
        return msg

    # ------------------------------------------------------------- delivery
    async def _client(self) -> aiohttp.ClientSession:
        if self._session is not None:
            return self._session
        proxy = self.c.tg_proxy
        if proxy and proxy.lower().startswith("socks"):
            try:
                from aiohttp_socks import ProxyConnector
            except ImportError:
                log.error("OOB_TG_PROXY is a socks proxy but aiohttp_socks is not installed; "
                          "install it or use an http(s) proxy — disabling alerts")
                self.enabled = False
                raise RuntimeError("aiohttp_socks required for socks proxy")
            self._session = aiohttp.ClientSession(connector=ProxyConnector.from_url(proxy))
            self._proxy_kw = {}
        else:
            self._session = aiohttp.ClientSession()
            self._proxy_kw = {"proxy": proxy} if proxy else {}
        return self._session

    async def _send(self, text: str) -> None:
        url = f"{self.c.tg_api_base}/bot{self.c.tg_token}/sendMessage"
        payload = {"chat_id": self.c.tg_chat, "text": text, "disable_web_page_preview": True}
        try:
            session = await self._client()
        except RuntimeError:
            return
        try:
            async with session.post(url, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=15),
                                    **self._proxy_kw) as r:
                if r.status != 200:
                    body = await r.text()
                    log.warning("telegram send failed %s: %s", r.status, body[:200])
        except Exception as e:  # never let an alert failure disturb capture
            log.warning("telegram send error: %s", e)

    async def close(self) -> None:
        if self._flush_handle is not None:
            self._flush_handle.cancel()
            self._flush_handle = None
        if self._session is not None:
            await self._session.close()
            self._session = None
