"""Alerter coalescing: a burst within the hold window collapses to one message."""
import asyncio

from oobox.alerts import Alerter
from oobox.config import Config


def _alerter(window=0.15, **over):
    c = Config()
    c.tg_token = "dummy"
    c.tg_chat = "1"
    c.alert_window = window
    for k, v in over.items():
        setattr(c, k, v)
    a = Alerter(c)
    sent = []
    async def fake(text):
        sent.append(text)
    a._send = fake
    return a, sent


def test_burst_coalesces_to_one_message():
    a, sent = _alerter(window=0.15)

    async def run():
        for _ in range(20):
            a.notify("http", "obtoken12", "GET /x")
        a.notify("xss", "obtoken12", "https://admin/panel")
        await asyncio.sleep(0.4)          # let the window flush
        await a.close()

    asyncio.run(run())
    assert len(sent) == 1, sent
    assert "21 OOB hits" in sent[0]        # 20 http + 1 xss
    assert "http×20" in sent[0] and "xss×1" in sent[0]


def test_two_bursts_two_messages():
    a, sent = _alerter(window=0.15)

    async def run():
        for _ in range(5):
            a.notify("dns", "obt", "A obt.oob")
        await asyncio.sleep(0.3)          # first window flushes
        for _ in range(3):
            a.notify("dns", "obt", "A obt.oob")
        await asyncio.sleep(0.3)          # second window flushes
        await a.close()

    asyncio.run(run())
    assert len(sent) == 2, sent


def test_single_event_message():
    a, sent = _alerter(window=0.1)

    async def run():
        a.notify("mail", "obt", "from x: verify")
        await asyncio.sleep(0.3)
        await a.close()

    asyncio.run(run())
    assert len(sent) == 1 and "mail hit on obt" in sent[0]


def test_disabled_when_unconfigured():
    c = Config()  # no tg_token / tg_chat
    a = Alerter(c)
    assert a.enabled is False
    a.notify("http", "obt", "x")          # must be a no-op, no scheduling


def test_kind_filter():
    a, sent = _alerter(window=0.1, alert_kinds=["xss"])

    async def run():
        a.notify("http", "obt", "ignored")
        a.notify("xss", "obt", "kept")
        await asyncio.sleep(0.25)
        await a.close()

    asyncio.run(run())
    assert len(sent) == 1 and "xss hit" in sent[0]
