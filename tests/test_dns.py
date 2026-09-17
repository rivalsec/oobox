"""DNS listener can bind multiple addresses (one box → two nameserver IPs)."""
import asyncio

import pytest
from dnslib import DNSRecord

from oobox.acme import AcmeStore
from oobox.config import Config
from oobox.dns_server import start_dns
from oobox.store import Store


def test_multi_bind_answers_on_every_address():
    async def run():
        c = Config()
        c.domain = "oob.test"
        c.ipv4 = "127.0.0.1"
        c.bind_host = "127.0.0.1 127.0.0.2"   # two distinct IPs on one host
        c.dns_port = 0                          # can't share an ephemeral port across addrs…
        # …so pick a fixed high port; skip if it's unavailable in the sandbox.
        c.dns_port = 15987
        store = Store(":memory:")
        try:
            dns = await start_dns(c, store, AcmeStore())
        except OSError:
            pytest.skip("cannot bind the test DNS port")
            return
        try:
            def q(ip):
                pkt = DNSRecord.question("ns2.oob.test", "A").send(ip, 15987, timeout=3)
                return [str(r.rdata) for r in DNSRecord.parse(pkt).rr if r.rtype == 1]
            a1 = await asyncio.to_thread(q, "127.0.0.1")
            a2 = await asyncio.to_thread(q, "127.0.0.2")
            assert a1 == ["127.0.0.1"], a1
            assert a2 == ["127.0.0.1"], a2   # both IPs serve the same authoritative zone
        finally:
            await dns.close()
            store.close()

    asyncio.run(run())
