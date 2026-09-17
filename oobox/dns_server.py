"""Authoritative DNS listener for OOBDOMAIN (UDP + TCP).

Answers A/AAAA for any label in the zone (wildcard → self), serves SOA/NS/MX and the
``_acme-challenge`` TXT records for certbot DNS-01, and logs every token-attributable
query as a ``dns`` interaction. A single DNS hit to ``<token>.OOBDOMAIN`` is confirmed
OOB reach — the classic SSRF/blind-injection proof.
"""
from __future__ import annotations

import asyncio
import logging

import time

from dnslib import (CLASS, QTYPE, RR, A, AAAA, CAA, CNAME, MX, NS, SOA, TXT,
                    DNSHeader, DNSLabel, DNSRecord)

from .acme import AcmeStore
from .config import Config
from .store import Store

log = logging.getLogger("oobox.dns")

ZONE_KEY = "zone"                       # store settings key for zone overrides
CACHE_TTL = 2.0                         # seconds to cache zone overrides + custom records
RECORD_TYPES = ("A", "AAAA", "TXT", "CNAME", "MX", "CAA")


class DNSResponder:
    """Pure builder: raw query bytes + client IP -> raw reply bytes (+ logging).

    Answers reflect the env Config merged with runtime zone overrides and custom records
    edited on the dashboard's DNS Zone page (persisted in the store, read here through a
    short cache)."""

    def __init__(self, config: Config, store: Store, acme: AcmeStore):
        self.c = config
        self.store = store
        self.acme = acme
        self.zone = DNSLabel(config.domain)
        self._cache_ts = 0.0
        self._ov: dict = {}
        self._records: list[dict] = []

    # ------------------------------------------------------- effective config
    def _refresh(self) -> None:
        now = time.monotonic()
        if now - self._cache_ts < CACHE_TTL:
            return
        self._ov = self.store.get_setting(ZONE_KEY) or {}
        self._records = self.store.dns_records()
        self._cache_ts = now

    def _eff_ipv4(self):
        return self._ov.get("ipv4") or self.c.ipv4
    def _eff_ipv6(self):
        return self._ov.get("ipv6") or self.c.ipv6
    def _eff_ttl(self):
        return int(self._ov.get("ttl") or self.c.dns_ttl)
    def _eff_ns(self):
        return self._ov.get("ns") or self.c.nameservers
    def _eff_soa_mail(self):
        return self._ov.get("soa_mail") or self.c.soa_rname
    def _eff_mx(self):
        return (self._ov.get("mx_host") or self.c.domain, int(self._ov.get("mx_pref") or 10))

    def _customs(self, name_str: str) -> list[dict]:
        return [r for r in self._records if r["name"].rstrip(".").lower() == name_str]

    def _in_zone(self, name: DNSLabel) -> bool:
        return name == self.zone or name.matchSuffix(self.zone)

    def _apex(self, name: DNSLabel) -> bool:
        return name == self.zone

    def handle(self, data: bytes, src_ip: str) -> bytes | None:
        try:
            req = DNSRecord.parse(data)
        except Exception:
            return None
        reply = req.reply()
        reply.header = DNSHeader(id=req.header.id, qr=1, aa=1, ra=0)

        q = req.q
        qname = q.qname
        qtype = QTYPE.get(q.qtype, str(q.qtype))
        name_str = str(qname).rstrip(".")

        if not self._in_zone(qname):
            reply.header.rcode = 5  # REFUSED — we are not authoritative for this
            return reply.pack()

        self._refresh()
        self._log_query(name_str, qtype, src_ip)
        ttl = self._eff_ttl()

        added = self._answer(reply, qname, qtype, ttl)

        # Always assert authority with the SOA (helps negative/empty answers validate).
        if not added:
            reply.add_auth(RR(self.zone, QTYPE.SOA, ttl=ttl, rdata=self._soa()))
        return reply.pack()

    # -------------------------------------------------------- answer builder
    def _answer(self, reply: DNSRecord, qname: DNSLabel, qtype: str, ttl: int) -> bool:
        name_str = str(qname).rstrip(".").lower()

        # ACME DNS-01: _acme-challenge.<...> TXT
        if qtype in ("TXT", "ANY") and name_str.split(".")[0] == "_acme-challenge":
            vals = self.acme.get(name_str)
            for v in vals:
                reply.add_answer(RR(qname, QTYPE.TXT, ttl=ttl, rdata=TXT(v)))
            return bool(vals)

        # Custom records for this exact name take precedence over the wildcard defaults.
        customs = self._customs(name_str)
        added = self._answer_custom(reply, qname, qtype, ttl, customs)
        has_addr_custom = any(r["type"] in ("A", "AAAA", "CNAME") for r in customs)

        if qtype in ("A", "ANY") and self._eff_ipv4() and not has_addr_custom:
            reply.add_answer(RR(qname, QTYPE.A, ttl=ttl, rdata=A(self._eff_ipv4())))
            added = True
        if qtype in ("AAAA", "ANY") and self._eff_ipv6() and not has_addr_custom:
            reply.add_answer(RR(qname, QTYPE.AAAA, ttl=ttl, rdata=AAAA(self._eff_ipv6())))
            added = True

        if self._apex(qname):
            if qtype in ("SOA", "ANY"):
                reply.add_answer(RR(self.zone, QTYPE.SOA, ttl=ttl, rdata=self._soa()))
                added = True
            if qtype in ("NS", "ANY"):
                for ns in self._eff_ns():
                    reply.add_answer(RR(self.zone, QTYPE.NS, ttl=ttl, rdata=NS(ns)))
                added = True
            if qtype in ("MX", "ANY") and not any(r["type"] == "MX" for r in customs):
                host, pref = self._eff_mx()
                reply.add_answer(RR(self.zone, QTYPE.MX, ttl=ttl, rdata=MX(host, pref)))
                added = True
        return added

    def _answer_custom(self, reply, qname, qtype, ttl, customs) -> bool:
        added = False
        for r in customs:
            rtype, val = r["type"], r["value"]
            rttl = int(r["ttl"]) if r.get("ttl") else ttl
            want = qtype in (rtype, "ANY")
            # a CNAME answers A/AAAA queries too (resolver then chases it)
            if rtype == "CNAME" and qtype in ("A", "AAAA"):
                want = True
            if not want:
                continue
            try:
                if rtype == "A":
                    rd = A(val)
                elif rtype == "AAAA":
                    rd = AAAA(val)
                elif rtype == "TXT":
                    rd = TXT(val)
                elif rtype == "CNAME":
                    rd = CNAME(val)
                elif rtype == "MX":
                    rd = MX(val, int(r.get("prio") or 10))
                elif rtype == "CAA":
                    # value "flags tag \"data\"", e.g.  0 issue "letsencrypt.org"
                    parts = val.split(None, 2)
                    rd = CAA(int(parts[0]), parts[1], parts[2].strip('"'))
                else:
                    continue
            except Exception:
                continue
            rr_type = QTYPE.CNAME if (rtype == "CNAME" and qtype in ("A", "AAAA")) else getattr(QTYPE, rtype)
            reply.add_answer(RR(qname, rr_type, ttl=rttl, rdata=rd))
            added = True
        return added

    def _soa(self) -> SOA:
        ns = self._eff_ns()
        primary = ns[0] if ns else str(self.zone)
        # serial/refresh/retry/expire/minimum — conservative defaults for a dynamic zone
        return SOA(primary, self._eff_soa_mail(),
                   (1, 3600, 600, 86400, self._eff_ttl()))

    def _log_query(self, name_str: str, qtype: str, src_ip: str) -> None:
        from .tokens import label_from_host
        token = label_from_host(name_str, self.c.domain)
        if not token:
            return  # apex / out-of-zone queries aren't recorded
        self.store.add_interaction(
            token, "dns", src_ip,
            summary=f"{qtype} {name_str}",
            detail={"qname": name_str, "qtype": qtype, "src_ip": src_ip},
        )


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, responder: DNSResponder):
        self.responder = responder

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        reply = self.responder.handle(data, addr[0])
        if reply is not None:
            self.transport.sendto(reply, addr)


async def _handle_tcp(responder: DNSResponder, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "?"
    try:
        length = await reader.readexactly(2)
        n = int.from_bytes(length, "big")
        data = await reader.readexactly(n)
        reply = responder.handle(data, src_ip)
        if reply is not None:
            writer.write(len(reply).to_bytes(2, "big") + reply)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


async def start_dns(config: Config, store: Store, acme: AcmeStore) -> "DNSListener":
    responder = DNSResponder(config, store, acme)
    loop = asyncio.get_running_loop()
    hosts = config.bind_hosts
    transports = []
    try:
        for host in hosts:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(responder), local_addr=(host, config.dns_port))
            transports.append(transport)
        # start_server accepts a list of hosts and binds all of them for TCP.
        tcp_server = await asyncio.start_server(
            lambda r, w: _handle_tcp(responder, r, w),
            host=hosts, port=config.dns_port,
        )
    except OSError as e:
        for t in transports:
            t.close()
        import errno
        hint = ""
        if e.errno == errno.EADDRINUSE and config.dns_port == 53 and "0.0.0.0" in hosts:
            hint = (" — port 53 on the wildcard address is usually held by systemd-resolved "
                    "(127.0.0.53:53). Bind oobox to your public IP(s) instead: set "
                    "OOB_BIND=<public-ip>  (or disable the stub with DNSStubListener=no in "
                    "/etc/systemd/resolved.conf and restart systemd-resolved).")
        elif e.errno == errno.EADDRNOTAVAIL:
            hint = (" — that address isn't on a local interface. If you're behind 1:1 NAT / a "
                    "floating IP, don't bind the PUBLIC IP: set OOB_BIND to the interface IP "
                    "(e.g. 10.0.0.6) or 0.0.0.0, and put the public IP in OOB_IPV4 instead.")
        elif e.errno in (errno.EACCES, errno.EPERM) and config.dns_port < 1024:
            hint = (f" — binding privileged port {config.dns_port} needs root or "
                    "CAP_NET_BIND_SERVICE (the provided systemd unit grants it).")
        raise OSError(f"cannot bind DNS on {hosts}:{config.dns_port}: {e}{hint}") from e
    port = transports[0].get_extra_info("sockname")[1]
    log.info("DNS listening on %s:%s (UDP+TCP), zone=%s",
             ",".join(hosts), port, config.domain)
    return DNSListener(transports, tcp_server, responder, port)


class DNSListener:
    def __init__(self, udp_transports, tcp_server, responder, port):
        self.udp = udp_transports
        self.tcp = tcp_server
        self.responder = responder
        self.port = port

    async def close(self):
        for t in self.udp:
            t.close()
        self.tcp.close()
        await self.tcp.wait_closed()
