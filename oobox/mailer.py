"""Outbound SMTP send (off by default; enabled with OOB_SMTP_SEND=true).

Lets the operator send mail from a token address (``<token>@OOBDOMAIN``) — e.g. to test
email spoofing / SPF handling on a target, to drive an OOB-to-email flow, or just to send
a test that the catch-all can loop back. Replies come back to the catch-all automatically
(the From is a real token address on our own MX).

Delivery: through a configured smarthost (``OOB_SMTP_RELAY``) if set, else direct-to-MX
(resolve the recipient's MX via ``OOB_RESOLVER`` and connect on :25). Direct-to-MX from a
VPS is best-effort — many networks block outbound :25 and receivers weigh SPF/DKIM/PTR; a
smarthost relay is the reliable path.

Blocking smtplib work is meant to be called via ``asyncio.to_thread`` from the API.

FOR AUTHORIZED TESTING ONLY.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from dnslib import QTYPE, DNSRecord

from .config import Config


def _resolve_mx(domain: str, resolver: str) -> list[str]:
    try:
        pkt = DNSRecord.question(domain, "MX").send(resolver, 53, timeout=6)
        rec = DNSRecord.parse(pkt)
        mxs = sorted(
            (int(rr.rdata.preference), str(rr.rdata.label).rstrip("."))
            for rr in rec.rr if rr.rtype == QTYPE.MX
        )
        hosts = [h for _, h in mxs if h]
        if hosts:
            return hosts
    except Exception:
        pass
    return [domain]  # implicit MX: the domain's A record


def send_mail(config: Config, mail_from: str, to: str, subject: str,
              text: str, html: str | None = None) -> dict:
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = to
    msg["Subject"] = subject or ""
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=config.domain)
    msg.set_content(text or "")
    if html:
        msg.add_alternative(html, subtype="html")

    if config.smtp_relay:
        host, _, port_s = config.smtp_relay.partition(":")
        port = int(port_s) if port_s else 25
        try:
            return _deliver(config, host, port, mail_from, [to], msg, use_creds=True)
        except Exception as e:
            return {"ok": False, "error": f"relay {host}:{port}: {e}"}

    domain = to.rsplit("@", 1)[-1]
    errors = []
    for mx in _resolve_mx(domain, config.resolver):
        try:
            return _deliver(config, mx, 25, mail_from, [to], msg, use_creds=False)
        except Exception as e:
            errors.append(f"{mx}: {e}")
    return {"ok": False, "error": "; ".join(errors) or "no MX / delivery failed"}


def _deliver(config: Config, host: str, port: int, mail_from: str, rcpts: list[str],
             msg: EmailMessage, use_creds: bool) -> dict:
    helo = config.nameservers[0] if config.nameservers else config.domain
    with smtplib.SMTP(host, port, timeout=25, local_hostname=helo) as s:
        s.ehlo()
        if config.smtp_relay_starttls and s.has_extn("starttls"):
            s.starttls(context=ssl.create_default_context())
            s.ehlo()
        if use_creds and config.smtp_relay_user:
            s.login(config.smtp_relay_user, config.smtp_relay_pass or "")
        s.send_message(msg, from_addr=mail_from, to_addrs=rcpts)
    return {"ok": True, "host": host, "port": port}
