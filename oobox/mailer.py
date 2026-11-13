"""Outbound SMTP send (off by default; enabled with OOB_SMTP_SEND=true).

Lets the operator send mail from any address — a token address (``<token>@OOBDOMAIN``),
any mailbox on the zone, or an arbitrary external address via ``from_full`` — e.g. to test
email spoofing / SPF handling on a target, to drive an OOB-to-email flow, or just to send
a test that the catch-all can loop back. Replies come back to the catch-all automatically
only when the From is a real address on our own MX.

Delivery: through a configured smarthost (``OOB_SMTP_RELAY``) if set, else direct-to-MX
(resolve the recipient's MX via ``OOB_RESOLVER`` and connect on :25). Direct-to-MX from a
VPS is best-effort — many networks block outbound :25 and receivers weigh SPF/DKIM/PTR; a
smarthost relay is the reliable path.

Besides the structured form, :func:`send_raw` sends an operator-edited raw RFC822
message verbatim (every header editable — preview via the API returns the exact bytes
the form would send).

Blocking smtplib work is meant to be called via ``asyncio.to_thread`` from the API.

FOR AUTHORIZED TESTING ONLY.
"""
from __future__ import annotations

import email
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate, getaddresses, make_msgid, parseaddr

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


def build_message(config: Config, mail_from: str, to: str, subject: str,
                  text: str, html: str | None = None,
                  from_name: str | None = None) -> EmailMessage:
    """Build (not send) the outgoing message. ``text`` and/or ``html`` (html-only sends a
    single ``text/html`` part — no empty plain alternative); ``from_name`` becomes the
    display part of the From header (``Name <addr>``). Split out so the API can hand the
    operator the exact raw bytes for editing before :func:`send_raw` sends them."""
    msg = EmailMessage()
    msg["From"] = formataddr((from_name, mail_from)) if from_name else mail_from
    msg["To"] = to
    msg["Subject"] = subject or ""
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=config.domain)
    if html and not (text or "").strip():
        msg.set_content(html, subtype="html")       # html-only message
    else:
        msg.set_content(text or "")
        if html:
            msg.add_alternative(html, subtype="html")
    return msg


def send_mail(config: Config, mail_from: str, to: str, subject: str,
              text: str, html: str | None = None,
              from_name: str | None = None) -> dict:
    return _send(config, build_message(config, mail_from, to, subject,
                                       text, html, from_name), mail_from, [to])


def _message_recipients(msg: EmailMessage) -> list[str]:
    """Every recipient named in To/Cc/Bcc (what smtplib derives when no explicit rcpts)."""
    return [a for _, a in getaddresses(msg.get_all("To", []) + msg.get_all("Cc", [])
                                       + msg.get_all("Bcc", [])) if a]


def parse_raw(raw: str) -> EmailMessage:
    """Parse an operator-edited raw RFC822 message. Tolerates a pasted mbox ``From_`` line;
    validates only that it names a sender and at least one recipient — everything else
    (headers, MIME structure, encodings) is the operator's to craft. Raises ``ValueError``
    with an operator-readable reason."""
    s = raw.lstrip("\r\n")
    if s.startswith("From "):                      # mbox envelope line, not a header
        s = s.split("\n", 1)[1] if "\n" in s else ""
    msg = email.message_from_string(s, policy=email.policy.default)
    frm = parseaddr(str(msg.get("From") or ""))[1]
    if "@" not in frm:
        raise ValueError("raw message needs a From: header with an address")
    if not _message_recipients(msg):
        raise ValueError("raw message needs at least one To:/Cc:/Bcc: recipient")
    return msg


def send_raw(config: Config, raw: str, mail_from: str | None = None,
             to: str | None = None) -> dict:
    """Send an operator-edited raw message verbatim — no header is added or rewritten.
    Hybrid envelope: explicit ``mail_from``/``to`` (from the compose form) override the
    headers, otherwise the envelope is derived from them. With an explicit envelope
    recipient the Bcc header is deleted first (smtplib strips it only when it derives
    recipients itself, so it would otherwise leak to every recipient)."""
    msg = parse_raw(raw)
    if to:
        del msg["Bcc"]
        return _send(config, msg, mail_from, [to])
    return _send(config, msg, mail_from, None)


def _send(config: Config, msg: EmailMessage, from_addr: str | None,
          rcpts: list[str] | None) -> dict:
    if config.smtp_relay:
        host, _, port_s = config.smtp_relay.partition(":")
        port = int(port_s) if port_s else 25
        try:
            return _deliver(config, host, port, from_addr, rcpts, msg, use_creds=True)
        except Exception as e:
            return {"ok": False, "error": f"relay {host}:{port}: {e}"}

    rcpts = rcpts or _message_recipients(msg)
    domain = (rcpts[0].rsplit("@", 1)[-1] if rcpts else config.domain)
    errors = []
    for mx in _resolve_mx(domain, config.resolver):
        try:
            return _deliver(config, mx, 25, from_addr, rcpts, msg, use_creds=False)
        except Exception as e:
            errors.append(f"{mx}: {e}")
    return {"ok": False, "error": "; ".join(errors) or "no MX / delivery failed"}


def _deliver(config: Config, host: str, port: int, mail_from: str | None,
             rcpts: list[str] | None, msg: EmailMessage, use_creds: bool) -> dict:
    helo = config.nameservers[0] if config.nameservers else config.domain
    with smtplib.SMTP(host, port, timeout=25, local_hostname=helo) as s:
        s.ehlo()
        if config.smtp_relay_starttls and s.has_extn("starttls"):
            s.starttls(context=ssl.create_default_context())
            s.ehlo()
        if use_creds and config.smtp_relay_user:
            s.login(config.smtp_relay_user, config.smtp_relay_pass or "")
        if mail_from is None:
            s.send_message(msg)     # envelope (and Bcc stripping) from the headers
        else:
            s.send_message(msg, from_addr=mail_from, to_addrs=rcpts)
    return {"ok": True, "host": host, "port": port}
