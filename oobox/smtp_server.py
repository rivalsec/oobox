"""Catch-all SMTP receiver (MX for OOBDOMAIN).

Accepts mail to any recipient under the zone — ``<token>@OOBDOMAIN`` (incl. plus-tags)
and ``<anything>@<token>.OOBDOMAIN`` — parses the full message, extracts the token and
any links (verification / reset / magic-link), and stores it. Unattributable mail to
the domain is kept under the synthetic token ``_catchall`` so it is never silently
dropped. Outbound send is not implemented (receive-only by default per config).
"""
from __future__ import annotations

import asyncio
import email
import logging
import re
from email.header import decode_header, make_header
from email.utils import parseaddr

from aiosmtpd.smtp import SMTP

from .config import Config
from .store import Store
from .tokens import label_from_rcpt

log = logging.getLogger("oobox.smtp")

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
CATCHALL = "_catchall"


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


class CatchAllHandler:
    def __init__(self, config: Config, store: Store):
        self.c = config
        self.store = store

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        dom = self.c.domain.lower()
        addr = address.lower().strip("<>")
        host = addr.split("@")[-1] if "@" in addr else ""
        if host == dom or host.endswith("." + dom):
            envelope.rcpt_tos.append(address)
            return "250 OK"
        return f"550 not authoritative for {host or address}"

    async def handle_DATA(self, server, session, envelope):
        src_ip = session.peer[0] if session.peer else "?"
        try:
            msg = email.message_from_bytes(envelope.content)
        except Exception:
            msg = None

        token = CATCHALL
        for rcpt in envelope.rcpt_tos:
            t = label_from_rcpt(rcpt, self.c.domain)   # ob-token, else the address label (bob@ → "bob")
            if t:
                token = t
                break

        subject = _decode(msg.get("Subject")) if msg else ""
        mail_from = envelope.mail_from or (parseaddr(msg.get("From"))[1] if msg else "")
        detail = self._parse(msg, envelope)

        eid = self.store.add_email(token, src_ip, mail_from, list(envelope.rcpt_tos),
                                   subject, detail)
        log.info("mail token=%s id=%s from=%s subj=%r rcpts=%s",
                 token, eid, mail_from, subject, envelope.rcpt_tos)
        return "250 Message accepted for delivery"

    def _parse(self, msg, envelope) -> dict:
        raw = envelope.content or b""
        detail: dict = {
            "mail_from": envelope.mail_from,
            "rcpt_tos": list(envelope.rcpt_tos),
            "size": len(raw),
            # Always keep the full raw RFC822 message (capped) for the dashboard's raw
            # viewer — extracted text/html parts below are for convenience, not a substitute.
            "raw": raw[: self.c.max_capture_bytes].decode("utf-8", "replace"),
        }
        if msg is None:
            return detail

        detail["headers"] = {k: _decode(v) for k, v in msg.items()}
        text_parts, html_parts, attachments = [], [], []
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            disp = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disp or part.get_filename():
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": _decode(part.get_filename()),
                    "content_type": ctype,
                    "size": len(payload),
                })
                continue
            try:
                payload = part.get_payload(decode=True) or b""
                text = payload.decode(part.get_content_charset() or "utf-8", "replace")
            except Exception:
                text = ""
            if ctype == "text/plain":
                text_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(text)

        text_body = "\n".join(text_parts)[: self.c.max_capture_bytes]
        html_body = "\n".join(html_parts)[: self.c.max_capture_bytes]
        detail["text"] = text_body
        detail["html"] = html_body
        detail["attachments"] = attachments
        links = _URL_RE.findall(text_body) + _URL_RE.findall(html_body)
        # de-dup, preserve order
        seen, uniq = set(), []
        for u in links:
            if u not in seen:
                seen.add(u)
                uniq.append(u)
        detail["links"] = uniq
        return detail


async def start_smtp(config: Config, store: Store) -> "SMTPListener":
    handler = CatchAllHandler(config, store)
    loop = asyncio.get_running_loop()
    hostname = config.nameservers[0] if config.nameservers else config.domain

    def factory():
        return SMTP(handler, hostname=hostname, ident="oobox")

    server = await loop.create_server(factory, host=config.bind_hosts, port=config.smtp_port)
    port = server.sockets[0].getsockname()[1]
    log.info("SMTP  listening on %s:%s (catch-all MX)", ",".join(config.bind_hosts), port)
    return SMTPListener(server, port)


class SMTPListener:
    def __init__(self, server, port):
        self.server = server
        self.port = port

    async def close(self):
        self.server.close()
        await self.server.wait_closed()
