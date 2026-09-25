"""Authenticated control API (bearer key + IP allowlist).

The only non-public surface. The harness client (``oob.py``) mints tokens, polls
interactions, reads mail, uploads payloads, and pulls blind-XSS reports through here.
certbot's DNS-01 hooks call ``/acme/present`` and ``/acme/cleanup``.

    POST /register              {note?, meta?}            -> token + per-channel endpoints
    GET  /poll?token=&since=&kind=                        -> dns/http/file interactions
    GET  /mail?token=&since=  /  GET /mail/{id}?token=    -> received mail
    GET  /xss?token=&since=   /  GET /xss/{id}?token=     -> blind-XSS reports
    GET  /pages?token=        /  GET /pages/{id}?token=   -> spidered/extra victim pages
    POST /upload?token=&path=  (raw body)                 -> host a payload, returns URL
    GET  /files?token=                                    -> hosted files for a token
    GET  /file?token=&path=                               -> raw bytes of one hosted file
    DELETE /files?token=&path=                            -> delete one hosted file (row + bytes)
    POST /send  {token,to,subject,body,html?,tag?}        -> send mail from <token>@domain
    GET  /sent?token=                                     -> mail sent from a token
    GET  /lookup?token=                                   -> cross-channel correlation summary
    GET  /craft?victim=&token=                            -> crafted victim-embedding catch-addresses
    GET  /tokens                                          -> all tokens
    GET  /overview                                        -> tokens + per-channel counts
    GET  /feed?before=&limit=&kind=                       -> merged activity across all tokens
    GET  /all/emails  /  GET /all/xss   (before=,limit=)  -> all-token email / blind-XSS lists
    GET  /zone   /  POST /zone                            -> DNS zone config (read / override)
    POST /zone/records  /  DELETE /zone/records/{id}      -> custom DNS records
    POST /acme/present / POST /acme/cleanup   {name,value}
    GET  /healthz   (unauthenticated liveness)

A browser dashboard is served on this same port at ``/`` behind a cookie login
(``/login`` — you authenticate with the API key). API routes accept either the bearer
key (``oob.py``) or the session cookie (dashboard); the IP allowlist applies to both.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import html as htmllib
import json
import logging
import os
import posixpath
import ssl
import time

from aiohttp import web

import ipaddress
import re

from .acme import AcmeStore
from .config import Config, is_staging_cert
from .craft import craft_addresses
from .dns_server import RECORD_TYPES, ZONE_KEY
from .http_server import CALLBACK_PATH, COLLECTOR_JS_PATH, MAX_DELAY_MS
from .store import Store
from .tokens import is_label, is_token, label_from_rcpt, mint

_LOCAL_RE = re.compile(r"[a-z0-9._+-]{1,64}")   # allowed email local-part for sending

log = logging.getLogger("oobox.api")

SESSION_COOKIE = "oobox_session"
SESSION_TTL = 12 * 3600
HTML_PATHS = {"/", "/dashboard"}
AUTH_EXEMPT = {"/healthz", "/login", "/logout", "/favicon.ico"}

_FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
            '<rect width="32" height="32" rx="6" fill="#0f1115"/>'
            '<text x="16" y="22" font-size="18" text-anchor="middle">🛰</text></svg>')

RESERVED_PATHS = {COLLECTOR_JS_PATH, CALLBACK_PATH}
CONFIG_KEY = web.AppKey("config", Config)


def _client_ip(request: web.Request) -> str:
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return peer[0] if peer else (request.remote or "?")


def _safe_path(path: str) -> str | None:
    """Normalise an upload path to a single rooted, traversal-free path."""
    if not path:
        return None
    p = "/" + path.lstrip("/")
    p = posixpath.normpath(p)
    if p in (".", "/") or ".." in p.split("/"):
        return None
    return p


class ControlAPI:
    def __init__(self, config: Config, store: Store, acme: AcmeStore,
                 dashboard_html: str = ""):
        self.c = config
        self.store = store
        self.acme = acme
        self.dashboard_html = dashboard_html

    # ----------------------------------------------------------- URL helpers
    def _base(self, token: str) -> str:
        scheme = "https" if self.c.http_tls() else "http"
        port = self.c.https_port if scheme == "https" else self.c.http_port
        std = 443 if scheme == "https" else 80
        hostport = f"{token}.{self.c.domain}" + ("" if port == std else f":{port}")
        return f"{scheme}://{hostport}"

    def _endpoints(self, token: str) -> dict:
        base = self._base(token)
        return {
            "token": token,
            "subdomain": f"{token}.{self.c.domain}",
            "email": f"{token}@{self.c.domain}",
            "http_base": base,
            "file_base": base + "/",
            "collector_js": base + COLLECTOR_JS_PATH,
            "callback": base + CALLBACK_PATH,
        }

    # ---------------------------------------------------------------- routes
    async def register(self, request: web.Request) -> web.Response:
        data = await _json(request)
        name = str(data.get("name") or "").strip().lower()
        if name:
            if not is_label(name):
                raise web.HTTPBadRequest(text="name must be a DNS-safe label (a-z0-9-, ≤63)")
            if self.store.token_exists(name):
                raise web.HTTPConflict(text="that name already exists")
            token = name
        else:
            length = int(data["len"]) if str(data.get("len") or "").isdigit() else self.c.token_len
            token = mint(exists=self.store.token_exists, length=length)
        self.store.create_token(token, note=data.get("note"), meta=data.get("meta"))
        log.info("registered token=%s note=%r", token, data.get("note"))
        return web.json_response(self._endpoints(token))

    async def poll(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        since = _int(request.query.get("since"), 0)
        kinds = [k for k in (request.query.get("kind") or "").split(",") if k] or None
        before = _int(request.query.get("before"), 0) or None
        limit = min(_int(request.query.get("limit"), 500), 500)
        rows = self.store.interactions(token, since=since, kinds=kinds, limit=limit, before=before)
        cursor = (rows[0]["id"] if rows else since) if before is not None else (rows[-1]["id"] if rows else since)
        nb = rows[-1]["id"] if (before is not None and len(rows) == limit) else None
        return web.json_response({"token": token, "cursor": cursor, "next_before": nb,
                                  "interactions": rows})

    async def mail_list(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        since = _int(request.query.get("since"), 0)
        before = _int(request.query.get("before"), 0) or None
        limit = min(_int(request.query.get("limit"), 200), 500)
        rows = self.store.emails(token, since=since, limit=limit, before=before)
        nb = rows[-1]["id"] if (before is not None and len(rows) == limit) else None
        cursor = rows[-1]["id"] if rows else since
        return web.json_response({"token": token, "cursor": cursor, "next_before": nb,
                                  "emails": rows})

    async def mail_get(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        mid = _int(request.match_info["id"], -1)
        rec = self.store.email(token, mid)
        if rec is None:
            raise web.HTTPNotFound(text="no such message for token")
        return web.json_response(rec)

    async def xss_list(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        since = _int(request.query.get("since"), 0)
        before = _int(request.query.get("before"), 0) or None
        limit = min(_int(request.query.get("limit"), 200), 500)
        rows = self.store.xss_reports(token, since=since, limit=limit, before=before)
        nb = rows[-1]["id"] if (before is not None and len(rows) == limit) else None
        cursor = rows[-1]["id"] if rows else since
        return web.json_response({"token": token, "cursor": cursor, "next_before": nb,
                                  "reports": rows})

    async def xss_get(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        rid = _int(request.match_info["id"], -1)
        rec = self.store.xss_report(token, rid)
        if rec is None:
            raise web.HTTPNotFound(text="no such report for token")
        return web.json_response(rec)

    async def pages_list(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        since = _int(request.query.get("since"), 0)
        before = _int(request.query.get("before"), 0) or None
        limit = min(_int(request.query.get("limit"), 500), 500)
        rows = self.store.xss_pages(token, since=since, limit=limit, before=before)
        nb = rows[-1]["id"] if (before is not None and len(rows) == limit) else None
        cursor = rows[-1]["id"] if rows else since
        return web.json_response({"token": token, "cursor": cursor, "next_before": nb,
                                  "pages": rows})

    async def pages_get(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        pid = _int(request.match_info["id"], -1)
        rec = self.store.xss_page(token, pid)
        if rec is None:
            raise web.HTTPNotFound(text="no such page for token")
        return web.json_response(rec)

    async def upload(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        if not (is_token(token) or is_label(token)):
            raise web.HTTPBadRequest(text="not a valid token/label")
        if not self.store.token_exists(token):
            self.store.create_token(token)  # allow hosting under a not-yet-registered label
        path = _safe_path(request.query.get("path", ""))
        if not path:
            raise web.HTTPBadRequest(text="missing/invalid ?path=")
        if path in RESERVED_PATHS:
            raise web.HTTPBadRequest(text=f"path {path} is reserved")

        body = await request.content.read(self.c.max_upload_bytes + 1)
        if len(body) > self.c.max_upload_bytes:
            raise web.HTTPRequestEntityTooLarge(
                max_size=self.c.max_upload_bytes, actual_size=len(body))

        disk_dir = os.path.join(self.c.files_dir, token)
        os.makedirs(disk_dir, exist_ok=True)
        disk_path = os.path.join(disk_dir, hashlib.sha256(path.encode()).hexdigest())
        with open(disk_path, "wb") as f:
            f.write(body)
        ctype = request.headers.get("Content-Type", "application/octet-stream").split(";")[0]
        sha = hashlib.sha256(body).hexdigest()

        # Optional programmable response (SSRF/open-redirect/XXE staging): status override,
        # extra response headers (?header=Name:%20Value, repeatable), a 3xx Location
        # (?redirect=), and/or an artificial delay (?delay_ms=). A pure rule needs no body.
        status = _int(request.query.get("status"), 0) or None
        if status is not None and not (100 <= status <= 599):
            raise web.HTTPBadRequest(text="status must be 100..599")
        redirect = (request.query.get("redirect") or "").strip() or None
        if redirect and len(redirect) > 4096:
            raise web.HTTPBadRequest(text="redirect too long")
        delay_ms = _int(request.query.get("delay_ms"), 0) or None
        if delay_ms is not None:
            delay_ms = max(0, min(delay_ms, MAX_DELAY_MS)) or None
        hdrs: dict[str, str] = {}
        for hv in request.query.getall("header", []):
            k, sep, v = hv.partition(":")
            k, v = k.strip(), v.strip()
            if sep and k:
                hdrs[k] = v
        resp_headers = json.dumps(hdrs) if hdrs else None

        self.store.add_file(token, path, ctype, len(body), sha, disk_path,
                            status=status, resp_headers=resp_headers,
                            redirect=redirect, delay_ms=delay_ms)
        url = self._base(token) + path
        log.info("hosted token=%s path=%s bytes=%s status=%s redirect=%s -> %s",
                 token, path, len(body), status, redirect, url)
        return web.json_response({"token": token, "path": path, "url": url,
                                  "size": len(body), "sha256": sha, "content_type": ctype,
                                  "status": status, "redirect": redirect,
                                  "delay_ms": delay_ms, "headers": hdrs or None})

    async def files(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        return web.json_response({"token": token, "files": self.store.files(token)})

    async def file_get(self, request: web.Request) -> web.Response:
        """Return a hosted file's raw bytes (for editing/downloading from the dashboard).
        This reads through the control API — no interaction is logged, unlike a target
        fetch of the public host."""
        token = _require(request, "token")
        path = _safe_path(request.query.get("path", ""))
        if not path:
            raise web.HTTPBadRequest(text="missing/invalid ?path=")
        rec = self.store.get_file(token, path)
        if not rec or not os.path.exists(rec["disk_path"]):
            raise web.HTTPNotFound(text="no such file for token")
        return web.FileResponse(
            rec["disk_path"],
            headers={"Content-Type": rec["content_type"] or "application/octet-stream"},
        )

    async def file_delete(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        path = _safe_path(request.query.get("path", ""))
        if not path:
            raise web.HTTPBadRequest(text="missing/invalid ?path=")
        rec = self.store.delete_file(token, path)
        if not rec:
            raise web.HTTPNotFound(text="no such file for token")
        try:
            os.remove(rec["disk_path"])
        except OSError:
            pass  # bytes already gone (swept / manual) — the row is what mattered
        log.info("deleted hosted token=%s path=%s", token, path)
        return web.json_response({"ok": True, "token": token, "path": path})

    # ------------------------------------------------------------- outbound mail
    def _crafted_sender(self, full: str) -> tuple[str, str]:
        """Validate a full crafted From address (from the address builder) and return
        (mail_from, correlation-label). Restricted to bare addresses within our own zone and
        to the clean/sendable shapes — quoted/encoded/comment forms are rejected for send."""
        addr = full.strip().strip("<>").lower()
        if "@" not in addr or re.search(r"""[\s<>"'(),;:%]""", addr):
            raise web.HTTPBadRequest(text="from_full must be a bare address (no quotes/%/comments)")
        host = addr.rsplit("@", 1)[-1]
        dom = self.c.domain
        if not (host == dom or host.endswith("." + dom)):
            raise web.HTTPBadRequest(text="from_full host must be your OOB domain or a subdomain of it")
        return addr, (label_from_rcpt(addr, dom) or "_catchall")

    async def send(self, request: web.Request) -> web.Response:
        if not self.c.smtp_send:
            raise web.HTTPForbidden(
                text="outbound send is disabled; set OOB_SMTP_SEND=true (and ideally "
                     "OOB_SMTP_RELAY) to enable")
        data = await _json(request)
        to = str(data.get("to") or "").strip()
        if "@" not in to:
            raise web.HTTPBadRequest(text="valid 'to' address required")

        # sender: a full crafted address via `from_full`, an arbitrary local-part via `from`
        # (bob → bob@OOBDOMAIN), or a token.
        full = str(data.get("from_full") or "").strip()
        frm = str(data.get("from") or "").strip().lower()
        tok = str(data.get("token") or "").strip()
        if full:
            mail_from, label = self._crafted_sender(full)
        elif frm:
            if "@" in frm:
                frm = frm.split("@", 1)[0]
            if not _LOCAL_RE.fullmatch(frm):
                raise web.HTTPBadRequest(text="invalid 'from' local-part")
            mail_from, label = f"{frm}@{self.c.domain}", frm.split("+", 1)[0]
        elif tok:
            if not (is_token(tok) or is_label(tok)):
                raise web.HTTPBadRequest(text="invalid token")
            tag = str(data.get("tag") or "").strip()
            local = f"{tok}+{tag}" if tag else tok
            mail_from, label = f"{local}@{self.c.domain}", tok
        else:
            raise web.HTTPBadRequest(text="need 'from_full', 'from' (e.g. bob), or 'token'")

        subject = data.get("subject") or ""
        body = data.get("body") or ""
        html_body = data.get("html")

        from .mailer import send_mail
        result = await asyncio.to_thread(send_mail, self.c, mail_from, to, subject,
                                         body, html_body)
        self.store.add_sent_mail(label, mail_from, to, subject,
                                 {"body": body, "html": html_body, "result": result})
        log.info("send from=%s to=%s ok=%s", mail_from, to, result.get("ok"))
        return web.json_response({"from": mail_from, "to": to, "label": label, "result": result},
                                 status=200 if result.get("ok") else 502)

    async def sent(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        since = _int(request.query.get("since"), 0)
        rows = self.store.sent_mail(token, since=since)
        cursor = rows[-1]["id"] if rows else since
        return web.json_response({"token": token, "cursor": cursor, "sent": rows})

    async def lookup(self, request: web.Request) -> web.Response:
        token = _require(request, "token")
        rec = self.store.lookup(token)
        if rec is None:
            raise web.HTTPNotFound(text="unknown token, no captured interactions")
        rec["endpoints"] = self._endpoints(token)
        return web.json_response(rec)

    async def tokens(self, request: web.Request) -> web.Response:
        return web.json_response({"tokens": self.store.list_tokens()})

    async def overview(self, request: web.Request) -> web.Response:
        limit = min(_int(request.query.get("limit"), 100), 500)
        offset = max(_int(request.query.get("offset"), 0), 0)
        q = (request.query.get("q") or "").strip() or None
        return web.json_response({"domain": self.c.domain,
                                  "tls": bool(self.c.http_tls()),
                                  "smtp_send": self.c.smtp_send,
                                  "total": self.store.token_count(q),
                                  "offset": offset, "limit": limit,
                                  "tokens": self.store.overview(limit, offset, q)})

    async def all_emails(self, request: web.Request) -> web.Response:
        limit = min(_int(request.query.get("limit"), 100), 500)
        before = request.query.get("before")
        rows = self.store.all_emails(float(before) if before and _isnum(before) else None, limit)
        nb = rows[-1]["ts"] if len(rows) == limit else None
        return web.json_response({"emails": rows, "next_before": nb, "count": len(rows)})

    async def all_xss(self, request: web.Request) -> web.Response:
        limit = min(_int(request.query.get("limit"), 100), 500)
        before = request.query.get("before")
        rows = self.store.all_xss(float(before) if before and _isnum(before) else None, limit)
        nb = rows[-1]["ts"] if len(rows) == limit else None
        return web.json_response({"reports": rows, "next_before": nb, "count": len(rows)})

    async def feed(self, request: web.Request) -> web.Response:
        limit = min(_int(request.query.get("limit"), 100), 500)
        before = request.query.get("before")
        before_f = float(before) if before and _isnum(before) else None
        kinds = [k for k in (request.query.get("kind") or "").split(",") if k] or None
        events = self.store.feed(before=before_f, limit=limit, kinds=kinds)
        next_before = events[-1]["ts"] if len(events) == limit else None
        return web.json_response({"events": events, "next_before": next_before, "count": len(events)})

    # --------------------------------------------------- crafted addresses
    async def craft(self, request: web.Request) -> web.Response:
        victim = _require(request, "victim").strip().lower().strip(".")
        if not victim or len(victim) > 100 or not re.fullmatch(r"[a-z0-9._-]+", victim):
            raise web.HTTPBadRequest(
                text="victim must be an address-safe string (a-z 0-9 . _ -), e.g. victim.tld, "
                     "internal-api, or 169.254.169.254")
        token = (request.query.get("token") or "").strip().lower() or None
        if token and not (is_token(token) or is_label(token)):
            raise web.HTTPBadRequest(text="token must be an ob-token or a DNS-safe label")
        return web.json_response({"victim": victim, "token": token,
                                  "addresses": craft_addresses(self.c.domain, victim, token)})

    # ------------------------------------------------------------- dashboard
    async def dashboard(self, request: web.Request) -> web.Response:
        return web.Response(text=self.dashboard_html, content_type="text/html",
                            headers={"Cache-Control": "no-store",
                                     "Content-Security-Policy": _DASH_CSP})

    async def login(self, request: web.Request) -> web.Response:
        error = ""
        if request.method == "POST":
            data = await request.post()
            key = str(data.get("key", ""))
            if self.c.api_key and hmac.compare_digest(key, self.c.api_key):
                resp = web.HTTPFound("/")
                resp.set_cookie(SESSION_COOKIE, _sign_session(self.c),
                                max_age=SESSION_TTL, httponly=True, samesite="Lax",
                                secure=bool(self.c.api_tls()), path="/")
                raise resp
            error = "Invalid key."
        return web.Response(text=_login_html(error), content_type="text/html",
                            headers={"Cache-Control": "no-store",
                                     "Content-Security-Policy": _DASH_CSP})

    async def logout(self, request: web.Request) -> web.Response:
        resp = web.HTTPFound("/login")
        resp.del_cookie(SESSION_COOKIE, path="/")
        raise resp

    # --------------------------------------------------------- DNS zone config
    def _zone_view(self) -> dict:
        ov = self.store.get_setting(ZONE_KEY) or {}
        defaults = {
            "domain": self.c.domain, "ipv4": self.c.ipv4, "ipv6": self.c.ipv6,
            "ttl": self.c.dns_ttl, "ns": self.c.nameservers,
            "soa_mail": self.c.soa_rname, "mx_host": self.c.domain, "mx_pref": 10,
        }
        eff = {
            "domain": self.c.domain,
            "ipv4": ov.get("ipv4") or self.c.ipv4,
            "ipv6": ov.get("ipv6") or self.c.ipv6,
            "ttl": int(ov.get("ttl") or self.c.dns_ttl),
            "ns": ov.get("ns") or self.c.nameservers,
            "soa_mail": ov.get("soa_mail") or self.c.soa_rname,
            "mx_host": ov.get("mx_host") or self.c.domain,
            "mx_pref": int(ov.get("mx_pref") or 10),
        }
        return {"effective": eff, "overrides": ov, "defaults": defaults,
                "record_types": list(RECORD_TYPES), "records": self.store.dns_records()}

    async def zone_get(self, request: web.Request) -> web.Response:
        return web.json_response(self._zone_view())

    async def zone_set(self, request: web.Request) -> web.Response:
        data = await _json(request)
        ov = self.store.get_setting(ZONE_KEY) or {}
        for k in ("ipv4", "ipv6", "soa_mail", "mx_host"):
            if k in data:
                v = str(data[k] or "").strip()
                if k in ("ipv4", "ipv6") and v:
                    try:
                        ipaddress.ip_address(v)
                    except ValueError:
                        raise web.HTTPBadRequest(text=f"{k} is not a valid IP")
                if v:
                    ov[k] = v          # empty value clears the override (falls back to env)
                else:
                    ov.pop(k, None)
        for k in ("ttl", "mx_pref"):
            if k in data:
                s = str(data[k]).strip()
                if s.isdigit():
                    ov[k] = int(s)
                else:
                    ov.pop(k, None)
        if "ns" in data:
            ns = data["ns"]
            if isinstance(ns, str):
                ns = [x.strip() for x in ns.replace(",", " ").split() if x.strip()]
            if ns:
                ov["ns"] = ns
            else:
                ov.pop("ns", None)
        self.store.set_setting(ZONE_KEY, ov)
        log.info("zone overrides updated: %s", ov)
        return web.json_response(self._zone_view())

    def _fqdn(self, name: str) -> str:
        n = str(name or "").strip().rstrip(".").lower()
        dom = self.c.domain
        if n in ("", "@"):
            return dom
        if n == dom or n.endswith("." + dom):
            return n
        return f"{n}.{dom}"

    async def zone_record_add(self, request: web.Request) -> web.Response:
        d = await _json(request)
        typ = str(d.get("type") or "").upper()
        if typ not in RECORD_TYPES:
            raise web.HTTPBadRequest(text=f"type must be one of {', '.join(RECORD_TYPES)}")
        value = str(d.get("value") or "").strip()
        if not value:
            raise web.HTTPBadRequest(text="value is required")
        if typ in ("A", "AAAA"):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise web.HTTPBadRequest(text=f"{typ} value must be an IP")
        prio = int(d["prio"]) if str(d.get("prio") or "").isdigit() else (10 if typ == "MX" else None)
        ttl = int(d["ttl"]) if str(d.get("ttl") or "").isdigit() else None
        name = self._fqdn(d.get("name", ""))
        rid = self.store.add_dns_record(name, typ, value, ttl, prio)
        log.info("dns record added #%s %s %s -> %s", rid, name, typ, value)
        return web.json_response({"id": rid, "name": name, "type": typ, "value": value,
                                  "ttl": ttl, "prio": prio})

    async def zone_record_del(self, request: web.Request) -> web.Response:
        rid = _int(request.match_info["id"], -1)
        if not self.store.delete_dns_record(rid):
            raise web.HTTPNotFound(text="no such record")
        return web.json_response({"ok": True, "deleted": rid})

    async def acme_present(self, request: web.Request) -> web.Response:
        data = await _json(request)
        name, value = data.get("name"), data.get("value")
        if not name or not value:
            raise web.HTTPBadRequest(text="need {name, value}")
        self.acme.present(name, value)
        log.info("acme present %s", name)
        return web.json_response({"ok": True})

    async def acme_cleanup(self, request: web.Request) -> web.Response:
        data = await _json(request)
        name = data.get("name")
        if not name:
            raise web.HTTPBadRequest(text="need {name}")
        self.acme.cleanup(name, data.get("value"))
        return web.json_response({"ok": True})

    async def healthz(self, request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "domain": self.c.domain})

    async def favicon(self, request: web.Request) -> web.Response:
        return web.Response(text=_FAVICON, content_type="image/svg+xml",
                            headers={"Cache-Control": "public, max-age=86400"})


# ------------------------------------------------------------------ helpers
def _int(val, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _isnum(val) -> bool:
    try:
        float(val)
        return True
    except (TypeError, ValueError):
        return False


def _require(request: web.Request, key: str) -> str:
    val = request.query.get(key)
    if not val:
        raise web.HTTPBadRequest(text=f"missing ?{key}=")
    return val


async def _json(request: web.Request) -> dict:
    if not request.can_read_body:
        return {}
    try:
        data = await request.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# --------------------------------------------------------------- session auth
def _sign_session(config: Config) -> str:
    exp = int(time.time()) + SESSION_TTL
    mac = hmac.new(config.api_key.encode(), str(exp).encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{mac}"


def _valid_session(config: Config, cookie: str | None) -> bool:
    if not cookie or "." not in cookie or not config.api_key:
        return False
    exp_s, _, mac = cookie.partition(".")
    try:
        if int(exp_s) < time.time():
            return False
    except ValueError:
        return False
    expected = hmac.new(config.api_key.encode(), exp_s.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)


def _authenticated(request: web.Request, config: Config) -> bool:
    auth = request.headers.get("Authorization", "")
    key = auth[7:] if auth.startswith("Bearer ") else ""
    if config.api_key and hmac.compare_digest(key, config.api_key):
        return True
    return _valid_session(config, request.cookies.get(SESSION_COOKIE))


@web.middleware
async def _auth_mw(request: web.Request, handler):
    config: Config = request.app[CONFIG_KEY]
    if request.path == "/healthz":
        return await handler(request)
    ip = _client_ip(request)
    if not config.ip_allowed(ip):
        log.warning("api denied ip=%s path=%s", ip, request.path)
        raise web.HTTPForbidden(text="ip not allowed")
    if request.path in AUTH_EXEMPT:
        return await handler(request)
    if _authenticated(request, config):
        return await handler(request)
    # not authenticated: send browsers to the login page, APIs get 401
    if request.path in HTML_PATHS:
        raise web.HTTPFound("/login")
    raise web.HTTPUnauthorized(text="bad or missing bearer key / session")


def make_api_app(config: Config, store: Store, acme: AcmeStore,
                 dashboard_html: str = "") -> web.Application:
    api = ControlAPI(config, store, acme, dashboard_html)
    app = web.Application(middlewares=[_auth_mw], client_max_size=config.max_upload_bytes + 65536)
    app[CONFIG_KEY] = config
    r = app.router
    r.add_post("/register", api.register)
    r.add_get("/poll", api.poll)
    r.add_get("/mail", api.mail_list)
    r.add_get("/mail/{id}", api.mail_get)
    r.add_get("/xss", api.xss_list)
    r.add_get("/xss/{id}", api.xss_get)
    r.add_get("/pages", api.pages_list)
    r.add_get("/pages/{id}", api.pages_get)
    r.add_post("/upload", api.upload)
    r.add_get("/files", api.files)
    r.add_get("/file", api.file_get)
    r.add_delete("/files", api.file_delete)
    r.add_post("/send", api.send)
    r.add_get("/sent", api.sent)
    r.add_get("/lookup", api.lookup)
    r.add_get("/craft", api.craft)
    r.add_get("/tokens", api.tokens)
    r.add_get("/overview", api.overview)
    r.add_get("/feed", api.feed)
    r.add_get("/all/emails", api.all_emails)
    r.add_get("/all/xss", api.all_xss)
    r.add_get("/zone", api.zone_get)
    r.add_post("/zone", api.zone_set)
    r.add_post("/zone/records", api.zone_record_add)
    r.add_delete("/zone/records/{id}", api.zone_record_del)
    r.add_post("/acme/present", api.acme_present)
    r.add_post("/acme/cleanup", api.acme_cleanup)
    r.add_get("/healthz", api.healthz)
    r.add_get("/favicon.ico", api.favicon)
    # dashboard (cookie login)
    r.add_get("/", api.dashboard)
    r.add_get("/dashboard", api.dashboard)
    r.add_get("/login", api.login)
    r.add_post("/login", api.login)
    r.add_get("/logout", api.logout)
    return app


# img-src permits remote schemes so the sandboxed email-HTML frame can load remote images
# ONLY when the operator opts in (the frame's own injected CSP blocks them by default and is
# the real gate; this is just the ceiling it intersects against). The dashboard's own
# document never inserts untrusted markup (inert-text rendering), so this widens nothing there.
_DASH_CSP = ("default-src 'none'; img-src 'self' data: https: http:; style-src 'unsafe-inline'; "
             "script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; "
             "frame-src 'self'; base-uri 'none'; frame-ancestors 'none'")


def _login_html(error: str = "") -> str:
    err = f'<p class="err">{htmllib.escape(error)}</p>' if error else ""
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>oobox login</title>
<style>
:root{{color-scheme:light dark}}
body{{font:14px system-ui,sans-serif;margin:0;display:grid;place-items:center;height:100vh;
background:#0f1115;color:#e6e6e6}}
form{{background:#181b22;padding:28px 26px;border-radius:12px;border:1px solid #2a2f3a;
width:320px;box-shadow:0 8px 30px rgba(0,0,0,.4)}}
h1{{font-size:18px;margin:0 0 4px}} .sub{{color:#8b93a7;font-size:12px;margin:0 0 18px}}
input{{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;
border:1px solid #333a48;background:#0f1115;color:#e6e6e6;font-size:14px}}
button{{width:100%;margin-top:12px;padding:10px;border:0;border-radius:8px;
background:#3b82f6;color:#fff;font-size:14px;font-weight:600;cursor:pointer}}
.err{{color:#f87171;font-size:12px;margin:10px 0 0}}
</style></head><body>
<form method=post action=/login>
<h1>oobox</h1><p class=sub>Sign in with the control-API key.</p>
<input type=password name=key placeholder="OOB_API_KEY" autofocus autocomplete=current-password>
<button type=submit>Sign in</button>{err}
</form></body></html>"""


def _ssl_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    if is_staging_cert(cert):
        log.warning("%s is a Let's Encrypt STAGING cert — no client will trust it. "
                    "Reissue against production: certbot delete --cert-name <domain>, "
                    "then re-run deploy/get-cert.sh WITHOUT --staging", cert)
    return ctx


async def start_api(config: Config, store: Store, acme: AcmeStore,
                    dashboard_html: str = "") -> "APIListener":
    app = make_api_app(config, store, acme, dashboard_html)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    tls = config.api_tls()
    ctx = _ssl_context(*tls) if tls else None
    site = web.TCPSite(runner, config.api_bind_host, config.api_port, ssl_context=ctx)
    await site.start()
    port = site._server.sockets[0].getsockname()[1] if site._server else config.api_port
    log.info("API   listening on %s:%s (%s)", config.api_bind_host, port,
             "TLS" if ctx else "plaintext — put behind TLS/mgmt iface")
    return APIListener(runner, port)


class APIListener:
    def __init__(self, runner, port):
        self.runner = runner
        self.port = port

    async def close(self):
        await self.runner.cleanup()
