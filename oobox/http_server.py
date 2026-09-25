"""HTTP/HTTPS listener: interaction catcher + token-scoped file host + XSS collector.

Everything is keyed off the request Host header's token label (``<token>.OOBDOMAIN``):

  * ``GET  <token>.OOBDOMAIN/<collector.js>``  -> the blind-XSS capture payload
  * ``POST <token>.OOBDOMAIN/<callback>``      -> store an XSS report under the token
  * ``GET  <token>.OOBDOMAIN/<uploaded path>`` -> serve the hosted payload, log a ``file`` hit
  * ``*    <token>.OOBDOMAIN/<anything else>``  -> log an ``http`` hit, return a benign 200

Non-token / apex requests get a benign 200 and are not logged (avoids scan noise), the
same discipline as the DNS listener.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import ssl

from aiohttp import web

from .config import Config, is_staging_cert
from .store import Store
from .tokens import label_from_host

log = logging.getLogger("oobox.http")

# Reserved paths on every token host (cannot be shadowed by an uploaded file).
COLLECTOR_JS_PATH = "/c.js"
CALLBACK_PATH = "/c"
H2C_PATH = "/h2c.js"          # vendored html2canvas, loaded by the collector for screenshots
CATCHALL_PATH = "/*"          # per-token programmable-response rule matching any path
MAX_DELAY_MS = 30000          # cap on a programmable response's artificial delay

_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


def _client_ip(request: web.Request) -> str:
    # This box is internet-facing (authoritative), so peername is the real client.
    # Honour X-Forwarded-For only if a trusted proxy set it (not enabled by default).
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return peer[0] if peer else (request.remote or "?")


def _headers_dict(request: web.Request) -> dict:
    # Preserve duplicates by joining; store as-is (client redacts before display).
    out: dict[str, str] = {}
    for k, v in request.headers.items():
        out[k] = f"{out[k]}, {v}" if k in out else v
    return out


async def _read_capped_body(request: web.Request, cap: int) -> tuple[str, int]:
    raw = await request.content.read(cap + 1)
    total = len(raw)
    truncated = total > cap
    body = raw[:cap]
    try:
        text = body.decode("utf-8", "replace")
    except Exception:
        text = repr(body)
    if truncated:
        text += "\n…[truncated]"
    return text, total


def make_app(config: Config, store: Store, collector_js: str,
             html2canvas_js: str = "") -> web.Application:
    app = web.Application(
        client_max_size=config.max_upload_bytes + config.max_screenshot_bytes + 65536)

    async def dispatch(request: web.Request) -> web.StreamResponse:
        host = request.headers.get("Host", "")
        token = label_from_host(host, config.domain)
        path = request.path
        src_ip = _client_ip(request)

        if request.method == "OPTIONS":
            return web.Response(status=204, headers=_CORS)

        if token is None:
            # apex / unknown host: benign, unlogged.
            return _benign()

        # 1) blind-XSS capture payload
        if request.method == "GET" and path == COLLECTOR_JS_PATH:
            store.add_interaction(token, "http", src_ip, f"GET {path} (collector)",
                                  _http_detail(request, path))
            return web.Response(text=collector_js,
                                content_type="application/javascript",
                                headers=_CORS)

        # 1b) vendored html2canvas (loaded by the collector for the screenshot)
        if request.method == "GET" and path == H2C_PATH:
            return web.Response(text=html2canvas_js,
                                content_type="application/javascript",
                                headers={**_CORS, "Cache-Control": "public, max-age=86400"})

        # 2) blind-XSS callback (POST body, or GET ?d= image-beacon fallback)
        if path == CALLBACK_PATH and (request.method == "POST" or "d" in request.query):
            return await _collect_xss(request, config, store, token, src_ip)

        # 3) hosted file OR programmable responder rule. Exact-path match first, then a
        #    per-token catch-all rule at "/*". A rule (redirect/status/headers/delay) fires
        #    for ANY method; static bytes are served for GET/HEAD as before. A plain bytes
        #    file hit with a non-GET/HEAD method and no rule falls through to the catcher.
        rec = store.get_file(token, path)
        if rec is None and path != CATCHALL_PATH:
            rec = store.get_file(token, CATCHALL_PATH)
        if rec is not None:
            has_bytes = bool(rec.get("size")) and rec.get("disk_path") \
                and os.path.exists(rec["disk_path"])
            if rec.get("redirect"):
                _log_file_hit(store, token, src_ip, request, path, rec)
                return await _serve_rule(rec)
            if request.method in ("GET", "HEAD") and has_bytes:
                _log_file_hit(store, token, src_ip, request, path, rec)
                return await _serve_file(request, rec)
            if _has_rule(rec):
                _log_file_hit(store, token, src_ip, request, path, rec)
                return await _serve_rule(rec)

        # 4) catcher — log the full request (incl. body, any method), return benign 200
        body, body_bytes = await _read_capped_body(request, config.max_capture_bytes)
        store.add_interaction(token, "http", src_ip,
                              f"{request.method} {path}",
                              _http_detail(request, path, body, body_bytes))
        return _benign()

    app.router.add_route("*", "/{tail:.*}", dispatch)
    return app


def _http_detail(request: web.Request, path: str,
                 body: str | None = None, body_bytes: int = 0) -> dict:
    detail = {
        "method": request.method,
        "path": path,
        # Parsed form for convenience; dict() collapses repeated keys, so also keep
        # the raw query string verbatim (nothing dropped, order/encoding preserved).
        "query": dict(request.query),
        "query_string": request.query_string,
        "host": request.headers.get("Host", ""),
        "headers": _headers_dict(request),
        "src_ip": _client_ip(request),
        "scheme": request.scheme,
    }
    # Include the raw request body when one was read (any method, capped at
    # max_capture_bytes). Empty bodies are omitted to keep GET hits tidy.
    if body:
        detail["body"] = body
        detail["body_bytes"] = body_bytes
    return detail


def _benign() -> web.Response:
    # Deliberately boring: proves reach without offering anything to a scanner.
    return web.Response(text="ok\n", content_type="text/plain")


# ------------------------------------------------------- programmable responses
# A hosted_files row may carry an operator-defined response: a status override, extra
# headers, a 3xx redirect (Location), and/or an artificial delay. This turns the file host
# into an SSRF/open-redirect/XXE staging responder (webhook.site-style) while every hit is
# still logged as a ``file`` interaction. FOR AUTHORIZED TESTING ONLY.

def _has_rule(rec: dict) -> bool:
    return bool(rec.get("redirect") or rec.get("status")
                or rec.get("resp_headers") or rec.get("delay_ms"))


def _resp_headers(rec: dict) -> dict:
    h = dict(_CORS)
    raw = rec.get("resp_headers")
    if raw:
        try:
            for k, v in (json.loads(raw) or {}).items():
                h[str(k)] = str(v)
        except Exception:
            pass
    return h


async def _apply_delay(rec: dict) -> None:
    d = rec.get("delay_ms")
    if d:
        try:
            await asyncio.sleep(min(int(d), MAX_DELAY_MS) / 1000.0)
        except Exception:
            pass


def _log_file_hit(store, token: str, src_ip: str, request: web.Request,
                  path: str, rec: dict) -> None:
    detail = {**_http_detail(request, path),
              "served_bytes": rec.get("size") or 0, "sha256": rec.get("sha256")}
    rule = {k: rec.get(k) for k in ("status", "redirect", "delay_ms") if rec.get(k)}
    if rec.get("resp_headers"):
        rule["headers"] = True
    if rule:
        detail["rule"] = rule
    store.add_interaction(token, "file", src_ip, f"{request.method} {path}", detail)


async def _serve_rule(rec: dict) -> web.Response:
    await _apply_delay(rec)
    headers = _resp_headers(rec)
    if rec.get("redirect"):
        headers["Location"] = str(rec["redirect"])
        return web.Response(status=int(rec["status"]) if rec.get("status") else 302,
                            headers=headers, text="")
    return web.Response(status=int(rec["status"]) if rec.get("status") else 200,
                        headers=headers, text="")


async def _serve_file(request: web.Request, rec: dict) -> web.StreamResponse:
    await _apply_delay(rec)
    headers = _resp_headers(rec)
    headers.setdefault("Content-Type", rec.get("content_type") or "application/octet-stream")
    status = int(rec["status"]) if rec.get("status") else 200
    if request.method == "HEAD":
        return web.Response(status=status, headers=headers)
    return web.FileResponse(rec["disk_path"], status=status, headers=headers)


async def _collect_xss(request, config: Config, store: Store, token: str, src_ip: str):
    import json
    if request.method == "GET":
        body = request.query.get("d", "")
    else:
        # allow room for a screenshot dataURL, which arrives on the attach POST
        body, _ = await _read_capped_body(request, config.max_screenshot_bytes)
    try:
        data = json.loads(body) if body.strip() else {}
        if not isinstance(data, dict):
            data = {"_raw": data}
    except json.JSONDecodeError:
        data = {"_raw": body}

    # Screenshot attach: the collector sends the core report first, then follows up with
    # {"attach": <id>, "screenshot": "data:image/..."} once html2canvas has rendered.
    attach = data.get("attach")
    if attach is not None and "screenshot" in data:
        ok = store.patch_xss(token, int(attach) if str(attach).isdigit() else -1,
                             {"screenshot": data["screenshot"]})
        log.info("xss screenshot token=%s attach=%s ok=%s", token, attach, ok)
        return web.json_response({"ok": ok, "attached": attach}, headers=_CORS)

    # Spidered/additional page: {"page": url, status, title, dom, depth, parent}.
    if data.get("page"):
        parent = data.get("parent")
        pid = store.add_xss_page(
            token, src_ip, str(data.get("page")),
            int(data.get("status") or 0),
            int(data.get("depth") or 0),
            int(parent) if str(parent).isdigit() else None,
            {"title": data.get("title"), "dom": data.get("dom")})
        return web.json_response({"ok": True, "page_id": pid}, headers=_CORS)

    origin = data.get("uri") or data.get("origin") or data.get("location") or ""
    tag = data.get("tag") or (data.get("custom") or {}).get("tag")
    data.setdefault("headers", _headers_dict(request))
    data.setdefault("src_ip", src_ip)
    rid = store.add_xss(token, src_ip, str(origin), data, tag=str(tag) if tag else None)
    log.info("xss report token=%s id=%s tag=%s origin=%s screenshot=%s",
             token, rid, tag, origin, "screenshot" in data)
    return web.json_response({"ok": True, "id": rid}, headers=_CORS)


def _ssl_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    if is_staging_cert(cert):
        log.warning("%s is a Let's Encrypt STAGING cert — no client will trust it. "
                    "Reissue against production: certbot delete --cert-name <domain>, "
                    "then re-run deploy/get-cert.sh WITHOUT --staging", cert)
    return ctx


async def start_http(config: Config, store: Store, collector_js: str,
                     html2canvas_js: str = "") -> "HTTPListener":
    app = make_app(config, store, collector_js, html2canvas_js)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    sites = []
    hosts = config.bind_hosts

    plain = None
    for host in hosts:
        s = web.TCPSite(runner, host, config.http_port)
        await s.start()
        sites.append(s)
        plain = plain or s
    http_port = plain._server.sockets[0].getsockname()[1] if plain and plain._server else config.http_port
    log.info("HTTP  listening on %s:%s", ",".join(hosts), http_port)

    https_port = None
    tls = config.http_tls()
    if tls:
        ctx = _ssl_context(*tls)
        secure = None
        for host in hosts:
            s = web.TCPSite(runner, host, config.https_port, ssl_context=ctx)
            await s.start()
            sites.append(s)
            secure = secure or s
        https_port = secure._server.sockets[0].getsockname()[1] if secure and secure._server else config.https_port
        log.info("HTTPS listening on %s:%s (TLS)", ",".join(hosts), https_port)
    else:
        log.warning("HTTPS disabled (no OOB_TLS_CERT/OOB_TLS_KEY) — catcher is HTTP-only")

    return HTTPListener(runner, sites, http_port, https_port)


class HTTPListener:
    def __init__(self, runner, sites, http_port, https_port):
        self.runner = runner
        self.sites = sites
        self.http_port = http_port
        self.https_port = https_port

    async def close(self):
        await self.runner.cleanup()
