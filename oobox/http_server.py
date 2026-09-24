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

import logging
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

        # 3) hosted file
        if request.method in ("GET", "HEAD"):
            rec = store.get_file(token, path)
            if rec:
                store.add_interaction(token, "file", src_ip, f"{request.method} {path}",
                                      {**_http_detail(request, path),
                                       "served_bytes": rec["size"],
                                       "sha256": rec["sha256"]})
                if request.method == "HEAD":
                    return web.Response(status=200,
                                        content_type=rec["content_type"] or "application/octet-stream")
                return web.FileResponse(
                    rec["disk_path"],
                    headers={"Content-Type": rec["content_type"] or "application/octet-stream"},
                )

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
