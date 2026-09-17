"""SQLite-backed store for tokens and captured interactions.

One connection guarded by a lock. Every method is synchronous and fast (single-row
inserts / small selects) so listener callbacks and API handlers can call it directly
on the event loop. The single per-interaction *token* ties every channel together:
DNS/HTTP/file hits (``interactions``), received mail (``emails``), and blind-XSS
callbacks (``xss_reports``) are all keyed by it, so one ``lookup`` resolves a callback
back to the exact planting days later.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT                 -- JSON blob
);
CREATE TABLE IF NOT EXISTS dns_records (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts    REAL NOT NULL,
    name  TEXT NOT NULL,        -- FQDN under the zone (or the apex)
    type  TEXT NOT NULL,        -- A|AAAA|TXT|CNAME|MX|CAA
    value TEXT NOT NULL,
    ttl   INTEGER,
    prio  INTEGER               -- MX preference (else NULL)
);
CREATE INDEX IF NOT EXISTS idx_dns_name ON dns_records(name, type);
CREATE TABLE IF NOT EXISTS tokens (
    token      TEXT PRIMARY KEY,
    created_ts REAL NOT NULL,
    note       TEXT,
    meta       TEXT             -- JSON: client-supplied injection-point ledger row
);
CREATE TABLE IF NOT EXISTS interactions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    token    TEXT NOT NULL,
    kind     TEXT NOT NULL,      -- dns | http | file
    ts       REAL NOT NULL,
    src_ip   TEXT,
    summary  TEXT,               -- one-line human summary (qtype qname / METHOD path)
    detail   TEXT                -- JSON: full request / query record
);
CREATE INDEX IF NOT EXISTS idx_inter_token ON interactions(token, id);
CREATE TABLE IF NOT EXISTS emails (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    token    TEXT NOT NULL,
    ts       REAL NOT NULL,
    src_ip   TEXT,
    mail_from TEXT,
    rcpt_to  TEXT,               -- JSON list of envelope recipients
    subject  TEXT,
    detail   TEXT                -- JSON: headers, text/html bodies, links, attachments meta
);
CREATE INDEX IF NOT EXISTS idx_email_token ON emails(token, id);
CREATE TABLE IF NOT EXISTS xss_reports (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    token    TEXT NOT NULL,
    ts       REAL NOT NULL,
    src_ip   TEXT,
    origin   TEXT,               -- URL where the payload fired
    tag      TEXT,               -- custom label from the payload (?tag=…) — which sink fired
    detail   TEXT                -- JSON: dom, cookies, storage, ua, referer, screenshot, custom
);
CREATE INDEX IF NOT EXISTS idx_xss_token ON xss_reports(token, id);
CREATE TABLE IF NOT EXISTS xss_pages (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    token    TEXT NOT NULL,
    ts       REAL NOT NULL,
    src_ip   TEXT,
    parent   INTEGER,            -- originating xss_reports.id, if the collector sent one
    url      TEXT,               -- same-origin URL fetched through the victim
    status   INTEGER,            -- HTTP status the victim's browser saw
    depth    INTEGER,            -- spider depth (0 = explicit page, 1+ = discovered)
    detail   TEXT                -- JSON: title, dom (capped)
);
CREATE INDEX IF NOT EXISTS idx_xpage_token ON xss_pages(token, id);
CREATE TABLE IF NOT EXISTS sent_mail (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    token    TEXT NOT NULL,
    ts       REAL NOT NULL,
    mail_from TEXT,
    mail_to  TEXT,
    subject  TEXT,
    detail   TEXT                -- JSON: body, html, delivery result
);
CREATE INDEX IF NOT EXISTS idx_sent_token ON sent_mail(token, id);
CREATE TABLE IF NOT EXISTS hosted_files (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    token    TEXT NOT NULL,
    path     TEXT NOT NULL,      -- request path under <token>.OOBDOMAIN/
    ts       REAL NOT NULL,
    content_type TEXT,
    size     INTEGER,
    sha256   TEXT,
    disk_path TEXT NOT NULL,     -- where the bytes live on disk
    UNIQUE(token, path)
);
"""


def now() -> float:
    return time.time()


class Store:
    def __init__(self, path: str):
        self.path = path
        # optional callback fired after each incoming capture: on_event(kind, token, summary).
        # Set by the server (→ Alerter.notify). Never raises into the caller.
        self.on_event = None
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()
        self._migrate()

    def _migrate(self) -> None:
        # add columns introduced after a DB was first created (engagement DBs are long-lived)
        with self._lock:
            cols = [r[1] for r in self._db.execute("PRAGMA table_info(xss_reports)").fetchall()]
            if "tag" not in cols:
                self._db.execute("ALTER TABLE xss_reports ADD COLUMN tag TEXT")
                self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------ global lists (all tokens)
    def all_emails(self, before: float | None = None, limit: int = 100) -> list[dict]:
        before = before if before else (now() + 1)
        with self._lock:
            rows = self._db.execute(
                "SELECT id, token, ts, src_ip, mail_from, subject FROM emails "
                "WHERE ts<? ORDER BY ts DESC LIMIT ?", (before, limit)).fetchall()
        return [dict(r) for r in rows]

    def all_xss(self, before: float | None = None, limit: int = 100) -> list[dict]:
        before = before if before else (now() + 1)
        with self._lock:
            rows = self._db.execute(
                "SELECT id, token, ts, src_ip, origin, tag FROM xss_reports "
                "WHERE ts<? ORDER BY ts DESC LIMIT ?", (before, limit)).fetchall()
        return [dict(r) for r in rows]

    # ----------------------------------------------------- global feed
    def feed(self, before: float | None = None, limit: int = 100,
             kinds: list[str] | None = None) -> list[dict]:
        """A merged, time-ordered activity feed across ALL tokens and channels. Fetches
        the most recent `limit` from each source with ts < `before`, merges, and returns
        the newest `limit`. Paginate older by passing `before` = the last row's ts."""
        before = before if before else (now() + 1)
        want = set(kinds) if kinds else None
        events: list[dict] = []

        def src(sql, args, build):
            with self._lock:
                rows = self._db.execute(sql, args).fetchall()
            for r in rows:
                events.append(build(r))

        # interactions (dns/http/file) — filter kinds in SQL when possible
        if want is None or want & {"dns", "http", "file"}:
            ik = list((want & {"dns", "http", "file"}) if want else {"dns", "http", "file"})
            q = ("SELECT id, ts, token, kind, summary, src_ip FROM interactions "
                 "WHERE ts<? AND kind IN (%s) ORDER BY ts DESC LIMIT ?" % ",".join("?" * len(ik)))
            src(q, [before, *ik, limit],
                lambda r: {"ts": r["ts"], "token": r["token"], "kind": r["kind"],
                           "summary": r["summary"], "src_ip": r["src_ip"],
                           "ref": {"table": "interactions", "id": r["id"]}})
        if want is None or "mail" in want:
            src("SELECT id, ts, token, mail_from, subject, src_ip FROM emails WHERE ts<? "
                "ORDER BY ts DESC LIMIT ?", [before, limit],
                lambda r: {"ts": r["ts"], "token": r["token"], "kind": "mail",
                           "summary": f"from {r['mail_from']}: {r['subject'] or '(no subject)'}",
                           "src_ip": r["src_ip"], "ref": {"table": "emails", "id": r["id"]}})
        if want is None or "sent" in want:
            src("SELECT id, ts, token, mail_to, subject FROM sent_mail WHERE ts<? "
                "ORDER BY ts DESC LIMIT ?", [before, limit],
                lambda r: {"ts": r["ts"], "token": r["token"], "kind": "sent",
                           "summary": f"to {r['mail_to']}: {r['subject'] or '(no subject)'}",
                           "src_ip": None, "ref": {"table": "sent_mail", "id": r["id"]}})
        if want is None or "xss" in want:
            src("SELECT id, ts, token, origin, tag, src_ip FROM xss_reports WHERE ts<? "
                "ORDER BY ts DESC LIMIT ?", [before, limit],
                lambda r: {"ts": r["ts"], "token": r["token"], "kind": "xss",
                           "summary": (f"[{r['tag']}] " if r["tag"] else "")
                                      + (r["origin"] or "(blind-xss callback)"),
                           "src_ip": r["src_ip"], "ref": {"table": "xss_reports", "id": r["id"]}})
        if want is None or "page" in want:
            src("SELECT id, ts, token, url, depth, src_ip FROM xss_pages WHERE ts<? "
                "ORDER BY ts DESC LIMIT ?", [before, limit],
                lambda r: {"ts": r["ts"], "token": r["token"], "kind": "page",
                           "summary": f"[d{r['depth']}] {r['url']}", "src_ip": r["src_ip"],
                           "ref": {"table": "xss_pages", "id": r["id"]}})

        events.sort(key=lambda e: e["ts"], reverse=True)
        return events[:limit]

    # --------------------------------------------------------- settings
    def get_setting(self, key: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if not row or not row["value"]:
            return None
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return None

    def set_setting(self, key: str, value: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO settings(key, value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )
            self._db.commit()

    # ------------------------------------------------------- dns records
    def add_dns_record(self, name: str, type_: str, value: str,
                       ttl: int | None, prio: int | None) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO dns_records(ts, name, type, value, ttl, prio) VALUES(?,?,?,?,?,?)",
                (now(), name, type_, value, ttl, prio),
            )
            self._db.commit()
            return cur.lastrowid

    def dns_records(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, ts, name, type, value, ttl, prio FROM dns_records ORDER BY name, type"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_dns_record(self, rec_id: int) -> bool:
        with self._lock:
            cur = self._db.execute("DELETE FROM dns_records WHERE id=?", (rec_id,))
            self._db.commit()
            return cur.rowcount > 0

    def _fire(self, kind: str, token: str, summary: str) -> None:
        cb = self.on_event
        if cb is None:
            return
        try:
            cb(kind, token, summary)
        except Exception:  # an alert hook must never break capture
            pass

    # ------------------------------------------------------------- tokens
    def create_token(self, token: str, note: str | None = None,
                     meta: dict | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO tokens(token, created_ts, note, meta) VALUES(?,?,?,?)",
                (token, now(), note, json.dumps(meta) if meta else None),
            )
            self._db.commit()

    def token_exists(self, token: str) -> bool:
        with self._lock:
            cur = self._db.execute("SELECT 1 FROM tokens WHERE token=?", (token,))
            return cur.fetchone() is not None

    def get_token(self, token: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["meta"] = json.loads(d["meta"]) if d["meta"] else None
        return d

    def list_tokens(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT token, created_ts, note FROM tokens ORDER BY created_ts DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def token_count(self, q: str | None = None) -> int:
        where, args = self._token_where(q)
        with self._lock:
            return self._db.execute(
                "SELECT COUNT(*) FROM tokens" + where, args).fetchone()[0]

    @staticmethod
    def _token_where(q: str | None):
        if q:
            like = f"%{q}%"
            return " WHERE token LIKE ? OR IFNULL(note,'') LIKE ?", [like, like]
        return "", []

    def overview(self, limit: int = 100, offset: int = 0, q: str | None = None) -> list[dict]:
        """A page of tokens (optionally matching search `q` in token/note), each with
        per-channel counts. Counts are computed only for the page's tokens (WHERE token
        IN …), so this stays cheap no matter how many tokens exist."""
        where, wargs = self._token_where(q)
        with self._lock:
            tokens = self._db.execute(
                "SELECT token, created_ts, note FROM tokens" + where +
                " ORDER BY created_ts DESC LIMIT ? OFFSET ?", (*wargs, limit, offset)
            ).fetchall()
            names = [t["token"] for t in tokens]
            counts: dict[str, dict[str, int]] = {n: {} for n in names}
            if names:
                ph = ",".join("?" * len(names))
                for r in self._db.execute(
                        f"SELECT token, kind, COUNT(*) FROM interactions WHERE token IN ({ph}) "
                        "GROUP BY token, kind", names):
                    counts[r[0]][r[1]] = r[2]
                for tbl, key in (("emails", "mail"), ("sent_mail", "sent"),
                                 ("xss_reports", "xss"), ("xss_pages", "pages"),
                                 ("hosted_files", "hosted_files")):
                    for r in self._db.execute(
                            f"SELECT token, COUNT(*) FROM {tbl} WHERE token IN ({ph}) "
                            "GROUP BY token", names):
                        counts[r[0]][key] = r[1]
        out = []
        for t in tokens:
            i = counts.get(t["token"], {})
            c = {"dns": i.get("dns", 0), "http": i.get("http", 0), "file": i.get("file", 0),
                 "mail": i.get("mail", 0), "sent": i.get("sent", 0), "xss": i.get("xss", 0),
                 "pages": i.get("pages", 0), "hosted_files": i.get("hosted_files", 0)}
            c["total"] = sum(c.values())
            out.append({"token": t["token"], "created_ts": t["created_ts"],
                        "note": t["note"], "counts": c})
        return out

    # ------------------------------------------------------- interactions
    def add_interaction(self, token: str, kind: str, src_ip: str | None,
                        summary: str, detail: dict) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO interactions(token, kind, ts, src_ip, summary, detail) "
                "VALUES(?,?,?,?,?,?)",
                (token, kind, now(), src_ip, summary, json.dumps(detail)),
            )
            self._db.commit()
            rid = cur.lastrowid
        self._fire(kind, token, summary)
        return rid

    def interactions(self, token: str, since: int = 0, kinds: list[str] | None = None,
                    limit: int = 500, before: int | None = None) -> list[dict]:
        # before-mode → newest-first page (id<before, DESC); else since-mode (id>since, ASC)
        args: list[Any] = [token, before if before is not None else since]
        q = ("SELECT * FROM interactions WHERE token=? AND id<?" if before is not None
             else "SELECT * FROM interactions WHERE token=? AND id>?")
        if kinds:
            q += " AND kind IN (%s)" % ",".join("?" * len(kinds))
            args += kinds
        q += " ORDER BY id DESC LIMIT ?" if before is not None else " ORDER BY id ASC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [self._row_json(r, "detail") for r in rows]

    # ------------------------------------------------------------- emails
    def add_email(self, token: str, src_ip: str | None, mail_from: str,
                 rcpt_to: list[str], subject: str, detail: dict) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO emails(token, ts, src_ip, mail_from, rcpt_to, subject, detail) "
                "VALUES(?,?,?,?,?,?,?)",
                (token, now(), src_ip, mail_from, json.dumps(rcpt_to), subject,
                 json.dumps(detail)),
            )
            self._db.commit()
            rid = cur.lastrowid
        self._fire("mail", token, f"from {mail_from}: {subject or '(no subject)'}")
        return rid

    def emails(self, token: str, since: int = 0, limit: int = 200,
               before: int | None = None) -> list[dict]:
        cols = "SELECT id, token, ts, src_ip, mail_from, rcpt_to, subject FROM emails WHERE token=? "
        with self._lock:
            if before is not None:
                rows = self._db.execute(
                    cols + "AND id<? ORDER BY id DESC LIMIT ?", (token, before, limit)).fetchall()
            else:
                rows = self._db.execute(
                    cols + "AND id>? ORDER BY id ASC LIMIT ?", (token, since, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["rcpt_to"] = json.loads(d["rcpt_to"]) if d["rcpt_to"] else []
            out.append(d)
        return out

    def email(self, token: str, email_id: int) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM emails WHERE token=? AND id=?", (token, email_id)
            ).fetchone()
        if not row:
            return None
        d = self._row_json(row, "detail")
        d["rcpt_to"] = json.loads(d["rcpt_to"]) if d["rcpt_to"] else []
        return d

    # ---------------------------------------------------------- sent mail
    def add_sent_mail(self, token: str, mail_from: str, mail_to: str, subject: str,
                      detail: dict) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO sent_mail(token, ts, mail_from, mail_to, subject, detail) "
                "VALUES(?,?,?,?,?,?)",
                (token, now(), mail_from, mail_to, subject, json.dumps(detail)),
            )
            self._db.commit()
            return cur.lastrowid

    def sent_mail(self, token: str, since: int = 0, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, token, ts, mail_from, mail_to, subject, detail FROM sent_mail "
                "WHERE token=? AND id>? ORDER BY id ASC LIMIT ?",
                (token, since, limit),
            ).fetchall()
        return [self._row_json(r, "detail") for r in rows]

    # -------------------------------------------------------- xss reports
    def add_xss(self, token: str, src_ip: str | None, origin: str, detail: dict,
                tag: str | None = None) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO xss_reports(token, ts, src_ip, origin, tag, detail) "
                "VALUES(?,?,?,?,?,?)",
                (token, now(), src_ip, origin, tag, json.dumps(detail)),
            )
            self._db.commit()
            rid = cur.lastrowid
        self._fire("xss", token, (f"[{tag}] " if tag else "") + (origin or "(blind-xss callback)"))
        return rid

    def xss_reports(self, token: str, since: int = 0, limit: int = 200,
                    before: int | None = None) -> list[dict]:
        cols = "SELECT id, token, ts, src_ip, origin, tag FROM xss_reports WHERE token=? "
        with self._lock:
            if before is not None:
                rows = self._db.execute(
                    cols + "AND id<? ORDER BY id DESC LIMIT ?", (token, before, limit)).fetchall()
            else:
                rows = self._db.execute(
                    cols + "AND id>? ORDER BY id ASC LIMIT ?", (token, since, limit)).fetchall()
        return [dict(r) for r in rows]

    def xss_report(self, token: str, report_id: int) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM xss_reports WHERE token=? AND id=?", (token, report_id)
            ).fetchone()
        return self._row_json(row, "detail") if row else None

    def patch_xss(self, token: str, report_id: int, extra: dict) -> bool:
        """Merge `extra` into an existing report's detail (used to attach the screenshot
        that arrives a moment after the core capture). Returns False if no such report."""
        with self._lock:
            row = self._db.execute(
                "SELECT detail FROM xss_reports WHERE token=? AND id=?", (token, report_id)
            ).fetchone()
            if row is None:
                return False
            try:
                detail = json.loads(row["detail"]) if row["detail"] else {}
            except (TypeError, json.JSONDecodeError):
                detail = {}
            detail.update(extra)
            self._db.execute(
                "UPDATE xss_reports SET detail=? WHERE token=? AND id=?",
                (json.dumps(detail), token, report_id),
            )
            self._db.commit()
            return True

    # -------------------------------------------------------- xss pages
    def add_xss_page(self, token: str, src_ip: str | None, url: str, status: int,
                     depth: int, parent: int | None, detail: dict) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO xss_pages(token, ts, src_ip, parent, url, status, depth, detail) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (token, now(), src_ip, parent, url, status, depth, json.dumps(detail)),
            )
            self._db.commit()
            rid = cur.lastrowid
        self._fire("xss", token, f"spidered page {url}")
        return rid

    def xss_pages(self, token: str, since: int = 0, limit: int = 500,
                  before: int | None = None) -> list[dict]:
        cols = "SELECT id, token, ts, src_ip, parent, url, status, depth FROM xss_pages WHERE token=? "
        with self._lock:
            if before is not None:
                rows = self._db.execute(
                    cols + "AND id<? ORDER BY id DESC LIMIT ?", (token, before, limit)).fetchall()
            else:
                rows = self._db.execute(
                    cols + "AND id>? ORDER BY id ASC LIMIT ?", (token, since, limit)).fetchall()
        return [dict(r) for r in rows]

    def xss_page(self, token: str, page_id: int) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM xss_pages WHERE token=? AND id=?", (token, page_id)
            ).fetchone()
        return self._row_json(row, "detail") if row else None

    # ------------------------------------------------------- hosted files
    def add_file(self, token: str, path: str, content_type: str, size: int,
                sha256: str, disk_path: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO hosted_files(token, path, ts, content_type, size, sha256, disk_path) "
                "VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(token, path) DO UPDATE SET "
                "ts=excluded.ts, content_type=excluded.content_type, size=excluded.size, "
                "sha256=excluded.sha256, disk_path=excluded.disk_path",
                (token, path, now(), content_type, size, sha256, disk_path),
            )
            self._db.commit()

    def get_file(self, token: str, path: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM hosted_files WHERE token=? AND path=?", (token, path)
            ).fetchone()
        return dict(row) if row else None

    def files(self, token: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT token, path, ts, content_type, size, sha256 FROM hosted_files "
                "WHERE token=? ORDER BY ts DESC", (token,)
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_file(self, token: str, path: str) -> dict | None:
        """Remove a single hosted file's row; returns the deleted row (with disk_path
        so the caller can unlink the bytes) or None if there was no such file."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM hosted_files WHERE token=? AND path=?", (token, path)
            ).fetchone()
            if row is None:
                return None
            self._db.execute(
                "DELETE FROM hosted_files WHERE token=? AND path=?", (token, path))
            self._db.commit()
        return dict(row)

    # -------------------------------------------------------- correlation
    def lookup(self, token: str) -> dict | None:
        tok = self.get_token(token)
        if tok is None:
            # Unknown token can still have caught traffic (catcher is public); report anyway.
            if not self._has_any(token):
                return None
            tok = {"token": token, "created_ts": None, "note": None, "meta": None}
        with self._lock:
            def counts(sql):
                return {r[0]: r[1] for r in self._db.execute(sql, (token,)).fetchall()}
            inter = counts(
                "SELECT kind, COUNT(*) FROM interactions WHERE token=? GROUP BY kind")
            n_mail = self._db.execute(
                "SELECT COUNT(*) FROM emails WHERE token=?", (token,)).fetchone()[0]
            n_sent = self._db.execute(
                "SELECT COUNT(*) FROM sent_mail WHERE token=?", (token,)).fetchone()[0]
            n_xss = self._db.execute(
                "SELECT COUNT(*) FROM xss_reports WHERE token=?", (token,)).fetchone()[0]
            n_pages = self._db.execute(
                "SELECT COUNT(*) FROM xss_pages WHERE token=?", (token,)).fetchone()[0]
            n_files = self._db.execute(
                "SELECT COUNT(*) FROM hosted_files WHERE token=?", (token,)).fetchone()[0]
        return {
            "token": token,
            "created_ts": tok["created_ts"],
            "note": tok["note"],
            "meta": tok["meta"],
            "counts": {
                "dns": inter.get("dns", 0),
                "http": inter.get("http", 0),
                "file": inter.get("file", 0),
                "mail": n_mail,
                "sent": n_sent,
                "xss": n_xss,
                "pages": n_pages,
                "hosted_files": n_files,
            },
        }

    def _has_any(self, token: str) -> bool:
        with self._lock:
            for tbl in ("interactions", "emails", "sent_mail", "xss_reports", "xss_pages",
                        "hosted_files"):
                if self._db.execute(
                    f"SELECT 1 FROM {tbl} WHERE token=? LIMIT 1", (token,)
                ).fetchone():
                    return True
        return False

    # ------------------------------------------------------------- sweeper
    def sweep(self, ttl_days: int) -> dict:
        """Delete captures older than ttl_days. Tokens themselves are kept (cheap) so
        `lookup` still resolves the injection point after captures expire."""
        if ttl_days <= 0:
            return {}
        cutoff = now() - ttl_days * 86400
        removed = {}
        with self._lock:
            for tbl in ("interactions", "emails", "sent_mail", "xss_reports", "xss_pages"):
                cur = self._db.execute(f"DELETE FROM {tbl} WHERE ts<?", (cutoff,))
                removed[tbl] = cur.rowcount
            # hosted_files rows are removed here; the on-disk bytes are swept by the caller.
            self._db.commit()
        return removed

    def expired_files(self, ttl_days: int) -> list[dict]:
        if ttl_days <= 0:
            return []
        cutoff = now() - ttl_days * 86400
        with self._lock:
            rows = self._db.execute(
                "SELECT id, disk_path FROM hosted_files WHERE ts<?", (cutoff,)
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_files(self, ids: list[int]) -> None:
        if not ids:
            return
        with self._lock:
            self._db.executemany("DELETE FROM hosted_files WHERE id=?", [(i,) for i in ids])
            self._db.commit()

    # --------------------------------------------------------------- utils
    @staticmethod
    def _row_json(row: sqlite3.Row, field: str) -> dict:
        d = dict(row)
        if d.get(field):
            try:
                d[field] = json.loads(d[field])
            except (TypeError, json.JSONDecodeError):
                pass
        return d
