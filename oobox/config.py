"""Runtime configuration for oobox.

Everything is driven by environment variables (see deploy/.env.example) with sane
defaults, so the server can run from a bare `python -m oobox serve` once OOBDOMAIN,
the public IP, and an API key are set. `Config.from_env()` is the single source of
truth; the CLI can override a few fields.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import os
import re
import secrets
from dataclasses import dataclass, field

log = logging.getLogger("oobox.config")


def _split(val: str | None) -> list[str]:
    if not val:
        return []
    return [p.strip() for p in val.replace(",", " ").split() if p.strip()]


def _bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _probe(path: str) -> str:
    """"ok" | "denied" | "missing". os.path.exists/os.access can't tell the last two
    apart: both return False when a parent dir is unreadable (certbot ships
    /etc/letsencrypt/live as 0700 root), so a real cert looks absent to a service
    user. Opening the file distinguishes EACCES from ENOENT."""
    try:
        with open(path, "rb"):
            return "ok"
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "denied"


def is_staging_cert(path: str) -> bool:
    """True if the chain was issued by Let's Encrypt *staging*. Staging roots are in no
    trust store, so every client rejects the cert — a silent footgun after running
    get-cert.sh --staging, and one certbot will not correct on its own (it reports
    "not yet due for renewal" and keeps the staging lineage). Looks for the marker LE
    puts in every staging CA name; the leaf carries it in its issuer, so no x509 parser
    is needed."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return False
    for block in re.findall(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                            blob, re.S):
        try:
            if b"(STAGING)" in base64.b64decode(block):
                return True
        except Exception:
            continue
    return False


def _whoami() -> str:
    uid = os.geteuid()
    try:
        import pwd
        return f"{pwd.getpwuid(uid).pw_name}, uid {uid}"
    except Exception:
        return f"uid {uid}"


@dataclass
class Config:
    # --- identity ---
    domain: str = "oob.example.com"          # OOBDOMAIN; zone we are authoritative for
    ipv4: str | None = None                  # public A record we answer with (this box)
    ipv6: str | None = None                  # public AAAA record (optional)
    ns_hosts: list[str] = field(default_factory=list)  # NS names (default: ns1.<domain>)
    soa_mail: str | None = None              # SOA RNAME (default: hostmaster.<domain>)

    # --- listeners ---
    dns_port: int = 53
    http_port: int = 80
    https_port: int = 443
    smtp_port: int = 25
    api_port: int = 8443
    bind_host: str = "0.0.0.0"
    api_bind_host: str = "0.0.0.0"           # bind the control API to a mgmt iface in prod

    # --- TLS (wildcard *.OOBDOMAIN + OOBDOMAIN) ---
    tls_cert: str | None = None              # PEM cert (fullchain); enables HTTPS if set
    tls_key: str | None = None               # PEM private key
    api_tls_cert: str | None = None          # falls back to tls_cert/tls_key if unset
    api_tls_key: str | None = None

    # --- auth ---
    api_key: str = ""                        # bearer key for the control API
    api_allow: list[str] = field(default_factory=list)  # IP/CIDR allowlist ([] = any)

    # --- storage / retention ---
    db_path: str = "oobox.db"
    files_dir: str = "hosted"
    ttl_days: int = 7                        # retention for interactions/emails/reports/files
    max_upload_bytes: int = 5 * 1024 * 1024  # per hosted file
    max_capture_bytes: int = 2 * 1024 * 1024  # per DNS/HTTP/XSS capture body stored
    max_screenshot_bytes: int = 6 * 1024 * 1024  # per blind-XSS screenshot dataURL POST

    # --- behaviour ---
    token_len: int = 8                       # random chars after the "ob" prefix
    smtp_send: bool = False                  # outbound send disabled by default
    smtp_relay: str | None = None            # smarthost "host[:port]"; else direct-to-MX
    smtp_relay_user: str | None = None
    smtp_relay_pass: str | None = None
    smtp_relay_starttls: bool = True
    resolver: str = "1.1.1.1"                # resolver used for outbound MX lookups
    dns_ttl: int = 60                        # TTL on answers we hand out

    # --- alerts (Telegram) ---
    tg_token: str | None = None              # bot token; alerts on when token+chat set
    tg_chat: str | None = None               # chat id (user, or negative for a group)
    tg_proxy: str | None = None              # optional http(s)://… or socks5://… proxy
    tg_api_base: str = "https://api.telegram.org"  # override for a proxying Bot API
    alert_window: float = 5.0                # coalesce a burst within this many seconds → 1 msg
    alert_kinds: list[str] = field(
        default_factory=lambda: ["dns", "http", "file", "mail", "xss"])

    # ----------------------------------------------------------------- helpers
    @property
    def bind_hosts(self) -> list[str]:
        """DNS/HTTP/SMTP bind address(es). OOB_BIND may list several (space/comma
        separated) so one box can serve DNS on two IPs — e.g. for a two-nameserver
        delegation where the registrar requires distinct NS IPs."""
        return _split(self.bind_host) or ["0.0.0.0"]

    @property
    def nameservers(self) -> list[str]:
        return self.ns_hosts or [f"ns1.{self.domain}", f"ns2.{self.domain}"]

    @property
    def soa_rname(self) -> str:
        return self.soa_mail or f"hostmaster.{self.domain}"

    def api_tls(self) -> tuple[str, str] | None:
        cert = self.api_tls_cert or self.tls_cert
        key = self.api_tls_key or self.tls_key
        return (cert, key) if cert and key else None

    def http_tls(self) -> tuple[str, str] | None:
        return (self.tls_cert, self.tls_key) if self.tls_cert and self.tls_key else None

    def ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        # Loopback is always allowed: it's where local processes reach the API (the certbot
        # DNS-01 hooks and renewals) and where SSH-tunnelled admin requests appear to come
        # from. The bearer key still gates it. So you never need 127.0.0.1 in OOB_API_ALLOW.
        if addr.is_loopback:
            return True
        if not self.api_allow:
            return True
        for entry in self.api_allow:
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif addr == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False

    def validate(self) -> list[str]:
        """Return a list of fatal problems for `serve` (empty == ok)."""
        problems = []
        if not self.domain or "." not in self.domain:
            problems.append("OOBDOMAIN must be a real domain, e.g. oob.example.com")
        if not self.ipv4 and not self.ipv6:
            problems.append("set OOB_IPV4 (and/or OOB_IPV6) to this box's public IP")
        if not self.api_key:
            problems.append("OOB_API_KEY is required (control API bearer key)")
        elif len(self.api_key) < 16:
            problems.append("OOB_API_KEY is too short (use >= 16 chars, e.g. `openssl rand -hex 24`)")
        return problems

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Config":
        e = env if env is not None else os.environ
        c = cls()
        c.domain = e.get("OOBDOMAIN", c.domain).rstrip(".").lower()
        c.ipv4 = e.get("OOB_IPV4") or None
        c.ipv6 = e.get("OOB_IPV6") or None
        c.ns_hosts = _split(e.get("OOB_NS"))
        c.soa_mail = e.get("OOB_SOA_MAIL") or None

        c.dns_port = int(e.get("OOB_DNS_PORT", c.dns_port))
        c.http_port = int(e.get("OOB_HTTP_PORT", c.http_port))
        c.https_port = int(e.get("OOB_HTTPS_PORT", c.https_port))
        c.smtp_port = int(e.get("OOB_SMTP_PORT", c.smtp_port))
        c.api_port = int(e.get("OOB_API_PORT", c.api_port))
        c.bind_host = e.get("OOB_BIND", c.bind_host)
        c.api_bind_host = e.get("OOB_API_BIND", c.api_bind_host)

        c.tls_cert = e.get("OOB_TLS_CERT") or None
        c.tls_key = e.get("OOB_TLS_KEY") or None
        # Convenience: if no cert is configured, pick up a Let's Encrypt wildcard that
        # get-cert.sh issued at the standard path — so HTTPS "just works" after issuance
        # with no env editing. Only used when both files exist and are readable.
        if not c.tls_cert and not c.tls_key and _bool(e.get("OOB_TLS_AUTODETECT"), True):
            le = f"/etc/letsencrypt/live/{c.domain}"
            cert, key = f"{le}/fullchain.pem", f"{le}/privkey.pem"
            states = (_probe(cert), _probe(key))
            if states == ("ok", "ok"):
                c.tls_cert, c.tls_key = cert, key
            elif "denied" in states:
                log.warning("a Let's Encrypt cert at %s is not readable by this user (%s) "
                            "— HTTPS stays off. Grant read, e.g.: "
                            "setfacl -R -m u:$USER:rX /etc/letsencrypt/live /etc/letsencrypt/archive && "
                            "setfacl -dR -m u:$USER:rX /etc/letsencrypt/live /etc/letsencrypt/archive",
                            le, _whoami())
        c.api_tls_cert = e.get("OOB_API_TLS_CERT") or None
        c.api_tls_key = e.get("OOB_API_TLS_KEY") or None

        c.api_key = e.get("OOB_API_KEY", "")
        c.api_allow = _split(e.get("OOB_API_ALLOW"))

        c.db_path = e.get("OOB_DB", c.db_path)
        c.files_dir = e.get("OOB_FILES_DIR", c.files_dir)
        c.ttl_days = int(e.get("OOB_TTL_DAYS", c.ttl_days))
        c.max_upload_bytes = int(e.get("OOB_MAX_UPLOAD", c.max_upload_bytes))
        c.max_capture_bytes = int(e.get("OOB_MAX_CAPTURE", c.max_capture_bytes))
        c.max_screenshot_bytes = int(e.get("OOB_MAX_SCREENSHOT", c.max_screenshot_bytes))

        c.token_len = int(e.get("OOB_TOKEN_LEN", c.token_len))
        c.smtp_send = _bool(e.get("OOB_SMTP_SEND"), c.smtp_send)
        c.smtp_relay = e.get("OOB_SMTP_RELAY") or None
        c.smtp_relay_user = e.get("OOB_SMTP_RELAY_USER") or None
        c.smtp_relay_pass = e.get("OOB_SMTP_RELAY_PASS") or None
        c.smtp_relay_starttls = _bool(e.get("OOB_SMTP_RELAY_STARTTLS"), c.smtp_relay_starttls)
        c.resolver = e.get("OOB_RESOLVER", c.resolver)
        c.dns_ttl = int(e.get("OOB_DNS_TTL", c.dns_ttl))

        c.tg_token = e.get("OOB_TG_TOKEN") or None
        c.tg_chat = e.get("OOB_TG_CHAT") or None
        c.tg_proxy = e.get("OOB_TG_PROXY") or None
        c.tg_api_base = e.get("OOB_TG_API_BASE", c.tg_api_base).rstrip("/")
        c.alert_window = float(e.get("OOB_ALERT_WINDOW", c.alert_window))
        kinds = _split(e.get("OOB_ALERT_KINDS"))
        if kinds:
            c.alert_kinds = kinds
        return c


def new_api_key() -> str:
    return secrets.token_hex(24)


def load_env_file(path: str) -> bool:
    """Load KEY=VALUE lines from a .env file into os.environ (without overriding vars
    already set in the real environment). Supports `export KEY=…`, `#` comments, and
    single/double-quoted values. Returns True if the file was read."""
    if not path or not os.path.exists(path):
        return False
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key, val = key.strip(), val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                    val = val[1:-1]
                if key and key not in os.environ:   # real env wins over the file
                    os.environ[key] = val
    except OSError:
        return False
    return True


def autoload_env(explicit: str | None = None) -> str | None:
    """Load the first existing env file and return its path (or None). Search order:
    an explicit path (or $OOB_ENV_FILE), then ./.env, then ./deploy/.env."""
    candidates = [explicit or os.environ.get("OOB_ENV_FILE"), ".env", "deploy/.env"]
    for c in candidates:
        if c and load_env_file(c):
            return c
    return None
