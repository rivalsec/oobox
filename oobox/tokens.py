"""Token minting and label→token resolution.

A token is a short random label (default ``ob`` + 8 base36 chars, e.g. ``ob7f3k9a2x``).
That single label is, simultaneously:

  * the subdomain           <token>.OOBDOMAIN         (DNS + HTTP catcher + file host)
  * the catch-all address   <token>@OOBDOMAIN         (and <anything>@<token>.OOBDOMAIN)
  * the file namespace       <token>.OOBDOMAIN/<path>
  * the blind-XSS report id  (carried by the callback)

Any hostname / recipient the target uses is mapped back to its token by
``token_from_host`` / ``token_from_rcpt``, so every channel correlates to one planting.
"""
from __future__ import annotations

import re
import secrets

PREFIX = "ob"
_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
DEFAULT_LEN = 8               # random chars after the prefix (total label = len(PREFIX)+N)
MIN_LEN = 4                   # recognition window: any token minted with 4..32 random
MAX_LEN = 32                  # chars is recognised, so mixed / reconfigured lengths still resolve
TOKEN_RE = re.compile(rf"{PREFIX}[0-9a-z]{{{MIN_LEN},{MAX_LEN}}}")


def clamp_len(n: int) -> int:
    return max(MIN_LEN, min(MAX_LEN, int(n)))


def mint(exists=None, length: int = DEFAULT_LEN) -> str:
    """Mint a fresh token: PREFIX + `length` base36 chars (clamped to MIN_LEN..MAX_LEN).
    `exists(token)->bool` (optional) rejects collisions."""
    n = clamp_len(length)
    while True:
        tok = PREFIX + "".join(secrets.choice(_ALPHABET) for _ in range(n))
        if exists is None or not exists(tok):
            return tok


LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def is_token(label: str) -> bool:
    return bool(TOKEN_RE.fullmatch(label or ""))


def is_label(label: str) -> bool:
    """A valid, DNS-safe label the operator may use as an arbitrary namespace (e.g. 'bob')."""
    return bool(LABEL_RE.fullmatch(label or ""))


_SEG_RE = re.compile(r"[^0-9a-z]+")


def sanitize_label(s: str | None) -> str | None:
    """Collapse an arbitrary string into a single DNS-safe label (a-z0-9-), e.g. a crafted
    local-part ``victim.tld`` -> ``victim-tld``. Used as the correlation bucket for mail to a
    crafted address that carries no ob-token."""
    slug = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")
    return slug[:63].strip("-") or None


def token_in_text(s: str | None) -> str | None:
    """Recover an ob-token embedded anywhere in a delimited string — e.g. the local-part of a
    crafted address such as ``ob7f3k9a2x.victim.tld`` or ``"ob7f3k9a2x.victim.tld"``. Splits on
    any run of non-base36 characters and returns the first segment that is itself a token; the
    delimiter-bounded split keeps a victim domain that merely contains ``ob`` (``roblox``…) from
    being misread as one."""
    for seg in _SEG_RE.split((s or "").lower()):
        if is_token(seg):
            return seg
    return None


def token_from_host(host: str, domain: str) -> str | None:
    """Extract the token from a hostname under OOBDOMAIN.

    Matches the token as ANY label of the qualified name (the left-most one wins), so
    ``import.ob7f3k9a2x.oob.example.com`` and ``ob7f3k9a2x.oob.example.com`` both resolve
    to ``ob7f3k9a2x``.
    """
    if not host:
        return None
    host = host.split(":")[0].rstrip(".").lower()
    dom = domain.rstrip(".").lower()
    if host == dom:
        return None
    if not host.endswith("." + dom):
        return None
    sub = host[: -(len(dom) + 1)]
    for label in sub.split("."):
        if is_token(label):
            return label
    return None


def label_from_host(host: str, domain: str) -> str | None:
    """Resolve a hostname under the zone to its correlation label — the ob-token if any
    label is one, else the label immediately left of the zone. So ``bob.OOBDOMAIN`` →
    ``bob`` and ``x.y.bob.OOBDOMAIN`` → ``bob`` (arbitrary named namespaces just work),
    while ``import.<token>.OOBDOMAIN`` still → ``<token>``. Apex / out-of-zone → None."""
    if not host:
        return None
    host = host.split(":")[0].rstrip(".").lower()
    dom = domain.rstrip(".").lower()
    if host == dom or not host.endswith("." + dom):
        return None
    labels = [x for x in host[: -(len(dom) + 1)].split(".") if x]
    if not labels:
        return None
    for x in labels:
        if is_token(x):
            return x
    return labels[-1]


def label_from_rcpt(rcpt: str, domain: str) -> str | None:
    """Like label_from_host, but for an envelope recipient. ``bob@OOBDOMAIN`` (and
    ``bob+tag@…``) → ``bob``; ``anyone@<label>.OOBDOMAIN`` → that label."""
    if not rcpt or "@" not in rcpt:
        return None
    rcpt = rcpt.strip().strip("<>").lower()
    local, _, host = rcpt.partition("@")
    dom = domain.rstrip(".").lower()
    if host == dom:
        # An ob-token embedded anywhere in the local-part wins (crafted victim-domain
        # addresses); otherwise bucket by the sanitized local-part.
        return token_in_text(local) or sanitize_label(local.split("+", 1)[0])
    return label_from_host(host, domain)


def token_from_rcpt(rcpt: str, domain: str) -> str | None:
    """Extract the token from an envelope recipient.

    Handles ``<token>@OOBDOMAIN`` (incl. plus-tags ``<token>+tag@OOBDOMAIN``) and
    ``anything@<token>.OOBDOMAIN``.
    """
    if not rcpt or "@" not in rcpt:
        return None
    rcpt = rcpt.strip().strip("<>").lower()
    local, _, host = rcpt.partition("@")
    dom = domain.rstrip(".").lower()

    if host == dom:
        # the token may be the local-part, a +plus-tag base, or embedded in a crafted address
        return token_in_text(local)
    # otherwise the token may be a label of the host
    return token_from_host(host, domain)
