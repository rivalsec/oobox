"""oobox — self-hosted all-in-one out-of-band interaction server.

One asyncio process that is authoritative DNS for a delegated domain, an HTTP/HTTPS
interaction catcher + token-scoped file host + blind-XSS collector, and a catch-all
SMTP receiver — all correlated by a single per-interaction token, and driven by an
authenticated control API.

FOR AUTHORIZED SECURITY TESTING ONLY. This is a passive catcher plus your own
file/mail host; it is never a means to attack third parties.
"""

__version__ = "0.1.0"
