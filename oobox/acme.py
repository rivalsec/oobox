"""ACME DNS-01 support.

Wildcard certs for ``*.OOBDOMAIN`` can only be issued via the DNS-01 challenge. Since
this box is authoritative for the zone, we answer the ``_acme-challenge`` TXT records
ourselves. certbot's ``--manual`` auth/cleanup hooks call the control API
(``/acme/present`` / ``/acme/cleanup``) to register/clear a challenge value; the DNS
listener serves whatever this in-memory registry holds.

The hook scripts and the ready-made certbot invocation live in ``deploy/`` and README.
"""
from __future__ import annotations

import threading


class AcmeStore:
    """Thread-safe registry of active ``_acme-challenge`` TXT values, keyed by FQDN."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._txt: dict[str, set[str]] = {}

    @staticmethod
    def _norm(name: str) -> str:
        return name.rstrip(".").lower()

    def present(self, name: str, value: str) -> None:
        with self._lock:
            self._txt.setdefault(self._norm(name), set()).add(value)

    def cleanup(self, name: str, value: str | None = None) -> None:
        key = self._norm(name)
        with self._lock:
            if value is None:
                self._txt.pop(key, None)
            elif key in self._txt:
                self._txt[key].discard(value)
                if not self._txt[key]:
                    self._txt.pop(key, None)

    def get(self, name: str) -> list[str]:
        with self._lock:
            return sorted(self._txt.get(self._norm(name), set()))
