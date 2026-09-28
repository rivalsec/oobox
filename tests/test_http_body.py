"""Regression tests for _read_capped_body.

aiohttp's StreamReader.read(n) returns UP TO n bytes and may return fewer than n before
EOF (it hands back whatever is currently buffered). A single read(cap+1) therefore silently
truncated any body spanning more than one network read — e.g. a real browser's screenshot
dataURL — which then failed to parse as JSON and was mis-stored as a separate _raw report.
The hermetic selftest never caught this because its bodies arrive in one chunk.
"""
import asyncio

from oobox.http_server import _read_capped_body


class ChunkedContent:
    """Mimics StreamReader.read(n): returns up to n bytes, but never more than `chunk`
    per call, so a single read() under-reads a multi-segment body (the pre-fix bug)."""

    def __init__(self, data: bytes, chunk: int = 4096):
        self._data, self._chunk, self._pos = data, chunk, 0

    async def read(self, n):
        if self._pos >= len(self._data):
            return b""
        end = min(self._pos + min(n, self._chunk), len(self._data))
        out = self._data[self._pos:end]
        self._pos = end
        return out


class FakeRequest:
    def __init__(self, content):
        self.content = content


def test_reads_full_body_across_many_chunks():
    body = b"x" * 30000  # spans several 4096-byte reads, like a browser screenshot POST
    req = FakeRequest(ChunkedContent(body, chunk=4096))
    text, total = asyncio.run(_read_capped_body(req, cap=6 * 1024 * 1024))
    assert total == len(body)
    assert text == body.decode()
    assert "…[truncated]" not in text


def test_truncates_and_marks_when_body_exceeds_cap():
    body = b"y" * 5000
    req = FakeRequest(ChunkedContent(body, chunk=1000))
    text, total = asyncio.run(_read_capped_body(req, cap=2000))
    assert total == 2001              # cap+1 bytes are accounted for
    assert text[:2000] == "y" * 2000
    assert text.endswith("…[truncated]")
