"""Run the full end-to-end selftest under pytest."""
import asyncio

from oobox.selftest import run_selftest


def test_end_to_end():
    assert asyncio.run(run_selftest()) is True
