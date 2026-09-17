"""Guard the served dashboard HTML against inline-script breakage.

The dashboard is one HTML document with an inline <script>. A literal ``</script>`` inside
a JS string (e.g. when emitting a `<script src=…>` payload snippet) silently terminates the
inline block — the rest is parsed as HTML and the page breaks. Every intentional closing tag
in the JS is written split as ``</'+'script>``, so the whole file must contain exactly ONE
literal ``</script>`` (the real closer).
"""
import re
import shutil
import subprocess
from pathlib import Path

DASH = Path(__file__).resolve().parent.parent / "oobox" / "static" / "dashboard.html"


def test_single_literal_closing_script_tag():
    html = DASH.read_text()
    assert html.count("</script>") == 1, (
        "found a literal </script> inside the inline JS — split it as </'+'script>")


def test_inline_script_is_valid_js():
    node = shutil.which("node")
    if not node:
        import pytest
        pytest.skip("node not installed; skipping JS syntax check")
    html = DASH.read_text()
    m = re.search(r"<script>(.*)</script>", html, re.S)
    assert m, "no inline <script> block found"
    tmp = DASH.parent / "_dash_inline_check.js"
    tmp.write_text(m.group(1))
    try:
        r = subprocess.run([node, "--check", str(tmp)], capture_output=True, text=True)
        assert r.returncode == 0, f"dashboard inline JS syntax error:\n{r.stderr}"
    finally:
        tmp.unlink(missing_ok=True)
