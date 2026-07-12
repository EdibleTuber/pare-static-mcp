from __future__ import annotations
import json
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk, TEST_STRING


@requires_apk
async def test_extract_finds_known_string():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.extract_strings(TEST_STRING))
    assert out.get("error") is not True
    vals = [r["value"] for r in out["rows"]]
    assert any(TEST_STRING in v for v in vals)
    assert all(r["source"] == "dex" for r in out["rows"])


@requires_apk
async def test_extract_strings_xref_populated():
    """At least one row for TEST_STRING should have a non-None class (xref wired up)."""
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.extract_strings(TEST_STRING))
    assert out.get("error") is not True
    rows = out["rows"]
    assert any(r["class"] is not None for r in rows), (
        "Expected at least one row with class set (string->method xref not wired)"
    )


@requires_apk
async def test_extract_strings_no_filter_summary_hints_filter():
    """When no filter is given, summary text should hint about filter= param."""
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.extract_strings())
    assert out.get("error") is not True
    assert "filter" in out["summary"], f"Expected 'filter' hint in summary, got: {out['summary']!r}"


async def test_extract_strings_without_apk_returns_error():
    """Calling extract_strings before load_apk returns an error payload."""
    import pare_static_mcp.apk.state as state_mod
    state_mod.CURRENT = None
    out = json.loads(await tools.extract_strings("anything"))
    assert out["error"] is True
