from __future__ import annotations
import json
import pytest
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk, TEST_METHOD


@requires_apk
@pytest.mark.asyncio
async def test_find_symbol_def():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.find_symbol(TEST_METHOD))
    assert out.get("error") is not True
    defs = [r for r in out["rows"] if r["kind"] == "def"]
    assert any(r["method"] == TEST_METHOD and "KeyStore" in r["class"] for r in defs)


@requires_apk
@pytest.mark.asyncio
async def test_find_symbol_default_kind_is_def():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.find_symbol(TEST_METHOD))
    assert all(r["kind"] == "def" for r in out["rows"])


@requires_apk
@pytest.mark.asyncio
async def test_find_symbol_caller_kind():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.find_symbol(TEST_METHOD, kind="caller"))
    assert out.get("error") is not True
    assert len(out["rows"]) > 0
    assert all(r["kind"] == "caller" for r in out["rows"])


@requires_apk
@pytest.mark.asyncio
async def test_find_symbol_rows_have_required_fields():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.find_symbol(TEST_METHOD, kind="both"))
    assert out.get("error") is not True
    for row in out["rows"]:
        assert "class" in row
        assert "method" in row
        assert "signature" in row
        assert "kind" in row
