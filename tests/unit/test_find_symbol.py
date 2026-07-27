from __future__ import annotations
import json
import pytest
from pare_static_mcp import tools
from tests.fixtures.locate import (
    test_apk, requires_apk, TEST_METHOD, TEST_DUAL_NAME, TEST_DUAL_CLASS,
)


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


@requires_apk
@pytest.mark.asyncio
async def test_find_symbol_surfaces_same_named_class():
    # The bug: a name that is an Activity CLASS resolves only to the same-named
    # onClick launcher METHOD, hiding the class that holds the real logic.
    # find_symbol must now return a kind='class' row for the activity so the
    # model can pivot to it (static_list_methods) instead of the launcher.
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.find_symbol(TEST_DUAL_NAME))
    assert out.get("error") is not True
    class_rows = [r for r in out["rows"] if r["kind"] == "class"]
    assert any(TEST_DUAL_NAME in r["class"] for r in class_rows), out
    # and the misleading launcher method is still present (we hid nothing)
    def_rows = [r for r in out["rows"] if r["kind"] == "def"]
    assert any(r["method"] == TEST_DUAL_NAME and "MyActivity" in r["class"]
               for r in def_rows), out


@requires_apk
@pytest.mark.asyncio
async def test_find_symbol_class_row_feeds_list_methods():
    # A kind='class' row's 'class' must be a usable class name: feeding it to
    # list_methods reaches decryptString (the challenge's real target).
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.find_symbol(TEST_DUAL_NAME))
    class_rows = [r for r in out["rows"] if r["kind"] == "class"]
    assert class_rows, out
    lm = json.loads(await tools.list_methods(class_rows[0]["class"]))
    assert lm.get("error") is not True
    assert any(r["method"] == "decryptString" for r in lm["rows"]), lm


@requires_apk
@pytest.mark.asyncio
async def test_find_symbol_kind_class_returns_only_classes():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.find_symbol(TEST_DUAL_NAME, kind="class"))
    assert out.get("error") is not True
    assert out["rows"], out
    assert all(r["kind"] == "class" for r in out["rows"]), out


@requires_apk
@pytest.mark.asyncio
async def test_find_symbol_cls_scoped_search_omits_class_rows():
    # A cls-scoped search is already inside a class; it must not inject class rows.
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.find_symbol(TEST_METHOD, cls=TEST_DUAL_CLASS))
    assert out.get("error") is not True
    assert all(r["kind"] != "class" for r in out["rows"]), out
