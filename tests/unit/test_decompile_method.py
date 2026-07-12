from __future__ import annotations
import json
import pytest
from pare_static_mcp import tools
from pare_static_mcp.tools import CFG
from tests.fixtures.locate import test_apk, requires_apk, TEST_CLASS, TEST_METHOD


@requires_apk
@pytest.mark.asyncio
async def test_decompile_smali_always_available():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.decompile_method(
        TEST_CLASS, TEST_METHOD, lang="smali"))
    assert out.get("error") is not True
    assert out["lang"] == "smali"
    assert TEST_METHOD in out["source"]


@requires_apk
@pytest.mark.asyncio
@pytest.mark.skipif(not CFG.jadx_available, reason="JADX_PATH unresolved")
async def test_decompile_java_via_jadx():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.decompile_method(
        TEST_CLASS, TEST_METHOD, lang="java"))
    assert out.get("error") is not True
    assert out["lang"] == "java"
    assert TEST_METHOD in out["source"]
