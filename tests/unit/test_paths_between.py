from __future__ import annotations
import json
import pytest
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk


@requires_apk
@pytest.mark.asyncio
async def test_paths_between_encrypt_to_cipherstream():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.paths_between(
        from_method="encryptString",
        to_method="write", to_cls="javax.crypto.CipherOutputStream",
    ))
    assert out.get("error") is not True
    assert len(out["path"]) >= 2
    assert out["path"][0]["method"] == "encryptString"          # source first
    assert out["path"][-1]["method"] == "write"                 # target last


@requires_apk
@pytest.mark.asyncio
async def test_paths_between_unreachable_is_empty_not_error():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.paths_between(
        from_method="encryptString",
        to_method="exec", to_cls="java.lang.Runtime",
    ))
    assert out.get("error") is not True
    assert out["path"] == []
