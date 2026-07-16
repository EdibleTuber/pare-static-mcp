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
    assert out["diagnostics"]["target_resolved"] is True        # target located


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
    # Runtime.exec is genuinely never referenced anywhere in this APK, so it
    # never resolves to a MethodAnalysis node => target_resolved is False.
    assert out["diagnostics"]["target_resolved"] is False


@requires_apk
@pytest.mark.asyncio
async def test_paths_between_garbage_target_flags_unresolved():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.paths_between(
        from_method="encryptString",
        to_method="wrteXYZ", to_cls="javax.crypto.CipherOutputStream",
    ))
    assert out.get("error") is not True
    assert out["path"] == []
    # A typo'd target must not masquerade as an honest "unreachable" negative -
    # it's flagged unresolved so a caller can tell the two apart.
    assert out["diagnostics"]["target_resolved"] is False
