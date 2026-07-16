from __future__ import annotations
import json
import pytest
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk

# Passed EXPLICITLY (mirrors the model retrieving these from PAL) — NOT via fallback,
# so the test cannot pass on a frozen worker constant.
PAL_CRYPTO_SINKS = [
    "javax.crypto.CipherOutputStream.write(byte[] b)",
    "javax.crypto.Cipher.doFinal(byte[] input)",
]


@requires_apk
@pytest.mark.asyncio
async def test_keystore_hook_target_derived_from_graph():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.reachable_sinks(to=PAL_CRYPTO_SINKS, depth=8))
    assert out.get("error") is not True
    cand_methods = {r["candidate"]["method"] for r in out["rows"]}
    assert "encryptString" in cand_methods, (
        f"expected encryptString as a hook candidate; got {sorted(cand_methods)}")
    assert out["diagnostics"]["sink_source"] == "provided"
    # the candidate's witness path ends at the catalogued sink
    enc = next(r for r in out["rows"] if r["candidate"]["method"] == "encryptString")
    assert enc["path"][-1]["method"] in ("write", "doFinal")
