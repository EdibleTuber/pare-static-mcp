from __future__ import annotations
import json
import pytest
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk, TEST_METHOD


@requires_apk
@pytest.mark.asyncio
async def test_callers_of_multi_hop_reaches_frontier():
    await tools.load_apk(str(test_apk()))
    # encryptString is called only from OMTG_DATAST_001_KeyStore$1.onClick (a
    # framework-dispatched callback with no static caller => frontier).
    out = json.loads(await tools.callers_of(TEST_METHOD, depth=5))
    assert out.get("error") is not True
    assert len(out["rows"]) > 0
    onclick = [r for r in out["rows"] if r["method"] == "onClick"]
    assert onclick, "expected onClick among transitive callers"
    assert onclick[0]["frontier"] is True
    for r in out["rows"]:
        assert {"class", "method", "signature", "depth", "frontier"} <= set(r)


@requires_apk
@pytest.mark.asyncio
async def test_callers_of_unknown_method_errors_honestly():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.callers_of("thisMethodDoesNotExist_xyz"))
    assert out.get("error") is True
