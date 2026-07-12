import json
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk, TEST_PACKAGE


@requires_apk
async def test_load_apk_returns_package_and_signals():
    out = json.loads(await tools.load_apk(str(test_apk())))
    assert out.get("error") is not True
    assert out["package"] == TEST_PACKAGE
    assert out["class_count"] >= 1
    assert out["dex_count"] >= 1
    assert "native_libs" in out and "dynamic_load" in out


@requires_apk
async def test_load_apk_replaces_previous():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.load_apk(str(test_apk())))
    assert out.get("error") is not True


async def test_load_apk_rejects_missing_file():
    out = json.loads(await tools.load_apk("/no/such.apk"))
    assert out["error"] is True
