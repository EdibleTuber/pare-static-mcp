import json
import pytest
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk, TEST_CLASS, TEST_METHOD


@requires_apk
@pytest.mark.asyncio
async def test_list_methods_finds_encrypt():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.list_methods(TEST_CLASS))
    assert out.get("error") is not True
    assert any(r["method"] == TEST_METHOD for r in out["rows"])
