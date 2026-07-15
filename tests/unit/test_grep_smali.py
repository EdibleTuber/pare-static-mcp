from __future__ import annotations
import json
import pytest
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk, TEST_STRING


@requires_apk
@pytest.mark.asyncio
async def test_grep_smali_matches_string_pool():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.grep_smali(TEST_STRING))
    assert out.get("error") is not True
    assert len(out["rows"]) >= 1


@requires_apk
@pytest.mark.asyncio
async def test_grep_smali_bad_regex_errors():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.grep_smali("("))
    assert out["error"] is True
