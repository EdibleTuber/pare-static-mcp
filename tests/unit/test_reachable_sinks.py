from __future__ import annotations
import json
import pytest
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk


@pytest.mark.asyncio
async def test_reachable_sinks_empty_to_without_fallback_errors():
    # no APK needed: guard fires before traversal
    out = json.loads(await tools.reachable_sinks(to=[]))
    assert out.get("error") is True
    assert "no sinks" in out["summary"].lower()


@requires_apk
@pytest.mark.asyncio
async def test_reachable_sinks_reports_unmatched_and_rejected():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.reachable_sinks(
        to=["com.nonexistent.Foo.bar", "!!!garbage!!!"]))
    assert out.get("error") is not True
    di: dict = out["diagnostics"]
    assert "com.nonexistent.Foo.bar" in diagnostics_flat(di["unmatched_sinks"])
    assert "!!!garbage!!!" in di["rejected_sinks"]
    assert di["sink_source"] == "provided"
    assert "under_approximation" in di


def diagnostics_flat(v):
    return v if isinstance(v, list) else list(v)


@requires_apk
@pytest.mark.asyncio
async def test_reachable_sinks_fallback_is_loud():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.reachable_sinks(to=[], allow_fallback=True))
    assert out.get("error") is not True
    assert out["diagnostics"]["sink_source"] == "fallback"


@requires_apk
@pytest.mark.asyncio
async def test_reachable_sinks_single_top_level_list():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.reachable_sinks(
        to=["javax.crypto.CipherOutputStream.write"]))
    list_keys = [k for k, v in out.items() if isinstance(v, list)]
    assert list_keys == ["rows"]        # exactly one top-level list
