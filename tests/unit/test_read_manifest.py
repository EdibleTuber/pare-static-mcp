import json
from pare_static_mcp import tools
from tests.fixtures.locate import test_apk, requires_apk


@requires_apk
async def test_read_manifest_shape():
    await tools.load_apk(str(test_apk()))
    out = json.loads(await tools.read_manifest())
    for k in ("permissions", "activities", "services", "receivers",
              "providers", "exported", "application_class",
              "debuggable", "allow_backup"):
        assert k in out


async def test_read_manifest_requires_load():
    tools.state_mod.CURRENT = None
    out = json.loads(await tools.read_manifest())
    assert out["error"] is True
