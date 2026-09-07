from pare_worker_kit import VALID_PRODUCES

from pare_static_mcp.contract import TOOL_SPECS, WorkerContractAdapter

EXPECTED = {"load_apk", "find_symbol", "grep_smali", "list_methods",
            "extract_strings", "decompile_method", "read_manifest",
            "callers_of", "paths_between", "reachable_sinks"}

def test_all_tools_named():
    assert {s.name for s in TOOL_SPECS} == EXPECTED

def test_adapter_lists_all():
    assert len(WorkerContractAdapter().list_tools()) == len(EXPECTED)


def test_reachability_tools_registered_low():
    from pare_static_mcp.contract import TOOL_SPECS
    names = {s.name: s for s in TOOL_SPECS}
    for n in ("callers_of", "paths_between", "reachable_sinks"):
        assert n in names, f"{n} missing from TOOL_SPECS"
        assert names[n].risk_tier == "low"


def test_server_wires_reachability_handlers():
    from pare_static_mcp import tools
    for n in ("callers_of", "paths_between", "reachable_sinks"):
        assert callable(getattr(tools, n))


def test_every_tool_declares_a_produces_value_the_daemon_understands():
    """A typo here is invisible at runtime, which is why it is caught here.

    Dispatch falls back to the safe reading when `produces` is unrecognised,
    so a tool meaning `artifact` and writing `ARTIFACT` would quietly stream a
    file's contents back as a tool result instead of a descriptor. agent_core
    rejects it at build time too; this catches it one repo earlier, where the
    typo actually gets written. The wire test cannot: it compares `_meta`
    against `spec.produces`, so both sides carry the same typo and agree.
    """
    for spec in TOOL_SPECS:
        assert spec.produces in VALID_PRODUCES, (
            f"{spec.name} declares produces={spec.produces!r}, "
            f"which is not one of {VALID_PRODUCES}")
