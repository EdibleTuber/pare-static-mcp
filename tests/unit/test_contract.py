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
