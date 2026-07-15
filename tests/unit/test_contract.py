from pare_static_mcp.contract import TOOL_SPECS, WorkerContractAdapter

EXPECTED = {"load_apk", "find_symbol", "grep_smali", "list_methods",
            "extract_strings", "decompile_method", "read_manifest"}

def test_seven_tools_named():
    assert {s.name for s in TOOL_SPECS} == EXPECTED

def test_adapter_lists_seven():
    assert len(WorkerContractAdapter().list_tools()) == 7
