from pare_static_mcp.contract import TOOL_SPECS

def test_all_tools_low_tier():
    assert all(s.risk_tier == "low" for s in TOOL_SPECS)
