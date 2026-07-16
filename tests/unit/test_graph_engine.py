# tests/unit/test_graph_engine.py
from __future__ import annotations
from pare_static_mcp.apk import graph


def _nf(adj):
    return lambda n: adj.get(n, [])


def test_bfs_min_depth_on_diamond():
    # A->B->D and A->C->D->... plus a short A->D via B; D reachable at depth 2 both ways
    adj = {"A": ["B", "C"], "B": ["D"], "C": ["D"], "D": []}
    depth, parent, trunc = graph.traverse(_nf(adj), ["A"], max_depth=12)
    assert depth["A"] == 0 and depth["B"] == 1 and depth["D"] == 2
    assert trunc is False


def test_cycle_terminates():
    adj = {"A": ["B"], "B": ["C"], "C": ["A"]}  # 3-node cycle
    depth, parent, trunc = graph.traverse(_nf(adj), ["A"], max_depth=12)
    assert set(depth) == {"A", "B", "C"}  # each visited once


def test_depth_clamp_boundary():
    # chain A->B->C->D->E ; max_depth=2 reaches C (depth2), not D
    adj = {"A": ["B"], "B": ["C"], "C": ["D"], "D": ["E"], "E": []}
    depth, parent, trunc = graph.traverse(_nf(adj), ["A"], max_depth=2)
    assert "C" in depth and depth["C"] == 2
    assert "D" not in depth


def test_node_cap_truncates():
    adj = {"A": [f"n{i}" for i in range(10)]}
    depth, parent, trunc = graph.traverse(_nf(adj), ["A"], max_depth=12, node_cap=5)
    assert trunc is True
    assert len(depth) <= 5


def test_duplicate_neighbors_visited_once():
    adj = {"A": ["B", "B", "B"], "B": []}  # duplicate edges (mirrors repeated call offsets)
    depth, parent, trunc = graph.traverse(_nf(adj), ["A"], max_depth=12)
    assert depth == {"A": 0, "B": 1}


def test_path_from_root():
    adj = {"A": ["B"], "B": ["C"], "C": []}
    depth, parent, trunc = graph.traverse(_nf(adj), ["A"], max_depth=12)
    assert graph.path_from_root("C", parent) == ["C", "B", "A"]
