"""Bounded BFS over an abstract graph, factored over a neighbor callable so the
traversal logic is testable on synthetic graphs (no androguard). androguard neighbor
adapters live at the bottom and are the only androguard-touching code — but they call
methods on objects passed in, so this module still imports nothing from androguard.
"""
from __future__ import annotations
from collections import deque

DEFAULT_DEPTH = 3
MAX_DEPTH = 12
MAX_NODES = 5000
MAX_ROWS = 200


def traverse(neighbors_fn, roots, max_depth, node_cap=MAX_NODES):
    """BFS. Returns (depth, parent, truncated). See module Interfaces in the plan."""
    depth: dict = {}
    parent: dict = {}
    q: deque = deque()
    for r in roots:
        if r not in depth:
            depth[r] = 0
            parent[r] = None
            q.append(r)
    truncated = False
    while q:
        node = q.popleft()
        if depth[node] >= max_depth:
            continue
        seen_local = set()
        for nb in neighbors_fn(node):
            if nb in seen_local or nb in depth:
                continue
            seen_local.add(nb)
            if len(depth) >= node_cap:
                truncated = True
                break
            depth[nb] = depth[node] + 1
            parent[nb] = node
            q.append(nb)
        if truncated:
            break
    return depth, parent, truncated


def path_from_root(node, parent) -> list:
    """[node, ..., root] following parent pointers; cycle-safe."""
    chain = []
    seen = set()
    cur = node
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        chain.append(cur)
        cur = parent.get(cur)
    return chain


# --- androguard neighbor adapters (called with MethodAnalysis nodes) ---

def callers(ma) -> list:
    """Backward neighbors: methods that invoke `ma` (index 1 of the 3-tuple)."""
    return [caller for _, caller, _ in ma.get_xref_from()]


def callees(ma) -> list:
    """Forward neighbors: methods `ma` invokes. External targets are included (so a
    sink edge is detectable) but callers()/callees() on them yield nothing to expand."""
    return [callee for _, callee, _ in ma.get_xref_to()]
