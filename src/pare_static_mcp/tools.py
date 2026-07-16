from __future__ import annotations
import asyncio
import json
import re
from typing import Any
from pare_static_mcp.config import load_config
from pare_static_mcp.apk import classes as classes_mod
from pare_static_mcp.apk import decompile as decompile_mod
from pare_static_mcp.apk import graph as graph_mod
from pare_static_mcp.apk import loader as loader_mod
from pare_static_mcp.apk import manifest as manifest_mod
from pare_static_mcp.apk import smali as smali_mod
from pare_static_mcp.apk import state as state_mod
from pare_static_mcp.apk import strings as strings_mod
from pare_static_mcp.apk import symbols as symbols_mod

CFG = load_config()


def _ok(summary: str, **extra: Any) -> str:
    pkg = state_mod.CURRENT.package if state_mod.CURRENT else None
    return json.dumps({"summary": summary, "package": pkg, **extra})


def _err(summary: str, exc: Exception | None = None) -> str:
    payload = {"summary": summary, "error": True}
    if exc is not None:
        payload["detail"] = str(exc)
    return json.dumps(payload)


def _require_current() -> state_mod.APKState:
    if state_mod.CURRENT is None:
        raise LookupError("no APK loaded - call load_apk first")
    return state_mod.CURRENT


async def load_apk(path: str) -> str:
    try:
        st = await asyncio.to_thread(loader_mod.load, path, CFG)
        state_mod.set_current(st)
        return _ok(f"loaded {st.package}", package=st.package,
                   min_sdk=st.apk.get_min_sdk_version(),
                   target_sdk=st.apk.get_target_sdk_version(),
                   class_count=st.class_count, dex_count=st.dex_count,
                   native_libs=st.native_libs, dynamic_load=st.dynamic_load)
    except Exception as e:
        return _err("load_apk failed", e)


async def read_manifest() -> str:
    try:
        st = _require_current()
        m = await asyncio.to_thread(manifest_mod.parse, st.apk)
        return _ok(f"manifest for {st.package}", **m)
    except Exception as e:
        return _err("read_manifest failed", e)


def _extract_strings_blocking(state: state_mod.APKState, filt: str) -> list[dict]:
    """Run xref build + string extraction on the calling thread (for asyncio.to_thread)."""
    loader_mod.ensure_xref(state)
    return strings_mod.extract(state.analysis, filt)


async def extract_strings(filter: str = "") -> str:
    try:
        st = _require_current()
        rows = await asyncio.to_thread(_extract_strings_blocking, st, filter)
        hint = "" if filter else " (pass filter= to narrow)"
        return _ok(f"{len(rows)} strings{hint}", rows=rows)
    except Exception as e:
        return _err("extract_strings failed", e)


def _list_methods_blocking(state: state_mod.APKState, cls: str) -> list[dict]:
    """Ensure xref then enumerate methods — runs on a thread (thread-safe via xref_lock)."""
    loader_mod.ensure_xref(state)
    return classes_mod.list_methods(state.analysis, cls)


async def list_methods(cls: str) -> str:
    try:
        st = _require_current()
        rows = await asyncio.to_thread(_list_methods_blocking, st, cls)
        return _ok(f"{len(rows)} methods in {cls}", rows=rows)
    except Exception as e:
        return _err("list_methods failed", e)


def _find_symbol_blocking(state: state_mod.APKState, symbol: str, kind: str, cls: str) -> list[dict]:
    """Ensure xref then find symbol — runs on a thread (thread-safe via xref_lock)."""
    loader_mod.ensure_xref(state)
    return symbols_mod.find(state.analysis, symbol, kind, cls)


async def find_symbol(symbol: str, kind: str = "def", cls: str = "") -> str:
    try:
        st = _require_current()
        rows = await asyncio.to_thread(_find_symbol_blocking, st, symbol, kind, cls)
        return _ok(f"{len(rows)} {kind} rows for {symbol}", rows=rows)
    except Exception as e:
        return _err("find_symbol failed", e)


async def grep_smali(pattern: str) -> str:
    try:
        st = _require_current()
        rows = await asyncio.to_thread(smali_mod.grep, st.analysis, pattern)
        return _ok(f"{len(rows)} smali matches", rows=rows)
    except Exception as e:
        return _err("grep_smali failed", e)


async def decompile_method(cls: str, method: str, signature: str = "",
                           lang: str = "java") -> str:
    try:
        st = _require_current()
        if lang == "java" and not CFG.jadx_available:
            lang = "smali"   # graceful degrade when jadx not on PATH
        res = await asyncio.to_thread(
            decompile_mod.decompile, st, cls, method, signature, lang, CFG
        )
        return _ok(f"decompiled {cls}.{method} ({res['lang']})", **res)
    except Exception as e:
        return _err("decompile_method failed", e)


def _resolve_methods(analysis, cls: str, method: str, signature: str = "") -> list:
    """Resolve (cls, method[, signature]) to MethodAnalysis objects. Anchors + escapes
    the regex (find_methods does an unanchored re.match; inner-class '$' is a metachar)."""
    classname = ("^" + re.escape("L" + cls.replace(".", "/") + ";") + "$") if cls else "."
    name = "^" + re.escape(method) + "$"
    out = []
    for ma in analysis.find_methods(classname=classname, methodname=name):
        if signature and str(getattr(ma, "descriptor", "")) != signature:
            continue
        out.append(ma)
    return out


def _method_row(ma, depth: int | None = None) -> dict:
    row = {
        "class": str(ma.class_name),
        "method": ma.name,
        "signature": str(getattr(ma, "descriptor", "")),
        "frontier": next(iter(ma.get_xref_from()), None) is None,
    }
    if depth is not None:
        row["depth"] = depth
    return row


def _callers_of_blocking(state, method: str, cls: str, signature: str, depth: int):
    loader_mod.ensure_xref(state)
    roots = _resolve_methods(state.analysis, cls, method, signature)
    if not roots:
        return None  # signal: not found
    md = min(depth, graph_mod.MAX_DEPTH)
    dmap, _parent, trunc = graph_mod.traverse(graph_mod.callers, roots, max_depth=md)
    rows = []
    for ma, d in dmap.items():
        if d == 0:
            continue  # skip the target itself
        rows.append(_method_row(ma, d))
        if len(rows) >= graph_mod.MAX_ROWS:
            trunc = True
            break
    return {"rows": rows, "truncated": trunc}


async def callers_of(method: str, cls: str = "", signature: str = "", depth: int = 3) -> str:
    try:
        st = _require_current()
        res = await asyncio.to_thread(
            _callers_of_blocking, st, method, cls, signature, depth
        )
        if res is None:
            return _err(f"root_not_found: {cls or '*'}.{method}")
        return _ok(f"{len(res['rows'])} transitive callers of {method}",
                   rows=res["rows"], diagnostics={"truncated": res["truncated"]})
    except Exception as e:
        return _err("callers_of failed", e)


def _paths_between_blocking(state, from_method, from_cls, to_method, to_cls,
                            from_sig, to_sig, max_depth):
    loader_mod.ensure_xref(state)
    sources = _resolve_methods(state.analysis, from_cls, from_method, from_sig)
    if not sources:
        return {"error": "root_not_found", "which": f"{from_cls or '*'}.{from_method}"}
    targets = _resolve_methods(state.analysis, to_cls, to_method, to_sig)
    if not targets:
        # The target resolved to zero MethodAnalysis nodes. That can mean either
        # a genuine "never called anywhere in the app" (androguard only
        # materializes nodes for referenced symbols - verified against raw
        # bytecode, not just xrefs) OR a typo'd target class/method. Both are
        # trivially unreachable, so path is empty rather than an _err; but we
        # surface target_resolved=False so a caller can tell an honest negative
        # apart from a query that never located the target at all.
        return {"path": [], "diagnostics": {"target_resolved": False}}
    md = min(max_depth, graph_mod.MAX_DEPTH)
    target_ids = {id(t) for t in targets}
    dmap, parent, _trunc = graph_mod.traverse(graph_mod.callees, sources, max_depth=md)
    hit = next((n for n in dmap if id(n) in target_ids), None)
    if hit is None:
        return {"path": [], "diagnostics": {"target_resolved": True}}
    chain = graph_mod.path_from_root(hit, parent)      # [target, ..., source]
    chain.reverse()                                    # -> [source, ..., target]
    return {"path": [{"class": str(m.class_name), "method": m.name,
                      "signature": str(getattr(m, "descriptor", ""))} for m in chain],
            "diagnostics": {"target_resolved": True}}


async def paths_between(from_method: str, from_cls: str = "", to_method: str = "",
                        to_cls: str = "", from_signature: str = "", to_signature: str = "",
                        max_depth: int = 12) -> str:
    try:
        st = _require_current()
        res = await asyncio.to_thread(
            _paths_between_blocking, st, from_method, from_cls, to_method, to_cls,
            from_signature, to_signature, max_depth,
        )
        if res.get("error"):
            return _err(f"{res['error']}: {res.get('which', '')}")
        n = len(res["path"])
        return _ok(f"path of {n} nodes" if n else "no static path (control-flow only; "
                   "reflection/callbacks invisible - confirm dynamically)",
                   path=res["path"], diagnostics=res.get("diagnostics", {}))
    except Exception as e:
        return _err("paths_between failed", e)
