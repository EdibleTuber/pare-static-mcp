from __future__ import annotations
import asyncio
import json
from typing import Any
from pare_static_mcp.config import load_config
from pare_static_mcp.apk import classes as classes_mod
from pare_static_mcp.apk import loader as loader_mod
from pare_static_mcp.apk import manifest as manifest_mod
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
