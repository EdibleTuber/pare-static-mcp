from __future__ import annotations
import os
import zipfile
from pare_static_mcp.apk.state import APKState

_DYNAMIC_MARKERS = ("Ldalvik/system/DexClassLoader", "Ldalvik/system/PathClassLoader",
                    "->loadLibrary", "->load(")


def _guard_input(path: str, cfg) -> None:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"not a regular file: {path}")
    size = os.path.getsize(path)
    if size > cfg.max_apk_bytes:
        raise ValueError(f"APK too large: {size} > {cfg.max_apk_bytes}")
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > cfg.max_zip_entries:
            raise ValueError(f"too many zip entries: {len(infos)}")
        total = sum(i.file_size for i in infos)
        if total > cfg.max_decompressed_bytes:
            raise ValueError(f"decompressed size too large: {total}")


def load(path: str, cfg) -> APKState:
    _guard_input(path, cfg)
    # Silence androguard's verbose loguru output so it can't muddy the stdio
    # channel; then lazy-import — MUST NOT be at module top (2s discovery ceiling).
    from loguru import logger
    logger.remove()
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    from androguard.core.analysis.analysis import Analysis
    apk = APK(path)
    analysis = Analysis()
    dex_count = 0
    for dex_bytes in apk.get_all_dex():
        analysis.add(DEX(dex_bytes))
        dex_count += 1
    class_count = sum(1 for _ in analysis.get_classes())
    native = [f for f in apk.get_files() if f.startswith("lib/") and f.endswith(".so")]
    dynamic = _detect_dynamic(analysis)
    return APKState(path=path, package=apk.get_package(), apk=apk, analysis=analysis,
                    dex_count=dex_count, class_count=class_count,
                    native_libs=native, dynamic_load=dynamic)


def _detect_dynamic(analysis) -> list[str]:
    found = set()
    for s in analysis.get_strings():
        v = s.get_value()
        for m in _DYNAMIC_MARKERS:
            if m.strip("L->(") in v:
                found.add(m.strip("L->("))
    return sorted(found)


def ensure_xref(state: APKState) -> None:
    if not state._xref_built:
        state.analysis.create_xref()
        state._xref_built = True
