# src/pare_static_mcp/apk/sink_match.py
"""Pure sink-signature parsing/matching. NO androguard import (kept module-top clean).

Accepts sink signatures as PAL's catalog emits them (dotted-Java) or in smali form,
and matches them against androguard call-edge targets by class+method. Parameters are
intentionally ignored in v1: PAL's per-sink `overload=[...]` carries the arg detail
for the Frida hook; the worker only needs to identify the sink method.
"""
from __future__ import annotations


def _to_smali_class(cls: str) -> str:
    cls = cls.strip()
    if cls.startswith("L") and cls.endswith(";"):
        return cls
    return "L" + cls.replace(".", "/") + ";"


def parse_sink(sig: str) -> tuple[str, str] | None:
    """Return (class_smali, method) or None if no method can be extracted."""
    s = (sig or "").strip()
    if not s:
        return None
    # strip a parameter list if present:  method(...)  ->  method
    if "(" in s:
        s = s.partition("(")[0].strip()
    if not s:
        return None
    # smali arrow form:  Lfoo/Bar;->method
    if "->" in s:
        cls, _, method = s.partition("->")
        method = method.strip()
        if not method:
            return None
        return (_to_smali_class(cls), method)
    # dotted form:  a.b.C.method   (method = last dotted segment)
    if "." not in s:
        return None
    cls, _, method = s.rpartition(".")
    if not method or not cls:
        return None
    return (_to_smali_class(cls), method)


def edge_matches(parsed: tuple[str, str], cls_name: str, method_name: str) -> bool:
    want_cls, want_method = parsed
    return method_name == want_method and _to_smali_class(str(cls_name)) == want_cls
