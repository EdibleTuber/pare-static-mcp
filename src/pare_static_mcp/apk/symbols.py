from __future__ import annotations

import re


def _rows_for(ma, kind: str) -> list[dict]:
    sig = str(getattr(ma, "descriptor", ""))
    base = {"class": str(ma.class_name), "method": ma.name, "signature": sig}
    out = []
    if kind in ("def", "both") and not ma.is_external():
        out.append({**base, "kind": "def"})
    if kind in ("caller", "both"):
        for _, caller_ma, _ in ma.get_xref_from():
            caller_sig = str(getattr(caller_ma, "descriptor", ""))
            out.append({
                "class": str(caller_ma.class_name),
                "method": caller_ma.name,
                "signature": caller_sig,
                "kind": "caller",
            })
    return out


def _class_rows(analysis, symbol: str) -> list[dict]:
    """Rows for app classes whose name equals ``symbol`` (kind='class').

    ``find_symbol`` matches METHOD names only. A bare name that is really a
    class — an Activity, say — would otherwise return just the same-named
    onClick launcher method and hide the class that holds the real logic
    (e.g. decryptString). Surface matching classes so the model can pivot to
    ``static_list_methods`` on the class instead of decompiling the launcher.

    Matches either the simple name (last path segment == symbol) or the full
    dotted name (com.pkg.Name). External/framework classes are skipped.
    """
    dotted = symbol.strip()
    simple = dotted.rsplit(".", 1)[-1]
    by_simple = re.compile(rf"^L(?:.*/)?{re.escape(simple)};$")
    by_full = "L" + dotted.replace(".", "/") + ";"
    out: list[dict] = []
    seen: set[str] = set()
    for ca in analysis.get_classes():
        name = str(ca.name)
        if name in seen:
            continue
        is_external = getattr(ca, "is_external", None)
        if callable(is_external) and is_external():
            continue
        if by_simple.match(name) or name == by_full:
            seen.add(name)
            out.append({"class": name, "method": "", "signature": "", "kind": "class"})
    return out


def find(analysis, symbol: str, kind: str, cls: str) -> list[dict]:
    classname = ("L" + cls.replace(".", "/") + ";") if cls else "."
    rows: list[dict] = []
    for ma in analysis.find_methods(classname=classname, methodname=f"^{symbol}$"):
        rows.extend(_rows_for(ma, kind))
    # Class resolution: only for an UNSCOPED name search (a cls-scoped search is
    # already inside a class), and only when defs/classes are wanted (a class is
    # not a "caller"). kind='class' narrows to classes only.
    if not cls and kind in ("def", "both", "class"):
        rows.extend(_class_rows(analysis, symbol))
    return rows
