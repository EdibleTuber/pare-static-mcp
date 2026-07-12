from __future__ import annotations


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


def find(analysis, symbol: str, kind: str, cls: str) -> list[dict]:
    classname = ("L" + cls.replace(".", "/") + ";") if cls else "."
    rows: list[dict] = []
    for ma in analysis.find_methods(classname=classname, methodname=f"^{symbol}$"):
        rows.extend(_rows_for(ma, kind))
    return rows
