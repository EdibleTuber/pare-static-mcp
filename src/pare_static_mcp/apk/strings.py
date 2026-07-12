from __future__ import annotations


def extract(analysis, filt: str) -> list[dict]:
    """Return string-pool rows with optional substring filter and xref annotation.

    Each row: {value, class, method, kind="string", source="dex"}.
    Rows with no xrefs get class=None, method=None.
    Rows with xrefs are fanned out — one row per (class, method) reference.
    """
    rows: list[dict] = []
    for sa in analysis.get_strings():
        value = sa.get_value()
        if filt and filt not in value:
            continue
        xrefs = list(sa.get_xref_from())  # (ClassAnalysis, MethodAnalysis) pairs
        if xrefs:
            for ca, ma in xrefs:
                rows.append({
                    "value": value,
                    "class": str(ca.name),
                    "method": getattr(ma, "name", None),
                    "kind": "string",
                    "source": "dex",
                })
        else:
            rows.append({
                "value": value,
                "class": None,
                "method": None,
                "kind": "string",
                "source": "dex",
            })
    return rows
