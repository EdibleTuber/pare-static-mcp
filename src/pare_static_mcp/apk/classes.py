from __future__ import annotations


def _match(name: str, cls: str) -> bool:
    """Accept dotted (com.example.Crypto) or smali (Lcom/example/Crypto;) class name."""
    smali = "L" + cls.replace(".", "/") + ";"
    return name in (cls, smali) or name.rstrip(";").endswith(cls.replace(".", "/"))


def list_methods(analysis, cls: str) -> list[dict]:
    """Return one row per method of the named class with descriptor, flags, and xref count.

    Each row: {method, descriptor, flags, xref_count}.
    Returns an empty list if the class name matches nothing.

    Androguard 4.1.3 note: EncodedMethod.access_flags_string is a broken property
    that always returns None; get_access_flags_string() is the correct call.
    ExternalMethod only has get_access_flags_string() (no property at all).
    """
    rows: list[dict] = []
    for ca in analysis.get_classes():
        if not _match(str(ca.name), cls):
            continue
        for ma in ca.get_methods():
            em = ma.get_method()
            descriptor = str(em.descriptor) if hasattr(em, "descriptor") else str(getattr(ma, "descriptor", ""))
            flags_fn = getattr(em, "get_access_flags_string", None)
            flags = flags_fn() if callable(flags_fn) else ""
            xref_count = len(list(ma.get_xref_from()))
            rows.append({
                "method": ma.name,
                "descriptor": descriptor,
                "flags": str(flags),
                "xref_count": xref_count,
            })
    return rows
