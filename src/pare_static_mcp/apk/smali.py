from __future__ import annotations
import re


def grep(analysis, pattern: str) -> list[dict]:
    """Regex search over smali instruction text for every non-external method.

    Instruction text is formed as ``"{opcode} {operands}"`` using androguard
    4.1.3 accessors ``get_name()`` / ``get_output()``, which embed resolved
    class/field/method references, so const-string values and type names are
    visible without a separate string-pool scan.

    Args:
        analysis: androguard Analysis object (must have DEX loaded).
        pattern: Python regex pattern. Caller is responsible for catching
                 ``re.error`` and converting to an error response.

    Returns:
        List of ``{class, method, insn, match}`` dicts, one per matching line.
    """
    rx = re.compile(pattern)  # raises re.error on bad pattern -> caller returns _err
    rows: list[dict] = []

    for ca in analysis.get_classes():
        if ca.is_external():
            continue
        for ma in ca.get_methods():
            if ma.is_external():
                continue
            em = ma.get_method()
            if em is None:
                continue
            try:
                instructions = em.get_instructions()
            except Exception:
                continue
            for ins in instructions:
                text = f"{ins.get_name()} {ins.get_output()}"
                m = rx.search(text)
                if m:
                    rows.append({
                        "class": str(ca.name),
                        "method": ma.name,
                        "insn": text.strip(),
                        "match": m.group(0),
                    })

    return rows
