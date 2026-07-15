from __future__ import annotations
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def _smali_source(state, cls: str, method: str) -> str | None:
    """Extract smali instructions for `method` in `cls` using androguard.

    Accepts both dotted FQCN (``sg.vp.owasp_mobile.Foo``) and dalvik
    descriptor (``Lsg/vp/owasp_mobile/Foo;``) as ``cls``.
    """
    smali = "L" + cls.replace(".", "/") + ";"
    for ca in state.analysis.get_classes():
        name = str(ca.name)
        if name not in (cls, smali) and not name.endswith(cls.replace(".", "/") + ";"):
            continue
        parts: list[str] = []
        for ma in ca.get_methods():
            if ma.name != method:
                continue
            em = ma.get_method()
            parts.append(f"# {ma.name} {getattr(em, 'descriptor', '')}")
            for ins in em.get_instructions():
                parts.append(f"    {ins.get_name()} {ins.get_output()}")
        if parts:
            return "\n".join(parts)
    return None


def _slice_java(java_text: str, method: str) -> list[str]:
    """Best-effort brace-matched extraction of each *definition* named ``method``.

    Matches only method definitions, never call sites.  A bare call such as
    ``x = encrypt(str);`` is preceded by whitespace (so the ``(?<!\\.)`` lookbehind
    alone would still match it); we additionally require that the parameter-list
    parentheses are followed by an optional ``throws`` clause and then a ``{``
    body.  A call site is followed by ``;``/``.``/``)`` and is skipped.
    """
    out: list[str] = []
    for m in re.finditer(rf"(?<!\.)\b{re.escape(method)}\s*\(", java_text):
        # Match the parameter-list parentheses to their close.
        depth, k = 1, m.end()
        while k < len(java_text) and depth:
            ch = java_text[k]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            k += 1
        if depth:  # unbalanced — not a well-formed signature
            continue
        # A definition has an optional throws clause then a '{' body.
        tail = re.match(r"\s*(?:throws\s+[\w.,\s]+?)?\{", java_text[k:])
        if not tail:
            continue
        body_open = k + tail.end() - 1  # index of the opening '{'
        start = java_text.rfind("\n", 0, m.start()) + 1
        depth, j = 0, body_open
        while j < len(java_text):
            c = java_text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    out.append(java_text[start : j + 1])
                    break
            j += 1
    return out


_PRIMITIVE_DESCRIPTORS = {
    "Z": "boolean", "B": "byte", "S": "short", "C": "char",
    "I": "int", "J": "long", "F": "float", "D": "double", "V": "void",
}


def _descriptor_params(signature: str) -> list[str] | None:
    """Parse parameter types out of a dalvik method descriptor.

    ``(Ljava/lang/String;I)[B`` -> ``["String", "int"]`` (simple names, so it
    can be compared against jadx's Java parameter list).  Returns None if the
    descriptor is malformed.
    """
    if "(" not in signature or ")" not in signature:
        return None
    inner = signature[signature.index("(") + 1 : signature.index(")")]
    params: list[str] = []
    i = 0
    while i < len(inner):
        dims = 0
        while i < len(inner) and inner[i] == "[":
            dims += 1
            i += 1
        if i >= len(inner):
            return None
        c = inner[i]
        if c == "L":
            end = inner.find(";", i)
            if end == -1:
                return None
            name = inner[i + 1 : end].split("/")[-1]
            i = end + 1
        elif c in _PRIMITIVE_DESCRIPTORS:
            name = _PRIMITIVE_DESCRIPTORS[c]
            i += 1
        else:
            return None
        params.append(name + "[]" * dims)
    return params


def _split_top_level(s: str) -> list[str]:
    """Split ``s`` on commas that are not nested inside ``<>`` or ``()``."""
    out: list[str] = []
    depth, cur = 0, []
    for ch in s:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _java_param_types(slice_text: str) -> list[str]:
    """Extract normalized parameter type names from a definition slice.

    ``... encrypt(String str, int rounds) {`` -> ``["String", "int"]``.
    """
    open_paren = slice_text.find("(")
    if open_paren == -1:
        return []
    depth, k = 1, open_paren + 1
    while k < len(slice_text) and depth:
        if slice_text[k] == "(":
            depth += 1
        elif slice_text[k] == ")":
            depth -= 1
        k += 1
    inner = slice_text[open_paren + 1 : k - 1].strip()
    if not inner:
        return []
    types: list[str] = []
    for raw in _split_top_level(inner):
        tokens = raw.strip().split()
        # Drop the parameter name (last token) and any modifiers (e.g. 'final').
        type_tokens = [t for t in tokens[:-1] if t != "final"]
        if not type_tokens:
            continue
        t = re.sub(r"<[^>]*>", "", type_tokens[-1])  # strip generics
        base = t.split("[")[0].split(".")[-1]
        dims = t.count("[")
        types.append(base + "[]" * dims)
    return types


def _select_by_signature(slices: list[str], signature: str) -> str | None:
    """Return the slice whose parameter types match ``signature``, else None."""
    want = _descriptor_params(signature)
    if want is None:
        return None
    for s in slices:
        if _java_param_types(s) == want:
            return s
    return None


def _guard_apk_path(path: str) -> None:
    """Reject APK paths that start with '-' to prevent flag injection.

    jadx 1.5.0 does not support the POSIX '--' end-of-options separator, so
    we use a path check instead.  The path should never start with '-' because
    it was already validated by the APK loader, but we enforce it explicitly
    here as a defence-in-depth measure.
    """
    if path.startswith("-"):
        raise ValueError(f"APK path must not start with '-': {path!r}")


def _jadx_class(state, cls: str, cfg) -> str:
    """Decompile the containing class with jadx and return the Java source.

    Security guards applied:
    - argv list, shell=False (no shell injection)
    - APK path validated not to start with '-'
    - stdout capped at cfg.jadx_stdout_cap bytes
    - output directory created via mkdtemp (unpredictable, mode 0700)
    - directory always cleaned up in a finally block
    """
    _guard_apk_path(state.path)
    outdir = Path(tempfile.mkdtemp(prefix="pare-static-"))
    try:
        # jadx 1.5.0 does not support '--' end-of-options; APK path is
        # pre-validated above so positional placement is safe.
        cmd = [
            cfg.jadx_path,
            "--rename-flags", "none",
            "--no-res",
            "--single-class", cls,
            "-d", str(outdir),
            state.path,
        ]
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            timeout=cfg.jadx_timeout_s,
            text=True,
        )
        java_files = list(outdir.rglob("*.java"))
        if not java_files:
            stderr_snippet = proc.stderr[-1000:] if proc.stderr else ""
            raise RuntimeError(
                f"jadx produced no source (rc={proc.returncode}): {stderr_snippet}"
            )
        return max(java_files, key=lambda p: p.stat().st_size).read_text(
            errors="replace")[: cfg.jadx_stdout_cap]
    finally:
        shutil.rmtree(outdir, ignore_errors=True)


def decompile(state, cls: str, method: str, signature: str, lang: str, cfg) -> dict:
    """Decompile ``method`` from ``cls``.

    Args:
        state: APKState with loaded androguard analysis.
        cls: Dotted FQCN of the containing class.
        method: Method name (not including descriptor).
        signature: Optional descriptor to disambiguate overloads (best-effort).
        lang: ``"smali"`` for androguard smali, ``"java"`` for jadx Java.
        cfg: Config instance.

    Returns:
        Dict with keys ``class``, ``method``, ``lang``, and either ``source``
        (single method) or ``overloads`` (list of strings, multiple matches).

    Raises:
        LookupError: Method or class not found.
        RuntimeError: jadx subprocess failed.
    """
    if lang == "smali":
        src = _smali_source(state, cls, method)
        if src is None:
            raise LookupError(f"{cls}.{method} not found in smali")
        return {"class": cls, "method": method, "lang": "smali", "source": src}

    # lang == "java"
    java = _jadx_class(state, cls, cfg)
    slices = _slice_java(java, method)
    if not slices:
        raise LookupError(f"{method} not found in decompiled {cls}")
    if len(slices) == 1:
        return {"class": cls, "method": method, "lang": "java", "source": slices[0]}
    # Multiple definitions: use the caller-supplied descriptor to select one.
    if signature:
        selected = _select_by_signature(slices, signature)
        if selected is not None:
            return {"class": cls, "method": method, "lang": "java", "source": selected}
    # No signature, or it matched nothing — present the overloads rather than
    # silently returning an arbitrary (possibly wrong) slice.
    return {
        "class": cls,
        "method": method,
        "lang": "java",
        "overloads": slices,
        "summary_note": "multiple overloads found; pass signature= to select one",
    }
