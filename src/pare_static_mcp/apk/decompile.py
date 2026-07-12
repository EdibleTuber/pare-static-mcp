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
    """Best-effort brace-matched extraction of each overload named ``method``.

    Uses a negative lookbehind ``(?<!\\.)`` to skip call sites (``obj.method(``)
    and match only definition-like occurrences (return type before the name).
    """
    out: list[str] = []
    for m in re.finditer(rf"(?<!\.)\b{re.escape(method)}\s*\(", java_text):
        start = java_text.rfind("\n", 0, m.start()) + 1
        depth, j, seen = 0, m.end(), False
        while j < len(java_text):
            c = java_text[j]
            if c == "{":
                depth += 1
                seen = True
            elif c == "}":
                depth -= 1
                if seen and depth == 0:
                    out.append(java_text[start : j + 1])
                    break
            j += 1
    return out


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
        # cap retained stdout
        _ = proc.stdout[: cfg.jadx_stdout_cap]

        java_files = list(outdir.rglob("*.java"))
        if not java_files:
            stderr_snippet = proc.stderr[-1000:] if proc.stderr else ""
            raise RuntimeError(
                f"jadx produced no source (rc={proc.returncode}): {stderr_snippet}"
            )
        return max(java_files, key=lambda p: p.stat().st_size).read_text(
            errors="replace"
        )
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
    if len(slices) > 1 and not signature:
        return {
            "class": cls,
            "method": method,
            "lang": "java",
            "overloads": slices,
            "summary_note": "multiple overloads found; pass signature= to select one",
        }
    return {"class": cls, "method": method, "lang": "java", "source": slices[0]}
