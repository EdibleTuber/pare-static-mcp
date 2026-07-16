from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CONTRACT_VERSION = 1

_BOUNDED_OUT = {"type": "object", "properties": {"summary": {"type": "string"}}}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    risk_tier: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] = field(default_factory=lambda: dict(_BOUNDED_OUT))


def _in(**props) -> dict[str, Any]:
    return {"type": "object", "properties": props}


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec("load_apk", "low",
             "STATIC (reads the APK file; no device/attach). Load an APK from a "
             "host path and make it the current target (replaces any previously "
             "loaded APK). Returns package, sdk versions, class/dex counts, "
             "native_libs, and dynamic_load indicators (DexClassLoader/loadLibrary) "
             "- when those are present, static analysis is partially blind and you "
             "should corroborate with the frida (dynamic) worker.",
             _in(path={"type": "string"})),
    ToolSpec("find_symbol", "low",
             "STATIC. Find a Java METHOD by NAME via cross-references - "
             "NOT string literals (for a string constant use static_extract_strings; "
             "for an API/text pattern use static_grep_smali). Returns rows of "
             "{class, method, signature, kind}; kind='def' is the implementation "
             "(feed its class+method+signature to static_decompile_method), "
             "kind='caller' is who invokes it. kind defaults to 'def'. Pass 'cls' "
             "to scope the search to one class.",
             _in(symbol={"type": "string"},
                 kind={"type": "string", "enum": ["def", "caller", "both"]},
                 cls={"type": "string"})),
    ToolSpec("grep_smali", "low",
             "STATIC. Regex search over smali instructions and the DEX string pool "
             "- reaches API/text patterns that find_symbol (name xref) cannot, e.g. "
             "'Ljavax/crypto/CipherOutputStream;->write'. Returns rows of "
             "{class, method, insn, match}. On a real APK pass a specific pattern; "
             "broad patterns are captured and slow to page.",
             _in(pattern={"type": "string"})),
    ToolSpec("list_methods", "low",
             "STATIC. List the methods of ONE class (to find a class or a symbol "
             "use static_find_symbol). Returns rows of {method, descriptor, flags, "
             "xref_count}; use this to choose a hook/decompile target without "
             "decompiling the whole class.",
             _in(cls={"type": "string"})),
    ToolSpec("extract_strings", "low",
             "STATIC. Extract string/constant literals from the DEX string pool "
             "(NOT resources.arsc/assets). Returns rows of {value, class, method, "
             "kind, source}; source='dex'. Pass 'filter' (substring) on a real APK "
             "- unfiltered results are captured and slow to page.",
             _in(filter={"type": "string"})),
    ToolSpec("decompile_method", "low",
             "STATIC. Decompile a single method to readable Java (jadx) or smali. "
             "Pass class+method; pass 'signature' (the descriptor from a find_symbol "
             "row) to disambiguate overloads - if omitted and the method is "
             "overloaded, all overloads are returned. lang='java' (default) or "
             "'smali' (no jadx needed).",
             _in(cls={"type": "string"}, method={"type": "string"},
                 signature={"type": "string"},
                 lang={"type": "string", "enum": ["java", "smali"]})),
    ToolSpec("read_manifest", "low",
             "STATIC. Parse AndroidManifest: package, permissions, "
             "activities/services/receivers/providers, application_class (a prime "
             "init/hook target), exported components (pre-31 intent-filter rule "
             "applied), debuggable, allow_backup.",
             _in()),
    ToolSpec("callers_of", "low",
             "STATIC. Multi-hop REVERSE reachability: methods that transitively CALL "
             "the target (generalizes find_symbol kind=caller to N hops). Rows of "
             "{class, method, signature, depth, frontier}; frontier=true means the "
             "method has no static caller (a framework-dispatched callback like onClick "
             "- the honest edge of static knowledge, where you hook and let Frida "
             "confirm). depth defaults to 3, capped at 12.",
             _in(method={"type": "string"}, cls={"type": "string"},
                 signature={"type": "string"}, depth={"type": "integer"})),
    ToolSpec("paths_between", "low",
             "STATIC. Shortest witness call-path from a source method to a target "
             "method (forward). Returns 'path' ordered source->target, or empty if "
             "unreachable within max_depth (control-flow only; reflection/callbacks are "
             "invisible - empty is not proof of safety). Use to confirm/expand a "
             "hypothesized route.",
             _in(from_method={"type": "string"}, from_cls={"type": "string"},
                 to_method={"type": "string"}, to_cls={"type": "string"},
                 from_signature={"type": "string"}, to_signature={"type": "string"},
                 max_depth={"type": "integer"})),
    ToolSpec("reachable_sinks", "low",
             "STATIC. Given dangerous SINK signatures (from PAL's sink catalog, dotted "
             "or smali), walk BACKWARD to the app methods that reach each sink - those "
             "are your hook candidates. Rows of {candidate, sink, path (candidate->sink), "
             "frontier}. Pass 'to' as a list of 'Class.method' strings. diagnostics "
             "reports unmatched_sinks, rejected_sinks, sink_source (provided|fallback), "
             "and an under_approximation note - an empty result is NOT proof of safety. "
             "Empty 'to' errors unless allow_fallback=true (a tiny generic catalog).",
             _in(to={"type": "array", "items": {"type": "string"}},
                 depth={"type": "integer"},
                 allow_fallback={"type": "boolean"})),
]


class WorkerContractAdapter:
    """Exposes the agent_core WorkerContract shape for assert_conformance."""

    def contract_version(self) -> int:
        return CONTRACT_VERSION

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {"name": s.name, "risk_tier": s.risk_tier,
             "input_schema": s.input_schema, "output_schema": s.output_schema}
            for s in TOOL_SPECS
        ]
