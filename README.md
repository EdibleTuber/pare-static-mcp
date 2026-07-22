# pare-static-mcp

Static-analysis MCP worker for PARE (Android APK). Provides seven read-only tools that let an agent derive hook targets, string constants, and class structure from an APK without running it. All tools are risk tier `low`.

## Tools

| Tool | What it does |
|------|-------------|
| `load_apk` | Opens an APK file and sets it as the current analysis target; replaces any previously loaded APK. |
| `find_symbol` | Finds method definitions and/or callers by name across all classes (regex anchored). |
| `grep_smali` | Regex-searches raw Smali bytecode across all classes, returning matching lines with class/method context. |
| `list_methods` | Lists every method defined in a given class with name, descriptor, and access flags. |
| `extract_strings` | Extracts string constants from the DEX string pool; accepts an optional substring filter. |
| `decompile_method` | Returns Smali or Java source for a single method; Java requires an external `jadx` binary; Smali always works. |
| `read_manifest` | Parses `AndroidManifest.xml` and returns package name, permissions, components, and security-relevant flags. |

Tools surface to the model as `static_*` when mounted into PARE.

## Role in the RE loop

These tools serve the **front** of PARE's reverse-engineering loop ([Orient → Enumerate → Hypothesize → Verify → Re-orient](https://github.com/EdibleTuber/PARE#how-pare-works-the-re-loop)) — static analysis forms the hypothesis that dynamic analysis ([`pare-frida-mcp`](https://github.com/EdibleTuber/pare-frida-mcp)) later *confirms*, rather than re-discovers:

- **Orient** — `read_manifest` (entry points, components, security flags) and `extract_strings` (symptoms, hints) locate the region of code to investigate.
- **Enumerate** — `grep_smali` and `find_symbol` build the *candidate set*: the sites / API family that could produce the symptom, before committing to one. (A search that matches several near-duplicate classes is where PARE pauses to have the operator disambiguate.)
- **Hypothesize** — `list_methods` and `decompile_method` pin the exact target and the value you expect to observe at runtime.

Results larger than the inline budget come back as capture refs (PARE's capture layer); the agent reads them with `read_capture`. PARE is the hub that drives these tools and carries the loop — see [PARE](https://github.com/EdibleTuber/PARE).

## Single-APK-open model

Only one APK is held in memory at a time. `load_apk` atomically replaces the current target — each subsequent call closes the previous one. All other tools require `load_apk` to have been called first and will return an error envelope if no APK is loaded.

## Dependencies

**Python (pip):**

```
androguard==4.1.3
```

**External binary (for Java decompilation only):**

A `jadx` binary and a JRE are required to use `lang="java"` in `decompile_method`. Locate jadx via the `JADX_PATH` env var (default: `jadx` on `PATH`). If jadx is unavailable, `decompile_method` automatically degrades to Smali. All other tools, including Smali decompilation, work without jadx.

## Configuration

All configuration is through environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `JADX_PATH` | `jadx` | Path to the jadx binary (or just the name if it is on PATH). |
| `PARE_STATIC_JADX_TIMEOUT` | `120` | Seconds before a jadx subprocess is killed. |
| `PARE_STATIC_JADX_STDOUT_CAP` | `4000000` | Maximum bytes of jadx stdout retained (truncates beyond this). |
| `PARE_STATIC_MAX_APK_BYTES` | `524288000` | APKs larger than this (in bytes) are rejected before parsing (500 MB). |
| `PARE_STATIC_MAX_ZIP_ENTRIES` | `100000` | Zip-bomb guard: reject APKs with more entries than this. |
| `PARE_STATIC_MAX_DECOMPRESSED_BYTES` | `2147483648` | Decompression-amplification guard (2 GB). |

## Running tests

Install dev dependencies:

```bash
pip install -e ".[dev]"
```

Run the full suite against the MSTG-Android-Java reference APK:

```bash
PARE_STATIC_TEST_APK=/path/to/MSTG-Android-Java.apk pytest -v
```

To also exercise Java decompilation via jadx:

```bash
JADX_PATH=/path/to/jadx PARE_STATIC_TEST_APK=/path/to/MSTG-Android-Java.apk pytest -v
```

Any test marked `@requires_apk` is automatically skipped when `PARE_STATIC_TEST_APK` is unset or the file does not exist. The unit tests that use synthetic fixture APKs always run.

The integration test `tests/integration/test_keystore_chain.py::test_derive_target_chain` exercises the full derivation chain: `load_apk` → `find_symbol("encryptString")` → `decompile_method` (Smali) → `extract_strings("Dummy")`. Passing this test proves the KeyStore hook target is derivable from static output alone.

## Mounting into PARE

Add a `static:` entry under `workers:` in PARE's `workers.yaml`:

```yaml
workers:
  static:
    command: /path/to/venv/bin/pare-static-mcp
    transport: stdio
    risk_default: low
    capability_tags: [static, apk, android]
```

Replace the `command` path with wherever `pare-static-mcp` is installed (typically inside the PARE venv after `pip install -e /path/to/pare-static-mcp`). The tools will be available to the model as `static_load_apk`, `static_find_symbol`, etc.
