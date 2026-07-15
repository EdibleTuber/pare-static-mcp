"""End-to-end KeyStore-chain integration test.

Proves §9's success criterion: the KeyStore hook target (encryptString) is
derivable from static analysis alone, without any runtime observation.

Chain: load_apk → find_symbol("encryptString") → take the def row →
decompile_method(smali, deterministic, no jadx) → assert method name in source;
extract_strings("Dummy") → assert alias found.
"""
from __future__ import annotations

import json

import pytest

from pare_static_mcp import tools
from tests.fixtures.locate import TEST_METHOD, TEST_STRING, requires_apk, test_apk


@requires_apk
@pytest.mark.asyncio
async def test_derive_target_chain():
    """Full KeyStore derivation chain passes with the MSTG-Android-Java APK."""
    # Step 1: load the APK
    load_out = json.loads(await tools.load_apk(str(test_apk())))
    assert load_out.get("error") is not True, f"load_apk failed: {load_out}"

    # Step 2: find the encryptString symbol (default kind=def)
    sym = json.loads(await tools.find_symbol(TEST_METHOD))
    assert sym.get("error") is not True, f"find_symbol failed: {sym}"
    assert len(sym["rows"]) > 0, "find_symbol returned no rows"

    # Step 3: grab the def row
    row = next(r for r in sym["rows"] if r["kind"] == "def")
    assert row["method"] == TEST_METHOD

    # Step 4: decompile via smali (deterministic; no jadx required)
    dec = json.loads(await tools.decompile_method(
        row["class"], row["method"], row["signature"], lang="smali"
    ))
    assert dec.get("error") is not True, f"decompile_method failed: {dec}"
    assert dec["lang"] == "smali"
    assert TEST_METHOD in dec["source"], (
        f"'{TEST_METHOD}' not found in smali source: {dec['source'][:200]}"
    )

    # Step 5: extract strings to confirm the KeyStore alias is present
    strings = json.loads(await tools.extract_strings(TEST_STRING))
    assert strings.get("error") is not True, f"extract_strings failed: {strings}"
    assert any(TEST_STRING in r["value"] for r in strings["rows"]), (
        f"'{TEST_STRING}' not found in extracted strings: {strings['rows'][:5]}"
    )
