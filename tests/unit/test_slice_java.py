"""Unit tests for Java method slicing + overload selection in apk/decompile.py.

Regression coverage for the OMTG_DATAST_001_BadEncryption failure: the decompiler
matched a *call site* (``encrypt(str)`` inside ``verify``) as if it were a method
definition, and ``signature=`` was accepted but never used to select an overload.
These are pure-function tests — no APK or jadx required.
"""
from __future__ import annotations

import pytest

from pare_static_mcp.apk import decompile as dc


# jadx-style source: verify() CALLS encrypt(str); encrypt() is the real definition.
BAD_ENCRYPTION_JAVA = """\
package sg.vp.owasp_mobile.OMTG_Android;

public class OMTG_DATAST_001_BadEncryption {
    public static boolean verify(String str) {
        byte[] decode = Base64.decode("vJqfip28ioydips=", 0);
        byte[] encrypt = encrypt(str);
        if (encrypt.length != decode.length) {
            return false;
        }
        for (int i = 0; i < encrypt.length; i++) {
            if (encrypt[i] != decode[i]) {
                return false;
            }
        }
        return true;
    }

    private static byte[] encrypt(String str) {
        byte[] bytes = str.getBytes();
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (bytes[i] ^ 16);
            bytes[i] = (byte) ((~bytes[i]) & 255);
        }
        return bytes;
    }
}
"""

# A class with genuine overloads of the same method name.
OVERLOADED_JAVA = """\
public class Over {
    private static byte[] encrypt(String str) {
        return str.getBytes();
    }

    private static byte[] encrypt(String str, int rounds) {
        byte[] b = str.getBytes();
        return b;
    }
}
"""


# --- Bug A: _slice_java must skip call sites, keep only definitions ----------

def test_slice_java_ignores_bare_call_site():
    slices = dc._slice_java(BAD_ENCRYPTION_JAVA, "encrypt")
    # The call site lives inside verify() and touches decode.length; a definition
    # never does. No returned slice may be the call-site fragment.
    assert all("decode.length" not in s for s in slices), slices


def test_slice_java_returns_single_real_definition():
    slices = dc._slice_java(BAD_ENCRYPTION_JAVA, "encrypt")
    assert len(slices) == 1, slices
    assert "str.getBytes()" in slices[0]
    assert "(byte) (bytes[i] ^ 16)" in slices[0]


def test_slice_java_keeps_genuine_overloads():
    slices = dc._slice_java(OVERLOADED_JAVA, "encrypt")
    assert len(slices) == 2, slices
    assert any("int rounds" in s for s in slices)
    assert any("int rounds" not in s for s in slices)


# --- Bug B: _select_by_signature must pick the matching overload ------------

def test_select_by_signature_one_arg():
    slices = dc._slice_java(OVERLOADED_JAVA, "encrypt")
    sel = dc._select_by_signature(slices, "(Ljava/lang/String;)[B")
    assert sel is not None
    assert "int rounds" not in sel


def test_select_by_signature_two_args():
    slices = dc._slice_java(OVERLOADED_JAVA, "encrypt")
    sel = dc._select_by_signature(slices, "(Ljava/lang/String;I)[B")
    assert sel is not None
    assert "int rounds" in sel


def test_select_by_signature_no_match_returns_none():
    slices = dc._slice_java(OVERLOADED_JAVA, "encrypt")
    assert dc._select_by_signature(slices, "(I)[B") is None


# --- decompile() integration (jadx monkeypatched) ---------------------------

@pytest.fixture
def fake_jadx(monkeypatch):
    def _install(java_text):
        monkeypatch.setattr(dc, "_jadx_class", lambda state, cls, cfg: java_text)
    return _install


def test_decompile_returns_real_body_not_call_site(fake_jadx):
    fake_jadx(BAD_ENCRYPTION_JAVA)
    out = dc.decompile(object(), "Foo", "encrypt", "", "java", object())
    assert "overloads" not in out
    assert "str.getBytes()" in out["source"]
    assert "decode.length" not in out["source"]


def test_decompile_signature_selects_overload(fake_jadx):
    fake_jadx(OVERLOADED_JAVA)
    out = dc.decompile(object(), "Over", "encrypt", "(Ljava/lang/String;I)[B", "java", object())
    assert "overloads" not in out
    assert "int rounds" in out["source"]


def test_decompile_unmatched_signature_lists_overloads(fake_jadx):
    # A signature that matches nothing must NOT silently return slices[0];
    # fall back to presenting the overloads.
    fake_jadx(OVERLOADED_JAVA)
    out = dc.decompile(object(), "Over", "encrypt", "(I)[B", "java", object())
    assert "overloads" in out
    assert len(out["overloads"]) == 2
