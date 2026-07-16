# tests/unit/test_sink_match.py
from __future__ import annotations
import pytest
from pare_static_mcp.apk import sink_match as sm


@pytest.mark.parametrize("sig,expected", [
    # dotted-Java, with params (params ignored)
    ("javax.crypto.CipherOutputStream.write(byte[] b)", ("Ljavax/crypto/CipherOutputStream;", "write")),
    # dotted, no params
    ("javax.crypto.Cipher.doFinal", ("Ljavax/crypto/Cipher;", "doFinal")),
    # smali arrow form with descriptor
    ("Ljavax/crypto/Cipher;->doFinal([B)[B", ("Ljavax/crypto/Cipher;", "doFinal")),
    # constructor
    ("java.lang.String.<init>(byte[])", ("Ljava/lang/String;", "<init>")),
    # nested/inner class ($ preserved)
    ("com.foo.Bar$1.onClick(android.view.View)", ("Lcom/foo/Bar$1;", "onClick")),
    # already-smali class, dotted method sep should not apply
    ("Landroid/util/Log;->e", ("Landroid/util/Log;", "e")),
])
def test_parse_sink_forms(sig, expected):
    assert sm.parse_sink(sig) == expected


@pytest.mark.parametrize("bad", ["", "   ", "NoMethodHere", "()"])
def test_parse_sink_rejects_unparseable(bad):
    assert sm.parse_sink(bad) is None


def test_edge_matches_class_and_method_only():
    parsed = sm.parse_sink("javax.crypto.Cipher.doFinal(byte[])")
    # androguard class_name is smali; different overload descriptor still matches (params ignored)
    assert sm.edge_matches(parsed, "Ljavax/crypto/Cipher;", "doFinal") is True
    assert sm.edge_matches(parsed, "Ljavax/crypto/Cipher;", "update") is False
    assert sm.edge_matches(parsed, "Ljavax/crypto/Mac;", "doFinal") is False
