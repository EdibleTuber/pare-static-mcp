from __future__ import annotations
import os
from pathlib import Path
import pytest

_DEFAULT = "/home/edible/Projects/bsides/off_the_leash/MSTG-Android-Java.apk"

TEST_PACKAGE = "sg.vp.owasp_mobile.omtg_android"
TEST_CLASS = "sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_001_KeyStore"
TEST_METHOD = "encryptString"
TEST_DESCRIPTOR = "(Ljava/lang/String;)V"
TEST_STRING = "Dummy"

def apk_path() -> Path:
    return Path(os.environ.get("PARE_STATIC_TEST_APK", _DEFAULT))

def test_apk() -> Path:
    p = apk_path()
    if not p.is_file():
        pytest.skip(f"test APK not present at {p} (set PARE_STATIC_TEST_APK)")
    return p
test_apk.__test__ = False

requires_apk = pytest.mark.skipif(
    not apk_path().is_file(),
    reason="OMTG test APK not present (set PARE_STATIC_TEST_APK)",
)
