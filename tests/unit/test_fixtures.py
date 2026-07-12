from tests.fixtures.locate import apk_path, requires_apk, TEST_PACKAGE

@requires_apk
def test_apk_present():
    assert apk_path().stat().st_size > 0

def test_constants_shape():
    assert TEST_PACKAGE.startswith("sg.vp.owasp_mobile")
