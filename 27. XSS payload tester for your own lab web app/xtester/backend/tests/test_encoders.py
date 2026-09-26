import pytest

from app.engine.encoders import (
    ALL_ENCODERS,
    html_dec_encode,
    html_hex_encode,
    js_hex_escape,
    js_string_mutation,
    js_unicode_escape,
    url_encode,
)


def test_html_hex_encodes_special_chars():
    out = html_hex_encode("<script>")
    assert "&#x3c;" in out and "script" in out
    assert out != "<script>"


def test_html_dec_encode():
    out = html_dec_encode("<img")
    assert "&#60;" in out


def test_js_hex_escape():
    out = js_hex_escape("a<b")
    assert "\\x3c" in out


def test_js_unicode_escape():
    out = js_unicode_escape("a<b")
    assert "\\u003c" in out


def test_url_encode_roundtrip_mangled():
    out = url_encode("<script>alert(1)</script>")
    assert "script" not in out.split("%")[0]
    assert "%3C" in out.upper()


def test_js_string_mutation_keeps_execution_semantics():
    # "alert" mutated via \u sequences still evaluates to alert()
    out = js_string_mutation("alert(1)")
    assert out != "alert(1)"
    assert "\\u" in out or "\\x" in out


@pytest.mark.parametrize("name", list(ALL_ENCODERS))
def test_all_encoders_are_callable(name):
    fn = ALL_ENCODERS[name]
    assert callable(fn)
    assert isinstance(fn("<x>"), str)


def test_case_mix_keeps_target_letters():
    from app.engine.encoders import case_mix

    out = case_mix("<script>alert(1)</script>", "script")
    low = out.lower()
    assert low == "<script>alert(1)</script>"