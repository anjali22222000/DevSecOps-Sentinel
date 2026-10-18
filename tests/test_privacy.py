from sentinel.privacy import redact_url


def test_userinfo_is_redacted():
    out = redact_url("https://user:secret@pypi.example/simple")
    assert out == "https://***@pypi.example/simple"
    assert "secret" not in out


def test_token_only_userinfo_is_redacted():
    assert redact_url("https://TOKEN123@host.example/x") == "https://***@host.example/x"


def test_query_string_is_redacted():
    assert redact_url("https://host.example/x?token=abc") == "https://host.example/x?***"


def test_clean_url_unchanged():
    assert redact_url("https://pypi.org/simple") == "https://pypi.org/simple"
