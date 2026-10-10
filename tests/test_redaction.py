from mcp_security.redaction import redact_sensitive_text, redact_sensitive_value


def test_redact_url_userinfo_and_sensitive_query_values():
    text = (
        "endpoint=https://test-user:pw_SENTINEL_123456789@api.example.com/mcp"
        "?api_key=QUERY_SENTINEL_abcdef0123456789&mode=read"
    )
    redacted = redact_sensitive_text(text)

    assert "test-user" not in redacted
    assert "pw_SENTINEL_123456789" not in redacted
    assert "QUERY_SENTINEL_abcdef0123456789" not in redacted
    assert "[REDACTED]" in redacted
    assert "mode=read" in redacted
    assert "api.example.com/mcp" in redacted


def test_redact_bearer_and_basic_auth_values():
    value = (
        "Authorization: Bearer HEADER_SENTINEL_abcdef0123456789; "
        "Basic BASIC_SENTINEL_abcdef0123456789"
    )
    redacted = redact_sensitive_text(value)

    assert "HEADER_SENTINEL" not in redacted
    assert "BASIC_SENTINEL" not in redacted
    assert redacted.count("[REDACTED]") == 2


def test_redact_recursive_metadata_but_keep_non_sensitive_values():
    value = {
        "url": "https://example.com/mcp?token=TOKEN_SENTINEL_abcdef0123456789",
        "labels": ["mode=read", "Authorization: Bearer HEADER_SENTINEL_abcdef0123456789"],
        "count": 2,
    }
    redacted = redact_sensitive_value(value)

    assert "TOKEN_SENTINEL" not in str(redacted)
    assert "HEADER_SENTINEL" not in str(redacted)
    assert redacted["labels"][0] == "mode=read"
    assert redacted["count"] == 2
