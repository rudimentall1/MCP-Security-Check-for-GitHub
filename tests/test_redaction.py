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


def test_recursive_metadata_redacts_short_secrets_by_field_name():
    runtime_reference = "$" + "{input:accessToken}"
    value = {
        "api_key": "SHORT_API_KEY_SENTINEL",
        "nested": {
            "Authorization": "SHORT_AUTH_SENTINEL",
            "password": "pw123",
            "clientSecret": "short-secret",
            "mode": "read",
            "runtime_token": runtime_reference,
            "placeholder_key": "changeme",
        },
        "headers": [
            {"x-api-key": "HEADER_KEY_SENTINEL", "X-Mode": "safe"},
        ],
    }

    redacted = redact_sensitive_value(value)
    serialized = str(redacted)

    for secret in (
        "SHORT_API_KEY_SENTINEL",
        "SHORT_AUTH_SENTINEL",
        "pw123",
        "short-secret",
        "HEADER_KEY_SENTINEL",
    ):
        assert secret not in serialized
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["nested"]["Authorization"] == "[REDACTED]"
    assert redacted["nested"]["password"] == "[REDACTED]"
    assert redacted["nested"]["clientSecret"] == "[REDACTED]"
    assert redacted["nested"]["mode"] == "read"
    assert redacted["nested"]["runtime_token"] == runtime_reference
    assert redacted["nested"]["placeholder_key"] == "changeme"
    assert redacted["headers"][0]["X-Mode"] == "safe"


def test_recursive_metadata_does_not_confuse_benign_field_names_with_secrets():
    value = {
        "tokenizer": "short ordinary value",
        "monkey": "banana",
        "mode": "read",
    }

    assert redact_sensitive_value(value) == value


def test_recursive_metadata_sanitizes_sensitive_values_inside_report_metadata():
    from mcp_security.model.finding import Finding, Severity

    finding = Finding(
        rule_id="MSC002-LITERAL",
        title="Possible Hardcoded Secret",
        severity=Severity.MEDIUM,
        description="Review config metadata",
        evidence="field detected",
        file="mcp.json",
        remediation="Rotate the value",
        metadata={
            "server": {
                "api_key": "RAW_METADATA_SECRET_SENTINEL",
                "authorization": "RAW_AUTH_METADATA_SENTINEL",
                "log_level": "debug",
            }
        },
    )

    serialized = str(finding.to_dict())
    assert "RAW_METADATA_SECRET_SENTINEL" not in serialized
    assert "RAW_AUTH_METADATA_SENTINEL" not in serialized
    assert finding.metadata["server"]["api_key"] == "[REDACTED]"
    assert finding.metadata["server"]["authorization"] == "[REDACTED]"
    assert finding.metadata["server"]["log_level"] == "debug"

