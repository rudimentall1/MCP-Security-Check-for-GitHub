"""Regression tests for short literals in credential-named fields."""

from mcp_security.analyzers.secrets import find_hardcoded_secret_like_values


def test_sensitive_key_names_detect_short_literal_values():
    values = {
        "API_KEY": "k7Q",
        "GITHUB_TOKEN": "t9",
        "PASSWORD": "pw1",
        "Authorization": "Bearer a7",
        "AWS_ACCESS_KEY_ID": "id123",
        "LOG_LEVEL": "debug",
        "APP_MODE": "production",
    }

    findings = dict(find_hardcoded_secret_like_values(values))

    assert findings == {
        "API_KEY": "k7Q",
        "GITHUB_TOKEN": "t9",
        "PASSWORD": "pw1",
        "Authorization": "Bearer a7",
        "AWS_ACCESS_KEY_ID": "id123",
    }


def test_sensitive_fields_ignore_runtime_references_and_placeholders():
    runtime_token = "$" + "{input:accessToken}"
    values = {
        "API_KEY": runtime_token,
        "TOKEN": "$" + "{env:GITHUB_TOKEN}",
        "PASSWORD": "changeme",
        "CLIENT_SECRET": "your_api_key",
        "AUTHORIZATION": "Bearer " + runtime_token,
        "NORMAL_VALUE": "literal-but-not-secret-shaped",
    }

    assert find_hardcoded_secret_like_values(values) == []


def test_weakly_named_values_still_use_token_shape_heuristic():
    long_literal = "TEST_SAMPLE_CREDENTIAL_abcdef0123456789"
    findings = find_hardcoded_secret_like_values({
        "CUSTOM_SETTING": long_literal,
        "LOG_LEVEL": "info",
    })

    assert findings == [("CUSTOM_SETTING", long_literal)]


def test_key_detection_does_not_match_unrelated_substrings():
    values = {
        "TOKENIZER": "short",
        "MONKEY": "short",
        "API_KEY_HINT": "short",
        "KEYBOARD_LAYOUT": "short",
        "APP_MODE": "production",
    }

    assert find_hardcoded_secret_like_values(values) == []
