"""Regression tests for literal credentials embedded in MCP server URLs."""

from mcp_security.analyzers.secrets import find_hardcoded_url_credentials


def test_common_api_credential_parameter_names_are_detected():
    parameter_names = (
        "key",
        "api-key",
        "x-api-key",
        "subscription_key",
        "oauth_token",
        "github_token",
        "clientSecret",
        "X-Amz-Signature",
        "private_key",
    )
    for name in parameter_names:
        findings = find_hardcoded_url_credentials(
            f"https://mcp.example.test/server?{name}=sampleCredentialValue123"
        )
        assert len(findings) == 1, name
        assert findings[0][0].startswith("url.query."), name


def test_fragment_credential_parameter_is_detected():
    findings = find_hardcoded_url_credentials(
        "https://mcp.example.test/server#access_token=sampleCredentialValue123"
    )
    assert len(findings) == 1
    assert findings[0][0] == "url.fragment.access_token"


def test_userinfo_password_detects_even_short_literal_values():
    findings = find_hardcoded_url_credentials(
        "https://user:pw123@mcp.example.test/server"
    )
    assert findings == [("url.userinfo.password", "pw123")]


def test_runtime_references_and_placeholders_are_ignored():
    runtime_value = "$" + "{input:accessToken}"
    findings = find_hardcoded_url_credentials(
        "https://mcp.example.test/server?access_token=" + runtime_value
        + "&api_key=changeme&client_secret=your_api_key"
    )
    assert findings == []


def test_benign_parameter_names_do_not_match_sensitive_substrings():
    findings = find_hardcoded_url_credentials(
        "https://mcp.example.test/server?tokenizer=build123&monkey=banana&mode=read"
    )
    assert findings == []


def test_encoded_runtime_reference_is_ignored():
    findings = find_hardcoded_url_credentials(
        "https://mcp.example.test/server?access_token=%24%7Binput%3Atoken%7D"
    )
    assert findings == []


def test_multiple_credentials_are_reported_independently():
    findings = find_hardcoded_url_credentials(
        "https://user:pw123@mcp.example.test/server?api_key=key123&access_token=tok456"
    )
    assert [where for where, _ in findings] == [
        "url.userinfo.password",
        "url.query.api_key",
        "url.query.access_token",
    ]


def test_malformed_url_does_not_crash_or_emit_partial_credentials():
    # urlsplit raises ValueError for malformed bracketed hosts; the analyzer
    # must fail safely and let schema validation report the invalid URL.
    assert find_hardcoded_url_credentials(
        "https://[invalid-host?api_key=sampleSecret123"
    ) == []
