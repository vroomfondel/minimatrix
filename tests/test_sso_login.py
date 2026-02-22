"""Tests for minimatrix.sso_login — pure HTML/URL parsing helpers."""

from __future__ import annotations

import pytest

from minimatrix.sso_login import (
    SSOLoginError,
    _extract_error_message,
    _extract_login_token,
    parse_keycloak_form,
)

# ---------------------------------------------------------------------------
# _extract_login_token
# ---------------------------------------------------------------------------


def test_extract_login_token_present() -> None:
    url = "https://matrix.example.com/_synapse/client/oidc/callback?loginToken=abc123xyz"
    assert _extract_login_token(url) == "abc123xyz"


def test_extract_login_token_missing() -> None:
    url = "https://matrix.example.com/_synapse/client/oidc/callback?other=value"
    assert _extract_login_token(url) is None


def test_extract_login_token_empty_url() -> None:
    assert _extract_login_token("https://example.com") is None


# ---------------------------------------------------------------------------
# parse_keycloak_form
# ---------------------------------------------------------------------------


def test_parse_keycloak_form_basic() -> None:
    """Standard Keycloak login form with id before action."""
    html = """
    <html><body>
    <form id="kc-form-login" action="https://kc.example.com/realms/matrix/login-actions/authenticate?code=abc">
        <input type="hidden" name="session_code" value="sess123">
        <input type="hidden" name="execution" value="exec456">
        <input type="text" name="username">
        <input type="password" name="password">
    </form>
    </body></html>
    """
    action, hidden = parse_keycloak_form(html)
    assert action == "https://kc.example.com/realms/matrix/login-actions/authenticate?code=abc"
    assert hidden == {"session_code": "sess123", "execution": "exec456"}


def test_parse_keycloak_form_action_before_id() -> None:
    """Handles reversed attribute order (action before id)."""
    html = """
    <form action="https://kc.example.com/login" id="kc-form-login">
        <input type="hidden" name="tab_id" value="t1">
    </form>
    """
    action, hidden = parse_keycloak_form(html)
    assert action == "https://kc.example.com/login"
    assert hidden == {"tab_id": "t1"}


def test_parse_keycloak_form_html_entities() -> None:
    """Action URL with HTML entities gets unescaped."""
    html = '<form id="kc-form-login" action="https://kc.example.com/login?a=1&amp;b=2"></form>'
    action, hidden = parse_keycloak_form(html)
    assert action == "https://kc.example.com/login?a=1&b=2"
    assert hidden == {}


def test_parse_keycloak_form_no_form_raises() -> None:
    """Raises SSOLoginError when no kc-form-login is found."""
    html = "<html><body><p>Not a login page</p></body></html>"
    with pytest.raises(SSOLoginError, match="Could not find Keycloak login form"):
        parse_keycloak_form(html)


def test_parse_keycloak_form_reversed_hidden_field_attrs() -> None:
    """Hidden fields with value before name are also parsed."""
    html = """
    <form id="kc-form-login" action="https://kc.example.com/login">
        <input type="hidden" value="val1" name="field1">
    </form>
    """
    action, hidden = parse_keycloak_form(html)
    assert hidden == {"field1": "val1"}


# ---------------------------------------------------------------------------
# _extract_error_message
# ---------------------------------------------------------------------------


def test_extract_error_message_kc_feedback() -> None:
    html = '<span class="kc-feedback-text">Invalid username or password.</span>'
    assert _extract_error_message(html) == "Invalid username or password."


def test_extract_error_message_alert() -> None:
    html = '<div class="alert alert-error">Account disabled</div>'
    assert _extract_error_message(html) == "Account disabled"


def test_extract_error_message_access_denied() -> None:
    html = "<html><body>Access Denied - you do not have the role</body></html>"
    assert "Access denied" in _extract_error_message(html)


def test_extract_error_message_fallback() -> None:
    html = "<html><body>Something went wrong</body></html>"
    assert _extract_error_message(html) == "Authentication failed"
