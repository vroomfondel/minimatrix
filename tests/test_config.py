"""Tests for minimatrix.config — MiniMatrixConfig.from_env() and helpers."""

from __future__ import annotations

import os

import pytest

from minimatrix.config import MiniMatrixConfig, _parse_bool

# ---------------------------------------------------------------------------
# _parse_bool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("YES", True),
        ("  true  ", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("", False),
        ("nope", False),
    ],
)
def test_parse_bool(value: str, expected: bool) -> None:
    """Verifies that _parse_bool correctly converts common truthy and falsy string values."""
    assert _parse_bool(value) is expected


# ---------------------------------------------------------------------------
# MiniMatrixConfig.from_env — happy path
# ---------------------------------------------------------------------------


def test_from_env_password_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Minimal required env vars produce a valid config with password auth."""
    monkeypatch.setenv("MATRIX_USER", "testuser")
    monkeypatch.setenv("MATRIX_PASSWORD", "secret")
    # clear any leftovers
    for key in ("MATRIX_HOMESERVER", "AUTH_METHOD", "CRYPTO_STORE_PATH"):
        monkeypatch.delenv(key, raising=False)

    cfg = MiniMatrixConfig.from_env()

    assert cfg.matrix_user == "testuser"
    assert cfg.matrix_password == "secret"
    assert cfg.matrix_homeserver == "https://matrix.org"
    assert cfg.auth_method == "password"
    assert cfg.crypto_store_path == "~/.local/share/minimatrix/crypto_store"
    assert cfg.sso_idp_id == "keycloak"


def test_from_env_custom_homeserver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that a custom MATRIX_HOMESERVER env var overrides the default value."""
    monkeypatch.setenv("MATRIX_USER", "bot")
    monkeypatch.setenv("MATRIX_PASSWORD", "pw")
    monkeypatch.setenv("MATRIX_HOMESERVER", "https://my.server.com")
    monkeypatch.delenv("AUTH_METHOD", raising=False)

    cfg = MiniMatrixConfig.from_env()
    assert cfg.matrix_homeserver == "https://my.server.com"


def test_from_env_jwt_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """JWT auth requires keycloak env vars and sets them on config."""
    monkeypatch.setenv("MATRIX_USER", "bot")
    monkeypatch.setenv("MATRIX_PASSWORD", "pw")
    monkeypatch.setenv("AUTH_METHOD", "jwt")
    monkeypatch.setenv("KEYCLOAK_URL", "https://kc.example.com")
    monkeypatch.setenv("KEYCLOAK_REALM", "matrix")
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "synapse-oauth")
    monkeypatch.setenv("KEYCLOAK_CLIENT_SECRET", "s3cret")
    monkeypatch.delenv("JWT_LOGIN_TYPE", raising=False)

    cfg = MiniMatrixConfig.from_env()
    assert cfg.auth_method == "jwt"
    assert cfg.keycloak_url == "https://kc.example.com"
    assert cfg.keycloak_realm == "matrix"
    assert cfg.keycloak_client_id == "synapse-oauth"
    assert cfg.keycloak_client_secret == "s3cret"
    assert cfg.jwt_login_type == "com.famedly.login.token.oauth"


# ---------------------------------------------------------------------------
# MiniMatrixConfig.from_env — validation errors
# ---------------------------------------------------------------------------


def test_from_env_missing_user(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that a missing MATRIX_USER env var raises a ValueError."""
    monkeypatch.delenv("MATRIX_USER", raising=False)
    monkeypatch.setenv("MATRIX_PASSWORD", "pw")
    with pytest.raises(ValueError, match="MATRIX_USER"):
        MiniMatrixConfig.from_env()


def test_from_env_missing_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that a missing MATRIX_PASSWORD env var raises a ValueError."""
    monkeypatch.setenv("MATRIX_USER", "bot")
    monkeypatch.delenv("MATRIX_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="MATRIX_PASSWORD"):
        MiniMatrixConfig.from_env()


def test_from_env_invalid_auth_method(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that an unrecognised AUTH_METHOD value raises a ValueError."""
    monkeypatch.setenv("MATRIX_USER", "bot")
    monkeypatch.setenv("MATRIX_PASSWORD", "pw")
    monkeypatch.setenv("AUTH_METHOD", "magic")
    with pytest.raises(ValueError, match="'password', 'sso', or 'jwt'"):
        MiniMatrixConfig.from_env()


def test_from_env_jwt_missing_keycloak_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that JWT auth without KEYCLOAK_URL raises a ValueError."""
    monkeypatch.setenv("MATRIX_USER", "bot")
    monkeypatch.setenv("MATRIX_PASSWORD", "pw")
    monkeypatch.setenv("AUTH_METHOD", "jwt")
    monkeypatch.delenv("KEYCLOAK_URL", raising=False)
    with pytest.raises(ValueError, match="KEYCLOAK_URL"):
        MiniMatrixConfig.from_env()


def test_from_env_jwt_missing_keycloak_realm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that JWT auth without KEYCLOAK_REALM raises a ValueError."""
    monkeypatch.setenv("MATRIX_USER", "bot")
    monkeypatch.setenv("MATRIX_PASSWORD", "pw")
    monkeypatch.setenv("AUTH_METHOD", "jwt")
    monkeypatch.setenv("KEYCLOAK_URL", "https://kc.example.com")
    monkeypatch.delenv("KEYCLOAK_REALM", raising=False)
    with pytest.raises(ValueError, match="KEYCLOAK_REALM"):
        MiniMatrixConfig.from_env()


def test_from_env_jwt_invalid_login_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that an unrecognised JWT_LOGIN_TYPE value raises a ValueError."""
    monkeypatch.setenv("MATRIX_USER", "bot")
    monkeypatch.setenv("MATRIX_PASSWORD", "pw")
    monkeypatch.setenv("AUTH_METHOD", "jwt")
    monkeypatch.setenv("KEYCLOAK_URL", "https://kc.example.com")
    monkeypatch.setenv("KEYCLOAK_REALM", "matrix")
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "client")
    monkeypatch.setenv("JWT_LOGIN_TYPE", "invalid.type")
    with pytest.raises(ValueError, match="JWT_LOGIN_TYPE"):
        MiniMatrixConfig.from_env()


def test_from_env_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    """Config dataclass is frozen — attributes cannot be reassigned."""
    monkeypatch.setenv("MATRIX_USER", "bot")
    monkeypatch.setenv("MATRIX_PASSWORD", "pw")
    monkeypatch.delenv("AUTH_METHOD", raising=False)
    cfg = MiniMatrixConfig.from_env()
    with pytest.raises(AttributeError):
        cfg.matrix_user = "other"  # type: ignore[misc]
