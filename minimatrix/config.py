"""minimatrix configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _parse_bool(value: str) -> bool:
    """Parse a string into a boolean.

    Args:
        value: The string to evaluate. Truthy values are ``"true"``, ``"1"``,
            and ``"yes"`` (case-insensitive).

    Returns:
        True if value is a recognised truthy string, False otherwise.
    """
    return value.strip().lower() in ("true", "1", "yes")


@dataclass(frozen=True)
class MiniMatrixConfig:
    """Immutable configuration for the minimatrix CLI client.

    All values are sourced from environment variables via :meth:`from_env`.
    """

    matrix_homeserver: str
    matrix_user: str
    matrix_password: str
    crypto_store_path: str
    auth_method: str
    sso_idp_id: str
    keycloak_url: str
    keycloak_realm: str
    keycloak_client_id: str
    keycloak_client_secret: str
    jwt_login_type: str

    @classmethod
    def from_env(cls) -> MiniMatrixConfig:
        """Build a :class:`MiniMatrixConfig` from environment variables.

        Reads the following environment variables:

        - ``MATRIX_HOMESERVER`` (optional): Matrix homeserver URL
          (default ``"https://matrix.org"``).
        - ``MATRIX_USER`` (required): Matrix username localpart, e.g. ``"myuser"``.
        - ``MATRIX_PASSWORD`` (required): Matrix password.
        - ``CRYPTO_STORE_PATH`` (optional): Path for persistent E2E key storage
          (default ``"~/.local/share/minimatrix/crypto_store"``).
        - ``AUTH_METHOD`` (optional): One of ``"password"``, ``"sso"``, or ``"jwt"``
          (default ``"password"``).
        - ``SSO_IDP_ID`` (optional): SSO IdP identifier (default ``"keycloak"``).
        - ``KEYCLOAK_URL`` (required when ``AUTH_METHOD=jwt``): Keycloak base URL.
        - ``KEYCLOAK_REALM`` (required when ``AUTH_METHOD=jwt``): Keycloak realm name.
        - ``KEYCLOAK_CLIENT_ID`` (required when ``AUTH_METHOD=jwt``): Keycloak client ID.
        - ``KEYCLOAK_CLIENT_SECRET`` (optional): Keycloak client secret.
        - ``JWT_LOGIN_TYPE`` (optional): Matrix login type for JWT auth
          (default ``"com.famedly.login.token.oauth"``).

        Returns:
            A fully populated :class:`MiniMatrixConfig` instance.

        Raises:
            ValueError: If a required environment variable is missing, empty, or
                contains an invalid value.
        """
        matrix_user = os.environ.get("MATRIX_USER", "").strip()
        if not matrix_user:
            raise ValueError("MATRIX_USER environment variable is required")

        matrix_password = os.environ.get("MATRIX_PASSWORD", "").strip()
        if not matrix_password:
            raise ValueError("MATRIX_PASSWORD environment variable is required")

        auth_method = os.environ.get("AUTH_METHOD", "password").strip().lower()
        if auth_method not in ("password", "sso", "jwt"):
            raise ValueError(f"AUTH_METHOD must be 'password', 'sso', or 'jwt', got '{auth_method}'")

        keycloak_url = ""
        keycloak_realm = ""
        keycloak_client_id = ""
        keycloak_client_secret = ""
        jwt_login_type = ""
        if auth_method == "jwt":
            keycloak_url = os.environ.get("KEYCLOAK_URL", "").strip()
            if not keycloak_url:
                raise ValueError("KEYCLOAK_URL environment variable is required when AUTH_METHOD=jwt")
            keycloak_realm = os.environ.get("KEYCLOAK_REALM", "").strip()
            if not keycloak_realm:
                raise ValueError("KEYCLOAK_REALM environment variable is required when AUTH_METHOD=jwt")
            keycloak_client_id = os.environ.get("KEYCLOAK_CLIENT_ID", "").strip()
            if not keycloak_client_id:
                raise ValueError("KEYCLOAK_CLIENT_ID environment variable is required when AUTH_METHOD=jwt")
            keycloak_client_secret = os.environ.get("KEYCLOAK_CLIENT_SECRET", "").strip()
            jwt_login_type = os.environ.get("JWT_LOGIN_TYPE", "com.famedly.login.token.oauth").strip()
            valid_login_types = ("com.famedly.login.token.oauth", "com.famedly.login.token", "org.matrix.login.jwt")
            if jwt_login_type not in valid_login_types:
                raise ValueError(f"JWT_LOGIN_TYPE must be one of {valid_login_types}, got '{jwt_login_type}'")

        return cls(
            matrix_homeserver=os.environ.get("MATRIX_HOMESERVER", "https://matrix.org").strip(),
            matrix_user=matrix_user,
            matrix_password=matrix_password,
            crypto_store_path=os.environ.get("CRYPTO_STORE_PATH", "~/.local/share/minimatrix/crypto_store").strip(),
            auth_method=auth_method,
            sso_idp_id=os.environ.get("SSO_IDP_ID", "keycloak").strip(),
            keycloak_url=keycloak_url,
            keycloak_realm=keycloak_realm,
            keycloak_client_id=keycloak_client_id,
            keycloak_client_secret=keycloak_client_secret,
            jwt_login_type=jwt_login_type,
        )
