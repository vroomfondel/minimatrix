"""JWT login via Keycloak Resource Owner Password Credentials (ROPC) grant.

Obtains a JWT access token from Keycloak's token endpoint and uses it to
authenticate against Synapse via ``com.famedly.login.token`` (synapse-token-authenticator).
"""

from __future__ import annotations

import aiohttp
from loguru import logger as glogger
from nio import AsyncClient, LoginResponse

logger = glogger.bind(classname="JWTLogin")


class JWTLoginError(Exception):
    """Base exception for JWT login failures."""


class JWTAuthError(JWTLoginError):
    """Authentication failure (bad credentials, ROPC disabled, missing role)."""


class JWTNetworkError(JWTLoginError):
    """Network-level failure during the JWT flow."""


class JWTLoginHandler:
    """Handles JWT login via Keycloak ROPC grant + Synapse JWT authentication.

    Supports these login types:
    - ``com.famedly.login.token.oauth``: synapse-token-authenticator with oauth: config (JWKS, default)
    - ``com.famedly.login.token``: synapse-token-authenticator with jwt: config (symmetric secret)
    - ``org.matrix.login.jwt``: native Synapse JWT (public key in homeserver.yaml)
    """

    def __init__(
        self,
        keycloak_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        login_type: str = "com.famedly.login.token.oauth",
    ) -> None:
        self.keycloak_url = keycloak_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.login_type = login_type

    async def obtain_jwt_token(self) -> str:
        """POST to Keycloak ROPC endpoint and return the ``access_token`` JWT.

        Raises
        ------
        JWTAuthError
            On authentication failure (401, 400).
        JWTNetworkError
            On network-level failure.
        JWTLoginError
            On unexpected responses.
        """
        token_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
        data: dict[str, str] = {
            "grant_type": "password",
            "client_id": self.client_id,
            "username": self.username,
            "password": self.password,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret

        logger.debug("Requesting ROPC token from {}", token_url)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(token_url, data=data) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        access_token = body.get("access_token")
                        if not access_token:
                            raise JWTLoginError("Keycloak response missing access_token")
                        logger.info("JWT access token obtained successfully")
                        return str(access_token)

                    if resp.status == 401:
                        raise JWTAuthError("Keycloak authentication failed: invalid credentials")

                    if resp.status == 400:
                        try:
                            body = await resp.json()
                            desc = body.get("error_description", body.get("error", "Bad request"))
                        except Exception:
                            desc = "Bad request"
                        raise JWTAuthError(f"Keycloak token request failed: {desc}")

                    raise JWTLoginError(f"Unexpected Keycloak response: HTTP {resp.status}")
        except JWTLoginError:
            raise
        except aiohttp.ClientError as exc:
            raise JWTNetworkError(f"Network error during JWT token request: {exc}") from exc

    async def perform_login(self, client: AsyncClient) -> LoginResponse:
        """Obtain a JWT token and authenticate the Matrix client.

        Returns
        -------
        LoginResponse
            The successful login response from the Matrix client.

        Raises
        ------
        JWTLoginError
            On any failure during the JWT flow.
        JWTAuthError
            On authentication failure.
        """
        jwt_token = await self.obtain_jwt_token()

        if self.login_type in ("com.famedly.login.token.oauth", "com.famedly.login.token"):
            # synapse-token-authenticator: both oauth: and jwt: configs use same payload structure
            login_body = {
                "type": self.login_type,
                "identifier": {"type": "m.id.user", "user": self.username},
                "token": jwt_token,
                "initial_device_display_name": "minimatrix",
            }
        else:  # org.matrix.login.jwt
            login_body = {
                "type": "org.matrix.login.jwt",
                "token": jwt_token,
                "initial_device_display_name": "minimatrix",
            }

        resp = await client.login_raw(login_body)

        if isinstance(resp, LoginResponse):
            return resp

        raise JWTLoginError(f"Matrix JWT login failed: {resp}")
