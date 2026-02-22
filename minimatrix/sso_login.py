"""SSO login via Keycloak OAuth Authorization Code flow.

Programmatically simulates the browser-based SSO redirect chain:
Synapse -> Keycloak login form -> credential submission -> Synapse OIDC callback -> login token.

.. warning::
    **DISCOURAGED** — This module relies on HTML parsing of Keycloak's login form,
    which is inherently fragile and may break with Keycloak upgrades or theme changes.

    **Prefer JWT authentication instead** (``AUTH_METHOD=jwt``), which uses the stable
    Keycloak ROPC token endpoint and synapse-token-authenticator for Matrix login.
    See the README for setup instructions.

    This SSO module exists for edge cases where JWT auth is not available, but should
    be considered a last resort.
"""

from __future__ import annotations

import html
import re
from urllib.parse import parse_qs, urlparse

import aiohttp
from loguru import logger as glogger
from nio import AsyncClient, LoginResponse

logger = glogger.bind(classname="SSOLogin")

# Redirect URL that is never actually reached — we capture the Location header.
_REDIRECT_URL = "http://localhost:0"

_MAX_REDIRECTS = 5


class SSOLoginError(Exception):
    """Base exception for SSO login failures."""


class SSOAuthError(SSOLoginError):
    """Authentication failure (bad credentials or missing role)."""


class SSONetworkError(SSOLoginError):
    """Network-level failure during the SSO flow."""


def parse_keycloak_form(page_html: str) -> tuple[str, dict[str, str]]:
    """Extract the form action URL and hidden fields from a Keycloak login page.

    Returns
    -------
    tuple[str, dict[str, str]]
        ``(action_url, hidden_fields)`` where *hidden_fields* maps field names to values.

    Raises
    ------
    SSOLoginError
        If the login form cannot be found in the HTML.
    """
    form_match = re.search(r'<form\s[^>]*id=["\']kc-form-login["\'][^>]*action=["\']([^"\']+)["\']', page_html)
    if not form_match:
        form_match = re.search(r"<form\s[^>]*action=[\"']([^\"']+)[\"'][^>]*id=[\"']kc-form-login[\"']", page_html)
    if not form_match:
        raise SSOLoginError("Could not find Keycloak login form in HTML response")

    action_url = html.unescape(form_match.group(1))

    hidden_fields: dict[str, str] = {}
    for m in re.finditer(
        r'<input\s[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
        page_html,
    ):
        hidden_fields[m.group(1)] = html.unescape(m.group(2))

    # Also match reversed attribute order (value before name)
    for m in re.finditer(
        r'<input\s[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']+)["\']',
        page_html,
    ):
        hidden_fields[m.group(2)] = html.unescape(m.group(1))

    return action_url, hidden_fields


def _extract_login_token(url: str) -> str | None:
    """Extract ``loginToken`` query parameter from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    tokens = params.get("loginToken", [])
    return tokens[0] if tokens else None


def _extract_error_message(page_html: str) -> str:
    """Try to extract an error message from a Keycloak error page."""
    # Keycloak renders errors in a span with class kc-feedback-text or in an alert div
    match = re.search(r'class=["\']kc-feedback-text["\'][^>]*>([^<]+)<', page_html)
    if match:
        return match.group(1).strip()
    match = re.search(r'class=["\']alert[^"\']*["\'][^>]*>([^<]+)<', page_html)
    if match and match.group(1).strip():
        return match.group(1).strip()
    if "access denied" in page_html.lower():
        return "Access denied (check that the user has the required role)"
    return "Authentication failed"


class SSOLoginHandler:
    """Handles the SSO login flow against a Synapse homeserver with a Keycloak IdP."""

    def __init__(self, homeserver: str, idp_id: str, username: str, password: str) -> None:
        self.homeserver = homeserver.rstrip("/")
        self.idp_id = idp_id
        self.username = username
        self.password = password

    async def obtain_login_token(self) -> str:
        """Run the full SSO redirect chain and return a Matrix login token.

        Raises
        ------
        SSOLoginError
            On any failure during the SSO flow.
        """
        jar = aiohttp.CookieJar(unsafe=True)
        try:
            async with aiohttp.ClientSession(cookie_jar=jar) as session:
                return await self._do_sso_flow(session)
        except SSOLoginError:
            raise
        except aiohttp.ClientError as exc:
            raise SSONetworkError(f"Network error during SSO flow: {exc}") from exc

    async def _do_sso_flow(self, session: aiohttp.ClientSession) -> str:
        # Step 1: GET the SSO redirect endpoint on Synapse
        sso_url = f"{self.homeserver}/_matrix/client/v3/login/sso/redirect/{self.idp_id}"
        logger.debug("Step 1: GET {}", sso_url)

        async with session.get(sso_url, params={"redirectUrl": _REDIRECT_URL}, allow_redirects=False) as resp:
            if resp.status == 404:
                raise SSOLoginError(
                    f"IDP '{self.idp_id}' not found on homeserver (404). "
                    f"Check SSO_IDP_ID and Synapse oidc_providers configuration."
                )
            if resp.status not in (301, 302, 303, 307, 308):
                raise SSOLoginError(f"Expected redirect from SSO endpoint, got HTTP {resp.status}")
            keycloak_auth_url = resp.headers["Location"]
            logger.debug("Step 1 redirect -> {}", keycloak_auth_url)

        # Step 2: GET the Keycloak auth URL to obtain the login form
        logger.debug("Step 2: GET Keycloak auth URL")
        async with session.get(keycloak_auth_url, allow_redirects=True) as resp:
            if resp.status != 200:
                raise SSOLoginError(f"Keycloak auth page returned HTTP {resp.status}")
            login_page_html = await resp.text()

        # Step 3: Parse form action and hidden fields
        form_action, hidden_fields = parse_keycloak_form(login_page_html)
        logger.debug("Step 3: form action={}, hidden fields={}", form_action, list(hidden_fields.keys()))

        # Step 4: POST credentials to the Keycloak form
        form_data = {**hidden_fields, "username": self.username, "password": self.password}
        logger.debug("Step 4: POST credentials to {}", form_action)

        async with session.post(form_action, data=form_data, allow_redirects=False) as resp:
            if resp.status == 200:
                # Re-rendered form means auth failure
                error_html = await resp.text()
                error_msg = _extract_error_message(error_html)
                raise SSOAuthError(f"Keycloak authentication failed: {error_msg}")
            if resp.status not in (301, 302, 303, 307, 308):
                raise SSOLoginError(f"Unexpected response from Keycloak login: HTTP {resp.status}")
            callback_url = resp.headers["Location"]
            logger.debug("Step 4 redirect -> {}", callback_url)

        # Step 5: Follow redirects through Synapse OIDC callback until we get loginToken
        for i in range(_MAX_REDIRECTS):
            # Check if this URL already contains the loginToken
            token = _extract_login_token(callback_url)
            if token:
                logger.info("SSO login token obtained successfully")
                return token

            logger.debug("Step 5.{}: GET {}", i + 1, callback_url)
            async with session.get(callback_url, allow_redirects=False) as resp:
                if resp.status not in (301, 302, 303, 307, 308):
                    raise SSOLoginError(f"Expected redirect during OIDC callback chain, got HTTP {resp.status}")
                callback_url = resp.headers["Location"]
                logger.debug("Step 5.{} redirect -> {}", i + 1, callback_url)

            # Check the new redirect target for the login token
            token = _extract_login_token(callback_url)
            if token:
                logger.info("SSO login token obtained successfully")
                return token

        raise SSOLoginError(f"Login token not found after {_MAX_REDIRECTS} redirects")

    async def perform_login(self, client: AsyncClient) -> LoginResponse:
        """Perform the full SSO login and authenticate the Matrix client.

        Returns
        -------
        LoginResponse
            The successful login response from the Matrix client.

        Raises
        ------
        SSOLoginError
            On any failure during the SSO flow.
        SSOAuthError
            On authentication failure (bad credentials or missing role).
        """
        login_token = await self.obtain_login_token()

        resp = await client.login_raw(
            {
                "type": "m.login.token",
                "token": login_token,
                "initial_device_display_name": "minimatrix",
            }
        )

        if isinstance(resp, LoginResponse):
            return resp

        raise SSOLoginError(f"Matrix token login failed: {resp}")
