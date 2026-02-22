"""MatrixClientHandler — encapsulates Matrix client operations with E2E encryption.

Provides a clean interface for Matrix/Synapse interactions including authentication
(password, SSO, JWT), TOFU device trust, and encrypted messaging.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Sequence
from typing import Any

from loguru import logger as glogger
from nio import (
    AsyncClient,
    AsyncClientConfig,
    LocalProtocolError,
    LoginResponse,
    SyncResponse,
)

logger = glogger.bind(classname="MatrixClientHandler")


class MatrixClientHandler:
    """Encapsulates Matrix client operations with E2E encryption and TOFU device trust."""

    def __init__(self, homeserver: str, user: str, crypto_store_path: str) -> None:
        """Create a Matrix client with E2E encryption support.

        Parameters
        ----------
        homeserver
            Matrix homeserver URL.
        user
            Matrix username (localpart).
        crypto_store_path
            Path for persistent E2E key storage.
        """
        self._homeserver = homeserver
        self._user = user
        self._crypto_store_path = crypto_store_path

        os.makedirs(crypto_store_path, exist_ok=True)
        nio_config = AsyncClientConfig(
            encryption_enabled=True,
            store_sync_tokens=True,
        )
        self._client = AsyncClient(
            homeserver,
            user,
            store_path=crypto_store_path,
            config=nio_config,
        )

    @property
    def client(self) -> AsyncClient:
        """Return the underlying nio AsyncClient."""
        return self._client

    @property
    def user_id(self) -> str:
        """Return the authenticated user ID (e.g. @user:homeserver.com)."""
        return str(self._client.user_id)

    @property
    def rooms(self) -> dict[str, Any]:
        """Return the dict of joined rooms."""
        return dict(self._client.rooms)

    # -- Login methods ---------------------------------------------------------

    async def login(
        self,
        auth_method: str,
        password: str,
        sso_idp_id: str | None = None,
        keycloak_url: str | None = None,
        keycloak_realm: str | None = None,
        keycloak_client_id: str | None = None,
        keycloak_client_secret: str | None = None,
        jwt_login_type: str | None = None,
    ) -> None:
        """Log in to the Matrix homeserver and upload device keys.

        Parameters
        ----------
        auth_method
            One of "password", "sso", or "jwt".
        password
            Matrix password (also used for Keycloak ROPC in jwt/sso modes).
        sso_idp_id
            SSO IdP identifier (required for auth_method="sso").
        keycloak_url
            Keycloak base URL (required for auth_method="jwt").
        keycloak_realm
            Keycloak realm name (required for auth_method="jwt").
        keycloak_client_id
            Keycloak client ID (required for auth_method="jwt").
        keycloak_client_secret
            Keycloak client secret (optional, empty for public clients).
        jwt_login_type
            Matrix login type for JWT auth (default: "com.famedly.login.token.oauth").
        """
        login_info = f"method={auth_method}"
        if auth_method == "jwt":
            login_info += f", login_type={jwt_login_type}"
        logger.info(
            "Logging in as {} on {} ({})",
            self._user,
            self._homeserver,
            login_info,
        )

        if auth_method == "sso":
            resp = await self._login_sso(sso_idp_id or "keycloak", password)
        elif auth_method == "jwt":
            resp = await self._login_jwt(
                password=password,
                keycloak_url=keycloak_url or "",
                keycloak_realm=keycloak_realm or "",
                keycloak_client_id=keycloak_client_id or "",
                keycloak_client_secret=keycloak_client_secret or "",
                jwt_login_type=jwt_login_type or "com.famedly.login.token.oauth",
            )
        else:
            resp = await self._client.login(password, device_name="minimatrix")

        if isinstance(resp, LoginResponse):
            logger.info("Login OK  user_id={}  device_id={}", resp.user_id, resp.device_id)
        else:
            logger.error("Login failed: {}", resp)
            sys.exit(1)

        if self._client.should_upload_keys:
            logger.info("Uploading device keys ...")
            await self._client.keys_upload()

    async def _login_sso(self, idp_id: str, password: str) -> LoginResponse:
        """Perform SSO login via Keycloak and return the LoginResponse."""
        from minimatrix.sso_login import SSOLoginError, SSOLoginHandler

        handler = SSOLoginHandler(
            homeserver=self._homeserver,
            idp_id=idp_id,
            username=self._user,
            password=password,
        )
        try:
            return await handler.perform_login(self._client)
        except SSOLoginError as exc:
            logger.error("SSO login failed: {}", exc)
            sys.exit(1)

    async def _login_jwt(
        self,
        password: str,
        keycloak_url: str,
        keycloak_realm: str,
        keycloak_client_id: str,
        keycloak_client_secret: str,
        jwt_login_type: str,
    ) -> LoginResponse:
        """Perform JWT login via Keycloak ROPC grant and return the LoginResponse."""
        from minimatrix.jwt_login import JWTLoginError, JWTLoginHandler

        handler = JWTLoginHandler(
            keycloak_url=keycloak_url,
            realm=keycloak_realm,
            client_id=keycloak_client_id,
            client_secret=keycloak_client_secret,
            username=self._user,
            password=password,
            login_type=jwt_login_type,
        )
        try:
            return await handler.perform_login(self._client)
        except JWTLoginError as exc:
            logger.error("JWT login failed: {}", exc)
            sys.exit(1)

    # -- E2E Device Trust (TOFU) -----------------------------------------------

    async def trust_devices_for_user(self, user_id: str) -> None:
        """Auto-trust all devices of a given user (TOFU)."""
        if self._client.olm:
            self._client.olm.users_for_key_query.add(user_id)
        try:
            await self._client.keys_query()
        except LocalProtocolError:
            logger.debug("No key query required for {} — using existing device store", user_id)
        device_store = self._client.device_store
        if user_id not in device_store:
            return
        for device_id, olm_device in device_store[user_id].items():
            if not self._client.is_device_verified(olm_device):
                logger.info("Trusting device {} of {}", device_id, user_id)
                self._client.verify_device(olm_device)

    async def trust_all_allowed_devices(self, allowed_users: Sequence[str]) -> None:
        """Trust devices of all allowed users."""
        for user_id in allowed_users:
            await self.trust_devices_for_user(user_id)

    async def trust_devices_in_room(self, room_id: str) -> None:
        """Trust all devices of all members in a room (TOFU)."""
        room = self._client.rooms.get(room_id)
        if not room:
            return
        for user_id in room.users:
            if user_id == self._client.user_id:
                continue
            await self.trust_devices_for_user(user_id)

    # -- Messaging -------------------------------------------------------------

    async def send_message(self, room_id: str, text: str) -> None:
        """Send a text message to a room with E2E encryption.

        Parameters
        ----------
        room_id
            The Matrix room ID to send to.
        text
            The message body.

        Note
        ----
        Uses ``ignore_unverified_devices=True`` as a safety net against race
        conditions where a device appears between the trust loop and the send.
        """
        try:
            await self._client.room_send(
                room_id=room_id,
                message_type="m.room.message",
                content={"msgtype": "m.text", "body": text},
                ignore_unverified_devices=True,
            )
        except Exception as exc:
            logger.error("Failed to send message to {}: {}", room_id, exc)

    async def join_room(self, room_id: str) -> None:
        """Join a Matrix room."""
        await self._client.join(room_id)

    # -- Callback registration -------------------------------------------------

    def add_event_callback(self, callback: Callable[..., Any], event_type: type) -> None:
        """Register an event callback with the Matrix client.

        Parameters
        ----------
        callback
            Async function to call when the event is received.
        event_type
            The nio event type class to listen for.
        """
        self._client.add_event_callback(callback, event_type)

    # -- Sync ------------------------------------------------------------------

    async def initial_sync(self, timeout: int = 10000) -> str | None:
        """Perform an initial sync and return the next_batch token.

        Parameters
        ----------
        timeout
            Sync timeout in milliseconds.

        Returns
        -------
        str | None
            The next_batch token if sync succeeded, None otherwise.
        """
        logger.info("Running initial sync ...")
        sync_resp = await self._client.sync(timeout=timeout)
        if isinstance(sync_resp, SyncResponse):
            self._client.next_batch = sync_resp.next_batch
            logger.info("Initial sync complete.")
            return str(sync_resp.next_batch)
        return None

    async def sync_forever(self, timeout: int = 30000) -> None:
        """Run the sync loop indefinitely.

        Parameters
        ----------
        timeout
            Sync timeout in milliseconds.
        """
        logger.info("Listening for commands ...")
        await self._client.sync_forever(timeout=timeout)

    # -- Cleanup ---------------------------------------------------------------

    async def close(self) -> None:
        """Close the Matrix client connection."""
        await self._client.close()
