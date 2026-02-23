"""MatrixClientHandler — encapsulates Matrix client operations with E2E encryption.

Provides a clean interface for Matrix/Synapse interactions including authentication
(password, SSO, JWT), TOFU device trust, and encrypted messaging.
"""

from __future__ import annotations

import glob
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
        # Invite metadata extracted from the raw SyncResponse, keyed by room_id.
        # Matrix guarantees at most one active invite per room per user — a re-invite
        # (after leave) replaces the previous one in Synapse's state, so a simple
        # room_id -> metadata dict is sufficient.
        self._invite_metadata: dict[str, dict[str, Any]] = {}  # room_id -> {is_dm, invite_ts}

        os.makedirs(crypto_store_path, exist_ok=True)

        # Recover device_id from existing crypto store DB to avoid creating new devices on every run
        device_id = self._recover_device_id(crypto_store_path, user)
        if device_id:
            logger.info("Reusing existing device_id={} from crypto store", device_id)

        nio_config = AsyncClientConfig(
            encryption_enabled=True,
            store_sync_tokens=True,
        )
        self._client = AsyncClient(
            homeserver,
            user,
            device_id=device_id or "",
            store_path=crypto_store_path,
            config=nio_config,
        )

    @staticmethod
    def _recover_device_id(store_path: str, user: str) -> str | None:
        """Recover device_id from an existing nio crypto store SQLite DB."""
        import sqlite3

        pattern = os.path.join(store_path, f"{user}_*.db")
        matches = glob.glob(pattern)
        if not matches:
            return None
        # Use the most recently modified store
        latest = max(matches, key=os.path.getmtime)
        try:
            conn = sqlite3.connect(latest)
            row = conn.execute("SELECT device_id FROM accounts WHERE user_id = ? LIMIT 1", (user,)).fetchone()
            conn.close()
            if row and row[0]:
                return str(row[0])
        except sqlite3.Error as exc:
            logger.warning("Could not read device_id from {}: {}", latest, exc)
        return None

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

    @property
    def invited_rooms(self) -> dict[str, Any]:
        """Return the dict of rooms with pending invites."""
        return dict(self._client.invited_rooms)

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
            username=self._user.removeprefix("@").split(":")[0],
            password=password,
            login_type=jwt_login_type,
        )
        try:
            return await handler.perform_login(self._client, device_id=self._client.device_id or None)
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

    async def initial_sync(self, timeout: int = 10000, auto_join: bool = False) -> str | None:
        """Perform an initial sync and return the next_batch token.

        Parameters
        ----------
        timeout
            Sync timeout in milliseconds.
        auto_join
            Automatically accept all pending room invitations.

        Returns
        -------
        str | None
            The next_batch token if sync succeeded, None otherwise.
        """
        # Force a full sync to pick up pending invites and current room state,
        # regardless of any stored next_batch token from a previous session.
        self._client.next_batch = ""
        self._client.loaded_sync_token = ""
        logger.info("Running initial sync ...")
        sync_resp = await self._client.sync(timeout=timeout, full_state=True)
        if isinstance(sync_resp, SyncResponse):
            self._client.next_batch = sync_resp.next_batch
            logger.info("Initial sync complete.")
            self._extract_invite_metadata(sync_resp)
            if auto_join:
                logger.info("Auto-join enabled — accepting pending invitations")
                await self._auto_join_invited_rooms()
            return str(sync_resp.next_batch)
        return None

    def _extract_invite_metadata(self, sync_resp: SyncResponse) -> None:
        """Extract invite timestamps and is_direct from the raw SyncResponse."""
        from nio.events.invite_events import InviteMemberEvent

        for room_id, invite_info in sync_resp.rooms.invite.items():
            meta: dict[str, Any] = {"is_dm": False, "invite_ts": None}
            for evt in invite_info.invite_state:
                if isinstance(evt, InviteMemberEvent) and evt.membership == "invite":
                    source = getattr(evt, "source", {})
                    meta["invite_ts"] = source.get("origin_server_ts")
                    content = getattr(evt, "content", {})
                    if content.get("is_direct") or source.get("content", {}).get("is_direct"):
                        meta["is_dm"] = True
            self._invite_metadata[room_id] = meta

    def get_invite_metadata(self, room_id: str) -> dict[str, Any]:
        """Return invite metadata (is_dm, invite_ts) for a room."""
        return self._invite_metadata.get(room_id, {"is_dm": False, "invite_ts": None})

    async def _auto_join_invited_rooms(self) -> None:
        """Automatically accept all pending room invitations."""
        from datetime import datetime, timezone

        for room_id, room in list(self._client.invited_rooms.items()):
            inviter = getattr(room, "inviter", None) or "unknown"
            meta = self.get_invite_metadata(room_id)
            is_dm = meta["is_dm"]
            invite_ts = meta["invite_ts"]
            ts_str = datetime.fromtimestamp(invite_ts / 1000, tz=timezone.utc).isoformat() if invite_ts else "unknown"
            kind = "DM" if is_dm else "Room"

            member_count = getattr(room, "member_count", "?")
            logger.info(
                "Auto-joining {} {} (invited by {}, type={}, members={}, invited_at={})",
                kind,
                room_id,
                inviter,
                kind,
                member_count,
                ts_str,
            )
            try:
                await self._client.join(room_id)
            except Exception as exc:
                logger.warning("Failed to auto-join {}: {}", room_id, exc)

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
