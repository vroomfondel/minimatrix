"""MatrixClientHandler — encapsulates Matrix client operations with E2E encryption.

Provides a clean interface for Matrix/Synapse interactions including authentication
(password, SSO, JWT), TOFU device trust, and encrypted messaging.
"""

from __future__ import annotations

import glob
import json
import os
import secrets
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
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

        Args:
            homeserver: Matrix homeserver URL.
            user: Matrix username (localpart).
            crypto_store_path: Path for persistent E2E key storage.
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
        """Recover device_id from an existing nio crypto store SQLite DB.

        Args:
            store_path: Directory containing the crypto store ``*.db`` files.
            user: Matrix user ID (localpart or full ``@user:server``) used to
                locate the matching database file.

        Returns:
            The device ID string if found in the database, or None if no matching
            store exists or the query fails.
        """
        import sqlite3

        # nio names DB files using the full Matrix user ID (@user:server_DEVICEID.db).
        # If only a localpart was provided, use a wildcard for the server part.
        if user.startswith("@"):
            pattern = os.path.join(store_path, f"{user}_*.db")
        else:
            pattern = os.path.join(store_path, f"@{user}:*_*.db")
        matches = glob.glob(pattern)
        if not matches:
            return None
        # Use the most recently modified store
        latest = max(matches, key=os.path.getmtime)
        try:
            conn = sqlite3.connect(latest)
            row = conn.execute("SELECT device_id FROM accounts LIMIT 1").fetchone()
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

    # -- Token cache -----------------------------------------------------------

    @property
    def _token_cache_path(self) -> Path:
        """Path to the cached Matrix session token file."""
        return Path(self._crypto_store_path) / "session.json"

    def _save_token(self) -> None:
        """Persist the current Matrix session to disk."""
        data = {
            "user_id": self._client.user_id,
            "device_id": self._client.device_id,
            "access_token": self._client.access_token,
        }
        self._token_cache_path.write_text(json.dumps(data))
        logger.debug("Session token cached to {}", self._token_cache_path)

    def _load_cached_token(self) -> dict[str, str] | None:
        """Load a cached Matrix session from disk.

        Returns:
            A dict with ``user_id``, ``device_id``, and ``access_token`` keys if a
            valid cache file exists, or None if the file is absent or unreadable.
        """
        path = self._token_cache_path
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text())
            if data.get("user_id") and data.get("device_id") and data.get("access_token"):
                return dict(data)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read cached token from {}: {}", path, exc)
        return None

    async def _try_restore_login(self) -> bool:
        """Attempt to restore a previous session from the token cache.

        Returns:
            True if the cached token is still valid, False otherwise.
        """
        cached = self._load_cached_token()
        if not cached:
            return False

        logger.info("Restoring session from cache (device_id={})", cached["device_id"])
        self._client.restore_login(
            user_id=cached["user_id"],
            device_id=cached["device_id"],
            access_token=cached["access_token"],
        )

        # Verify the token is still valid with a whoami call
        resp = await self._client.whoami()
        if hasattr(resp, "user_id"):
            logger.info("Cached session valid for {}", resp.user_id)
            return True

        logger.info("Cached session expired, performing fresh login")
        self._token_cache_path.unlink(missing_ok=True)
        return False

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

        Args:
            auth_method: One of ``"password"``, ``"sso"``, or ``"jwt"``.
            password: Matrix password (also used for Keycloak ROPC in jwt/sso modes).
            sso_idp_id: SSO IdP identifier (required for ``auth_method="sso"``).
            keycloak_url: Keycloak base URL (required for ``auth_method="jwt"``).
            keycloak_realm: Keycloak realm name (required for ``auth_method="jwt"``).
            keycloak_client_id: Keycloak client ID (required for ``auth_method="jwt"``).
            keycloak_client_secret: Keycloak client secret (optional, empty for public
                clients).
            jwt_login_type: Matrix login type for JWT auth (default:
                ``"com.famedly.login.token.oauth"``).
        """
        # Try restoring a cached session first
        if await self._try_restore_login():
            return

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

        self._save_token()

        if self._client.should_upload_keys:
            logger.info("Uploading device keys ...")
            await self._client.keys_upload()

    async def _login_sso(self, idp_id: str, password: str) -> LoginResponse:
        """Perform SSO login via Keycloak.

        Args:
            idp_id: The SSO identity provider identifier registered on the homeserver.
            password: The user's password passed to the Keycloak HTML login form.

        Returns:
            A :class:`~nio.LoginResponse` on success. Exits the process on failure.
        """
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
        """Perform JWT login via Keycloak ROPC grant.

        Args:
            password: The user's password used for the Keycloak ROPC token request.
            keycloak_url: Keycloak base URL.
            keycloak_realm: Keycloak realm name.
            keycloak_client_id: Keycloak client ID.
            keycloak_client_secret: Keycloak client secret (empty for public clients).
            jwt_login_type: Matrix login type string for the JWT auth flow.

        Returns:
            A :class:`~nio.LoginResponse` on success. Exits the process on failure.
        """
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
        """Auto-trust all devices of a given user (TOFU).

        Args:
            user_id: The fully-qualified Matrix user ID whose devices to trust.
        """
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
        """Trust devices of all allowed users.

        Args:
            allowed_users: Sequence of fully-qualified Matrix user IDs whose devices
                should be trusted.
        """
        for user_id in allowed_users:
            await self.trust_devices_for_user(user_id)

    async def trust_devices_in_room(self, room_id: str) -> None:
        """Trust all devices of all members in a room (TOFU).

        Args:
            room_id: The Matrix room ID whose members' devices should be trusted.
        """
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

        Args:
            room_id: The Matrix room ID to send to.
            text: The message body.

        Note:
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
        """Join a Matrix room.

        Args:
            room_id: The Matrix room ID to join.

        Raises:
            RuntimeError: If the homeserver returns an error response.
        """
        from nio import JoinResponse

        resp = await self._client.join(room_id)
        if isinstance(resp, JoinResponse):
            logger.info("Joined room {}", room_id)
        else:
            logger.error("Failed to join room {}: {}", room_id, resp)
            raise RuntimeError(f"Failed to join room {room_id}: {resp}")

    # -- Callback registration -------------------------------------------------

    def add_event_callback(self, callback: Callable[..., Any], event_type: type) -> None:
        """Register an event callback with the Matrix client.

        Args:
            callback: Async function to call when the event is received.
            event_type: The nio event type class to listen for.
        """
        self._client.add_event_callback(callback, event_type)

    # -- Sync ------------------------------------------------------------------

    async def initial_sync(self, timeout: int = 10000, auto_join: bool = False) -> str | None:
        """Perform an initial sync and return the next_batch token.

        Args:
            timeout: Sync timeout in milliseconds.
            auto_join: Automatically accept all pending room invitations.

        Returns:
            The next_batch token if sync succeeded, or None if the sync response
            was not a :class:`~nio.SyncResponse`.
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
                # Re-sync to update room state after joining
                resync = await self._client.sync(timeout=timeout)
                if isinstance(resync, SyncResponse):
                    self._client.next_batch = resync.next_batch
            return str(self._client.next_batch)
        return None

    def _extract_invite_metadata(self, sync_resp: SyncResponse) -> None:
        """Extract invite timestamps and is_direct from the raw SyncResponse.

        Args:
            sync_resp: The :class:`~nio.SyncResponse` returned by the initial sync,
                used to populate ``_invite_metadata`` for all invited rooms.
        """
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
        """Return invite metadata for a room.

        Args:
            room_id: The Matrix room ID to look up.

        Returns:
            A dict with keys ``"is_dm"`` (bool) and ``"invite_ts"`` (int or None).
            Defaults to ``{"is_dm": False, "invite_ts": None}`` if the room is not
            found in the metadata cache.
        """
        return self._invite_metadata.get(room_id, {"is_dm": False, "invite_ts": None})

    async def _auto_join_invited_rooms(self) -> None:
        """Automatically accept all pending room invitations."""
        from datetime import datetime, timezone

        joined_room_ids = set(self._client.rooms.keys())
        for room_id, room in list(self._client.invited_rooms.items()):
            if room_id in joined_room_ids:
                logger.debug("Skipping {} — already joined", room_id)
                continue
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
                await self.join_room(room_id)
            except Exception as exc:
                logger.warning("Failed to auto-join {}: {}", room_id, exc)

    async def sync_forever(self, timeout: int = 30000) -> None:
        """Run the sync loop indefinitely.

        Args:
            timeout: Sync timeout in milliseconds.
        """
        logger.info("Listening for commands ...")
        await self._client.sync_forever(timeout=timeout)

    # -- Device management -----------------------------------------------------

    @property
    def device_id(self) -> str:
        """Return the current device ID."""
        return str(self._client.device_id)

    async def list_devices(self) -> list[dict[str, Any]]:
        """List all devices registered on the homeserver for the current user.

        Returns:
            A list of dicts with keys: device_id, display_name, last_seen_ip, last_seen_ts.
        """
        from nio.responses import DevicesResponse

        resp = await self._client.devices()
        if not isinstance(resp, DevicesResponse):
            logger.error("Failed to list devices: {}", resp)
            return []
        result: list[dict[str, Any]] = []
        for d in resp.devices:
            result.append(
                {
                    "device_id": d.id,
                    "display_name": d.display_name or "",
                    "last_seen_ip": d.last_seen_ip or "",
                    "last_seen_date": d.last_seen_date or "",
                }
            )
        return result

    async def delete_other_devices(self, password: str) -> int:
        """Delete all devices except the current one using UIA password auth.

        Args:
            password: The user's Matrix password for the UIA flow.

        Returns:
            The number of devices deleted.
        """
        from nio.responses import DeleteDevicesAuthResponse, DeleteDevicesResponse

        devices = await self.list_devices()
        other_ids = [d["device_id"] for d in devices if d["device_id"] != self._client.device_id]
        if not other_ids:
            logger.info("No other devices to delete")
            return 0

        # First call without auth to get session ID
        resp = await self._client.delete_devices(other_ids)
        if isinstance(resp, DeleteDevicesAuthResponse):
            # UIA required — retry with password auth
            auth = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": self._client.user_id},
                "password": password,
                "session": resp.session,
            }
            resp = await self._client.delete_devices(other_ids, auth=auth)

        if isinstance(resp, DeleteDevicesResponse):
            logger.info("Deleted {} device(s)", len(other_ids))
            return len(other_ids)

        logger.error("Failed to delete devices: {}", resp)
        return 0

    async def import_keys_from_old_stores(self, delete_old: bool = False) -> tuple[int, int]:
        """Import megolm sessions from old crypto store DBs into the current store.

        Auto-generates a random passphrase for the export/import roundtrip.

        Args:
            delete_old: If True, delete old .db files (and associated sidecar files)
                after successful import.

        Returns:
            A tuple of (sessions_imported, old_devices_count).
        """
        passphrase = secrets.token_urlsafe(32)
        user = self._client.user_id
        store_path = self._crypto_store_path
        current_device = self._client.device_id

        pattern = os.path.join(store_path, f"{user}_*.db")
        all_dbs = glob.glob(pattern)

        old_dbs = [db for db in all_dbs if not db.endswith(f"{user}_{current_device}.db")]
        if not old_dbs:
            logger.info("No old crypto store DBs found")
            return (0, 0)

        sessions_imported = 0
        devices_processed = 0

        for db_path in old_dbs:
            # Extract device_id from filename: {user}_{device_id}.db
            filename = os.path.basename(db_path)
            # Remove the "{user}_" prefix and ".db" suffix
            old_device_id = filename[len(f"{user}_") : -len(".db")]
            if not old_device_id:
                continue

            logger.info("Exporting keys from old device {}", old_device_id)

            nio_config = AsyncClientConfig(encryption_enabled=True, store_sync_tokens=True)
            tmp_client = AsyncClient(
                self._homeserver,
                user,
                device_id=old_device_id,
                store_path=store_path,
                config=nio_config,
            )

            export_path: str | None = None
            try:
                # Load the olm account from the old crypto store DB.
                # restore_login() triggers load_store() which initializes the Olm
                # object — required before export_keys() can access megolm sessions.
                # The access_token is unused (no API calls are made).
                tmp_client.restore_login(
                    user_id=user,
                    device_id=old_device_id,
                    access_token="not-needed",
                )

                with tempfile.NamedTemporaryFile(suffix=".keys", delete=False) as tf:
                    export_path = tf.name

                await tmp_client.export_keys(export_path, passphrase)
                if os.path.getsize(export_path) > 0:
                    import_resp = await self._client.import_keys(export_path, passphrase)
                    if hasattr(import_resp, "keys"):
                        count = len(import_resp.keys) if import_resp.keys else 0
                    else:
                        count = 0
                    sessions_imported += count
                    devices_processed += 1
                    logger.info("Imported {} session(s) from device {}", count, old_device_id)
                else:
                    logger.warning("No keys exported from device {}", old_device_id)
            except Exception as exc:
                logger.warning("Failed to process old device {}: {}", old_device_id, exc)
            finally:
                await tmp_client.close()
                if export_path and os.path.exists(export_path):
                    os.unlink(export_path)

        if delete_old and devices_processed > 0:
            for db_path in old_dbs:
                base = db_path[: -len(".db")]
                for suffix in (".db", ".trusted_devices", ".blacklisted_devices", ".ignored_devices"):
                    path = base + suffix
                    if os.path.exists(path):
                        os.unlink(path)
                        logger.debug("Removed {}", path)

        return (sessions_imported, devices_processed)

    # -- Cleanup ---------------------------------------------------------------

    async def close(self) -> None:
        """Close the Matrix client connection."""
        await self._client.close()
