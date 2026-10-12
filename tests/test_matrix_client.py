"""Tests for minimatrix.matrix_client — sync resilience, sending, joining, login hooks."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from nio import AsyncClient, JoinResponse, LocalProtocolError, RoomSendError, RoomSendResponse
from nio.crypto.device import DeviceStore, OlmDevice, TrustState

from minimatrix.matrix_client import MatrixClientHandler, MessageSendError, TrustResult


def make_handler(tmp_path: Path | None = None) -> MatrixClientHandler:
    """Build a handler without running ``__init__`` and with a mocked nio client."""
    handler = MatrixClientHandler.__new__(MatrixClientHandler)
    handler._client = MagicMock()
    handler._client.rooms = {}
    handler._crypto_store_path = str(tmp_path) if tmp_path else "/nonexistent-store"
    handler._stop_requested = False
    handler._homeserver = "http://hs.example"
    handler._user = "@bot:example.com"
    handler._invite_metadata = {}
    return handler


def send_ok() -> RoomSendResponse:
    """Return a successful room_send response."""
    return RoomSendResponse(event_id="$e", room_id="!r:x")


# ---------------------------------------------------------------------------
# sync_forever / stop_sync
# ---------------------------------------------------------------------------


class TestSync:
    """Sync loop resilience against nio's key-query race."""

    def test_resumes_after_no_key_query(self) -> None:
        """A 'No key query required' error is swallowed and sync restarts."""
        h = make_handler()
        h._client.sync_forever = AsyncMock(side_effect=[LocalProtocolError("No key query required."), None])
        asyncio.run(h.sync_forever(timeout=1))
        assert h._client.sync_forever.await_count == 2

    def test_other_protocol_error_propagates(self) -> None:
        """Other LocalProtocolErrors are not swallowed."""
        h = make_handler()
        h._client.sync_forever = AsyncMock(side_effect=LocalProtocolError("boom"))
        with pytest.raises(LocalProtocolError):
            asyncio.run(h.sync_forever())
        assert h._client.sync_forever.await_count == 1

    def test_no_resume_after_stop(self) -> None:
        """After stop_sync the race error does not restart the loop."""
        h = make_handler()

        async def fake(**_: Any) -> None:
            h.stop_sync()
            raise LocalProtocolError("No key query required.")

        h._client.sync_forever = AsyncMock(side_effect=fake)
        asyncio.run(h.sync_forever())
        assert h._client.sync_forever.await_count == 1

    def test_stop_sync_sets_flag_and_stops(self) -> None:
        """stop_sync sets the flag and calls stop_sync_forever."""
        h = make_handler()
        h.stop_sync()
        assert h._stop_requested is True
        h._client.stop_sync_forever.assert_called_once_with()

    def test_sync_forever_resets_flag(self) -> None:
        """sync_forever clears a stale stop flag at start."""
        h = make_handler()
        h._stop_requested = True
        h._client.sync_forever = AsyncMock(return_value=None)
        asyncio.run(h.sync_forever())
        assert h._stop_requested is False


# ---------------------------------------------------------------------------
# send_message
# ---------------------------------------------------------------------------


class TestSendMessage:
    """Plain/HTML content and strict/non-strict error handling."""

    def test_plain_content(self) -> None:
        """Plain messages carry only msgtype and body."""
        h = make_handler()
        h._client.room_send = AsyncMock(return_value=send_ok())
        assert asyncio.run(h.send_message("!r:x", "hi")) is True
        kwargs = h._client.room_send.await_args.kwargs
        assert kwargs["content"] == {"msgtype": "m.text", "body": "hi"}
        assert kwargs["ignore_unverified_devices"] is True

    def test_html_content(self) -> None:
        """HTML adds format and formatted_body."""
        h = make_handler()
        h._client.room_send = AsyncMock(return_value=send_ok())
        assert asyncio.run(h.send_message("!r:x", "hi", html="<b>hi</b>")) is True
        assert h._client.room_send.await_args.kwargs["content"] == {
            "msgtype": "m.text",
            "body": "hi",
            "format": "org.matrix.custom.html",
            "formatted_body": "<b>hi</b>",
        }

    def test_strict_error_response_raises(self) -> None:
        """strict=True turns a RoomSendError response into MessageSendError."""
        h = make_handler()
        h._client.room_send = AsyncMock(return_value=RoomSendError("forbidden"))
        with pytest.raises(MessageSendError):
            asyncio.run(h.send_message("!r:x", "hi", strict=True))

    def test_strict_exception_raises(self) -> None:
        """strict=True wraps a send exception in MessageSendError."""
        h = make_handler()
        h._client.room_send = AsyncMock(side_effect=RuntimeError("net"))
        with pytest.raises(MessageSendError, match="net"):
            asyncio.run(h.send_message("!r:x", "hi", strict=True))

    def test_non_strict_returns_false_and_logs(self) -> None:
        """Non-strict failures return False and log an error."""
        h = make_handler()
        h._client.room_send = AsyncMock(return_value=RoomSendError("forbidden"))
        with patch("minimatrix.matrix_client.logger") as log:
            assert asyncio.run(h.send_message("!r:x", "hi")) is False
        log.error.assert_called_once()

    def test_non_strict_exception_returns_false(self) -> None:
        """Non-strict exceptions return False."""
        h = make_handler()
        h._client.room_send = AsyncMock(side_effect=RuntimeError("net"))
        assert asyncio.run(h.send_message("!r:x", "hi")) is False


# ---------------------------------------------------------------------------
# send_file
# ---------------------------------------------------------------------------


class TestSendFile:
    """send_file bool/strict semantics."""

    def test_missing_file(self, tmp_path: Path) -> None:
        """A missing file still raises FileNotFoundError."""
        h = make_handler(tmp_path)
        with pytest.raises(FileNotFoundError):
            asyncio.run(h.send_file("!r:x", tmp_path / "nope.txt"))

    def test_upload_failure(self, tmp_path: Path) -> None:
        """Upload failure: False when lenient, MessageSendError when strict."""
        f = tmp_path / "a.txt"
        f.write_text("x")
        h = make_handler(tmp_path)
        h._client.upload = AsyncMock(return_value=(MagicMock(), None))
        assert asyncio.run(h.send_file("!r:x", f)) is False
        with pytest.raises(MessageSendError):
            asyncio.run(h.send_file("!r:x", f, strict=True))

    def test_success(self, tmp_path: Path) -> None:
        """Successful upload and send returns True."""
        from nio import UploadResponse

        f = tmp_path / "a.txt"
        f.write_text("x")
        h = make_handler(tmp_path)
        h._client.upload = AsyncMock(return_value=(UploadResponse("mxc://x/y"), None))
        h._client.room_send = AsyncMock(return_value=send_ok())
        assert asyncio.run(h.send_file("!r:x", f)) is True
        assert h._client.room_send.await_args.kwargs["content"]["url"] == "mxc://x/y"

    def test_send_failure_strict(self, tmp_path: Path) -> None:
        """Send error after a successful upload raises when strict."""
        from nio import UploadResponse

        f = tmp_path / "a.txt"
        f.write_text("x")
        h = make_handler(tmp_path)
        h._client.upload = AsyncMock(return_value=(UploadResponse("mxc://x/y"), None))
        h._client.room_send = AsyncMock(return_value=RoomSendError("no"))
        assert asyncio.run(h.send_file("!r:x", f)) is False
        with pytest.raises(MessageSendError):
            asyncio.run(h.send_file("!r:x", f, strict=True))


# ---------------------------------------------------------------------------
# join_room
# ---------------------------------------------------------------------------


class TestJoinRoom:
    """join_room for IDs, aliases and errors."""

    def test_known_id_skips_join(self) -> None:
        """An already joined room ID is returned without joining."""
        h = make_handler()
        h._client.rooms = {"!r:x": object()}
        h._client.join = AsyncMock()
        assert asyncio.run(h.join_room("!r:x")) == "!r:x"
        h._client.join.assert_not_awaited()

    def test_alias_resolves_to_room_id(self) -> None:
        """An alias is joined and the room_id from the response is returned."""
        h = make_handler()
        h._client.join = AsyncMock(return_value=JoinResponse(room_id="!real:x"))
        assert asyncio.run(h.join_room("#alias:x")) == "!real:x"
        h._client.join.assert_awaited_once_with("#alias:x")

    def test_error_raises(self) -> None:
        """A non-JoinResponse raises RuntimeError."""
        h = make_handler()
        h._client.join = AsyncMock(return_value=MagicMock())
        with pytest.raises(RuntimeError):
            asyncio.run(h.join_room("!r:x"))

    def test_odd_spec_warns_and_tries(self) -> None:
        """An unrecognised form logs a warning but still attempts the join."""
        h = make_handler()
        h._client.join = AsyncMock(return_value=JoinResponse(room_id="!r:x"))
        with patch("minimatrix.matrix_client.logger") as log:
            assert asyncio.run(h.join_room("weird")) == "!r:x"
        log.warning.assert_called_once()


# ---------------------------------------------------------------------------
# login / ensure_cross_signed
# ---------------------------------------------------------------------------


def login_handler(restore: bool = True, should_upload: bool = True) -> MatrixClientHandler:
    """Build a handler with login collaborators mocked."""
    h = make_handler()
    h._client.should_upload_keys = should_upload
    h._client.keys_upload = AsyncMock()
    h._try_restore_login = AsyncMock(return_value=restore)  # type: ignore[method-assign]
    h._fresh_login = AsyncMock()  # type: ignore[method-assign]
    h.ensure_cross_signed = AsyncMock(return_value="done")  # type: ignore[method-assign]
    return h


class TestLogin:
    """Login hook behaviour."""

    def test_restore_uploads_keys(self) -> None:
        """The restore path also uploads keys when needed, and skips fresh login."""
        h = login_handler()
        asyncio.run(h.login("password", "pw", self_sign_keys=False))
        h._client.keys_upload.assert_awaited_once()
        h._fresh_login.assert_not_awaited()  # type: ignore[attr-defined]

    def test_fresh_login_path(self) -> None:
        """Without a valid cache, a fresh login is performed."""
        h = login_handler(restore=False, should_upload=False)
        asyncio.run(h.login("password", "pw", self_sign_keys=False))
        h._fresh_login.assert_awaited_once()  # type: ignore[attr-defined]
        h._client.keys_upload.assert_not_awaited()

    def test_self_sign_true(self) -> None:
        """self_sign_keys=True calls ensure_cross_signed with the given secret."""
        h = login_handler()
        asyncio.run(h.login("password", "pw", self_sign_keys=True, cross_signing_secret="s"))
        h.ensure_cross_signed.assert_awaited_once_with("s")  # type: ignore[attr-defined]

    def test_self_sign_false(self) -> None:
        """self_sign_keys=False does not cross-sign."""
        h = login_handler()
        asyncio.run(h.login("password", "pw", self_sign_keys=False))
        h.ensure_cross_signed.assert_not_awaited()  # type: ignore[attr-defined]

    def test_self_sign_failure_swallowed(self) -> None:
        """Cross-signing errors are logged but do not fail the login."""
        h = login_handler()
        h.ensure_cross_signed = AsyncMock(side_effect=RuntimeError("bad"))  # type: ignore[method-assign]
        with patch("minimatrix.matrix_client.logger") as log:
            asyncio.run(h.login("password", "pw", self_sign_keys=True))
        log.error.assert_called_once()

    def test_self_sign_keys_is_required(self) -> None:
        """self_sign_keys has no default."""
        h = login_handler()
        with pytest.raises(TypeError):
            asyncio.run(h.login("password", "pw"))  # type: ignore[call-arg]


class TestEnsureCrossSigned:
    """ensure_cross_signed secret handling."""

    def test_loads_secret_when_missing(self, tmp_path: Path) -> None:
        """Without a secret, load_or_create_secret supplies one."""
        h = make_handler(tmp_path)
        h._client.should_upload_keys = True
        h._client.keys_upload = AsyncMock()
        fake = MagicMock()
        fake.load_or_create_secret.return_value = "stored"
        fake.ensure_device_cross_signed = AsyncMock(return_value="summary")
        with patch.dict(sys.modules, {"minimatrix.cross_signing": fake}):
            assert asyncio.run(h.ensure_cross_signed()) == "summary"
        fake.load_or_create_secret.assert_called_once_with(str(tmp_path))
        fake.ensure_device_cross_signed.assert_awaited_once_with(h._client, "stored")
        h._client.keys_upload.assert_awaited_once()

    def test_uses_given_secret(self, tmp_path: Path) -> None:
        """An explicit secret bypasses the store."""
        h = make_handler(tmp_path)
        h._client.should_upload_keys = False
        fake = MagicMock()
        fake.ensure_device_cross_signed = AsyncMock(return_value="ok")
        with patch.dict(sys.modules, {"minimatrix.cross_signing": fake}):
            assert asyncio.run(h.ensure_cross_signed("mine")) == "ok"
        fake.load_or_create_secret.assert_not_called()
        fake.ensure_device_cross_signed.assert_awaited_once_with(h._client, "mine")


# ---------------------------------------------------------------------------
# TOFU device trust — real nio AsyncClient (store/olm loaded from tmp_path) and a
# real DeviceStore/OlmDevice; only keys_query (network) is mocked. Fakes that invent
# client methods (is_device_verified) or a dict device store hid two bugs here.
# ---------------------------------------------------------------------------


class TestTrustDevices:
    USER = "@alice:example.com"
    BOT = "@bot:example.com"

    def trust_handler(self, tmp_path: Path, *devices: OlmDevice) -> MatrixClientHandler:
        client = AsyncClient("http://hs.invalid", self.BOT, device_id="BOTDEV", store_path=str(tmp_path))
        client.user_id = self.BOT
        client.load_store()
        for device in devices:
            client.device_store.add(device)
        client.keys_query = AsyncMock(side_effect=LocalProtocolError("No key query required."))
        h = make_handler(tmp_path)
        h._client = client
        return h

    def device(self, device_id: str, *, user_id: str = USER, deleted: bool = False) -> OlmDevice:
        keys = {"ed25519": f"ed-{device_id}", "curve25519": f"cu-{device_id}"}
        return OlmDevice(user_id, device_id, keys, deleted=deleted)

    def test_unknown_user_is_noop(self, tmp_path: Path) -> None:
        h = self.trust_handler(tmp_path, self.device("A"))
        result = asyncio.run(h.trust_devices_for_user("@nobody:example.com"))
        assert result == TrustResult("@nobody:example.com", (), (), ())

    def test_mixed_devices(self, tmp_path: Path) -> None:
        a, b, known, gone = self.device("A"), self.device("B"), self.device("KNOWN"), self.device("GONE", deleted=True)
        known.trust_state = TrustState.verified
        h = self.trust_handler(tmp_path, a, b, known, gone)
        result = asyncio.run(h.trust_devices_for_user(self.USER))
        assert set(result.known) == {"A", "B", "KNOWN"}
        assert set(result.trusted) == {"A", "B", "KNOWN"}
        assert set(result.newly_trusted) == {"A", "B"}
        assert a.verified and b.verified
        assert not gone.verified
        # trust is persisted by nio's store, a second run trusts nothing new
        assert asyncio.run(h.trust_devices_for_user(self.USER)).newly_trusted == ()

    def test_room_skips_self(self, tmp_path: Path) -> None:
        h = self.trust_handler(tmp_path, self.device("A"), self.device("OTHER", user_id=self.BOT))
        h._client.rooms = {"!r:x": MagicMock(users={self.USER: None, self.BOT: None})}
        results = asyncio.run(h.trust_devices_in_room("!r:x"))
        assert results == [TrustResult(self.USER, ("A",), ("A",), ("A",))]
        assert asyncio.run(h.trust_devices_in_room("!unknown:x")) == []

    def test_all_allowed_devices(self, tmp_path: Path) -> None:
        h = self.trust_handler(tmp_path, self.device("A"))
        results = asyncio.run(h.trust_all_allowed_devices([self.USER, "@nobody:example.com"]))
        assert [r.newly_trusted for r in results] == [("A",), ()]
