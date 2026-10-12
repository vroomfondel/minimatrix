"""Tests for minimatrix.cross_signing -- key derivation, signing, upload flow, secret storage."""

import asyncio
import base64
import json
import stat
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from minimatrix import cross_signing as cs

USER = "@bot:example.org"
DEVICE = "DEVICEID"
KEYS = cs.CrossSigningKeys.from_secret("s3cret")


def _b64decode(unpadded: str) -> bytes:
    """Decode unpadded standard base64."""
    return base64.b64decode(unpadded + "=" * (-len(unpadded) % 4))


def _verify(obj: dict[str, Any], key: Any) -> None:
    """Raise unless *obj* carries a valid signature by *key* (canonical JSON, spec style)."""
    sig = obj["signatures"][USER][f"ed25519:{key.public_key}"]
    stripped = {k: v for k, v in obj.items() if k not in ("signatures", "unsigned")}
    public = Ed25519PublicKey.from_public_bytes(_b64decode(key.public_key))
    public.verify(_b64decode(sig), cs.canonical_json(stripped).encode("utf-8"))


def _device_keys() -> dict[str, Any]:
    return {
        "user_id": USER,
        "device_id": DEVICE,
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "keys": {f"curve25519:{DEVICE}": "curve", f"ed25519:{DEVICE}": "ed"},
        "signatures": {USER: {f"ed25519:{DEVICE}": "selfsig"}},
        "unsigned": {"device_display_name": "bot"},
    }


class FakeClient:
    """Minimal nio client: records POSTs, answers from a path -> (status, json) table."""

    def __init__(self, answers: dict[str, tuple[int, dict[str, Any]]]) -> None:
        self.user_id = USER
        self.device_id = DEVICE
        self.access_token = "tok"
        self.answers = answers
        self.posts: list[tuple[str, dict[str, Any]]] = []

    async def send(self, method: str, path: str, data: str, headers: dict[str, str]) -> Any:
        assert method == "POST" and headers["Authorization"] == "Bearer tok"
        self.posts.append((path, json.loads(data)))
        status, body = self.answers.get(path.rsplit("/v3/", 1)[1], (200, {}))
        resp = MagicMock(status=status)
        resp.json = AsyncMock(return_value=body)
        return resp

    def paths(self) -> list[str]:
        return [p.rsplit("/v3/", 1)[1] for p, _ in self.posts]


def _query(master: str | None = None, device: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    body: dict[str, Any] = {"device_keys": {USER: {DEVICE: device or _device_keys()}}}
    if master:
        body["master_keys"] = {USER: {"user_id": USER, "usage": ["master"], "keys": {f"ed25519:{master}": master}}}
    return 200, body


def test_keys_are_derived_deterministically_and_distinct() -> None:
    again = cs.CrossSigningKeys.from_secret("s3cret")
    other = cs.CrossSigningKeys.from_secret("other")
    pubs = {KEYS.master.public_key, KEYS.self_signing.public_key, KEYS.user_signing.public_key}
    assert len(pubs) == 3
    assert again.master.public_key == KEYS.master.public_key
    assert other.master.public_key != KEYS.master.public_key


def test_keys_match_libolm_known_answers() -> None:
    """Verifies that keys and signatures equal those python-olm 3.2.16 (PkSigning) produced."""
    keys = cs.CrossSigningKeys.from_secret("test-secret")
    assert keys.master.public_key == "tvIJxzDSYteJTE1twoIlzcDmTOkOBnRSwGJPIYTi254"
    assert keys.self_signing.public_key == "TZf77+HxLtQ79OV12Yiv2MGzUsBTUWUnMq3oDPhXpIw"
    assert keys.user_signing.public_key == "zh4Vw08Ww1MC9Qqh1DwnNd+SnrgLe0RKiebH3Mel+80"
    assert keys.master.sign('{"a":1}') == (
        "/dhbxpEk90Qb405ieNPuUP5CigGcwCkjmDQ0lzK4XRu8S6w/jFyHP+bSfATBMAhf6nwk+W8WfAoPrLRgWvVpDw"
    )
    assert cs.SigningKey(bytes(range(32))).public_key == "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"


def test_canonical_json_is_sorted_and_compact() -> None:
    assert cs.canonical_json({"b": 1, "a": {"d": "ä", "c": [1, 2]}}) == '{"a":{"c":[1,2],"d":"ä"},"b":1}'


def test_sign_json_ignores_signatures_and_unsigned_and_keeps_existing() -> None:
    signed = cs.sign_json(_device_keys(), KEYS.self_signing, USER)
    _verify(signed, KEYS.self_signing)
    assert signed["signatures"][USER][f"ed25519:{DEVICE}"] == "selfsig"
    assert signed["unsigned"] == {"device_display_name": "bot"}


def test_upload_body_signs_sub_keys_with_master() -> None:
    body = cs.device_signing_upload_body(KEYS, USER)
    assert body["master_key"]["keys"] == {f"ed25519:{KEYS.master.public_key}": KEYS.master.public_key}
    assert body["self_signing_key"]["usage"] == ["self_signing"]
    _verify(body["self_signing_key"], KEYS.master)
    _verify(body["user_signing_key"], KEYS.master)


def test_first_run_uploads_keys_and_signs_device() -> None:
    client = FakeClient({"keys/query": _query()})
    summary = asyncio.run(cs.ensure_device_cross_signed(client, "s3cret"))
    assert client.paths() == ["keys/query", "keys/device_signing/upload", "keys/signatures/upload"]
    assert summary == f"cross-signing keys uploaded, device {DEVICE} signed"
    signed = client.posts[2][1][USER][DEVICE]
    _verify(signed, KEYS.self_signing)
    assert "unsigned" not in signed


def test_already_set_up_does_nothing() -> None:
    device = cs.sign_json(_device_keys(), KEYS.self_signing, USER)
    client = FakeClient({"keys/query": _query(KEYS.master.public_key, device)})
    summary = asyncio.run(cs.ensure_device_cross_signed(client, "s3cret"))
    assert client.paths() == ["keys/query"]
    assert summary == f"device {DEVICE} already signed"


def test_known_master_signs_only_the_new_device() -> None:
    client = FakeClient({"keys/query": _query(KEYS.master.public_key)})
    asyncio.run(cs.ensure_device_cross_signed(client, "s3cret"))
    assert client.paths() == ["keys/query", "keys/signatures/upload"]


def test_foreign_master_raises_with_replacement_options() -> None:
    client = FakeClient({"keys/query": _query("FOREIGN"), "keys/device_signing/upload": (401, {"flows": []})})
    with pytest.raises(cs.CrossSigningError) as exc:
        asyncio.run(cs.ensure_device_cross_signed(client, "s3cret"))
    message = str(exc.value)
    assert "FOREIGN" in message
    assert "--no-self-sign-keys" in message and "SELF_SIGN_KEYS=false" in message
    assert "CROSS_SIGNING_SECRET" in message
    assert "_allow_cross_signing_replacement_without_uia" in message and "MAS" in message
    assert "digital identity reset" in message
    assert "keys/signatures/upload" not in client.paths()


def test_signature_failures_raise() -> None:
    client = FakeClient(
        {
            "keys/query": _query(KEYS.master.public_key),
            "keys/signatures/upload": (200, {"failures": {USER: {DEVICE: {"errcode": "M_INVALID_SIGNATURE"}}}}),
        }
    )
    with pytest.raises(cs.CrossSigningError, match="M_INVALID_SIGNATURE"):
        asyncio.run(cs.ensure_device_cross_signed(client, "s3cret"))


def test_unknown_device_raises() -> None:
    client = FakeClient({"keys/query": (200, {"device_keys": {USER: {}}})})
    with pytest.raises(cs.CrossSigningError, match="not known to the server"):
        asyncio.run(cs.ensure_device_cross_signed(client, "s3cret"))


def test_from_secret_empty_raises() -> None:
    """Verifies that an empty secret is rejected with ValueError."""
    with pytest.raises(ValueError):
        cs.CrossSigningKeys.from_secret("")


def test_seed_info_changes_keys() -> None:
    """Verifies that a different seed_info template yields different keys."""
    other = cs.CrossSigningKeys.from_secret("s3cret", "wachtmeater cross-signing {usage}")
    assert other.master.public_key != KEYS.master.public_key
    assert other.self_signing.public_key != KEYS.self_signing.public_key
    same = cs.CrossSigningKeys.from_secret("s3cret", cs.DEFAULT_SEED_INFO)
    assert same.master.public_key == KEYS.master.public_key


def test_ensure_uses_custom_seed_info() -> None:
    """Verifies that ensure_device_cross_signed derives keys with the given seed_info."""
    info = "wachtmeater cross-signing {usage}"
    custom = cs.CrossSigningKeys.from_secret("s3cret", info)
    client = FakeClient({"keys/query": _query(custom.master.public_key)})
    asyncio.run(cs.ensure_device_cross_signed(client, "s3cret", info))
    assert client.paths() == ["keys/query", "keys/signatures/upload"]


def test_load_or_create_secret_creates_private_file(tmp_path: Path) -> None:
    """Verifies that a missing secret is created with mode 0600 and reused on the second call."""
    store = tmp_path / "nested" / "store"
    first = cs.load_or_create_secret(store)
    path = store / "cross_signing_secret"
    assert first and path.read_text().strip() == first
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert cs.load_or_create_secret(str(store)) == first


def test_load_or_create_secret_reads_existing(tmp_path: Path) -> None:
    """Verifies that an existing secret file is read and stripped."""
    (tmp_path / "cross_signing_secret").write_text("  existing-secret \n")
    assert cs.load_or_create_secret(tmp_path) == "existing-secret"
