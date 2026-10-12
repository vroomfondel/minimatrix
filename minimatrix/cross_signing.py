"""Cross-sign the CLI/bot's own Matrix device so clients stop flagging its messages.

Element marks every message of a bot or CLI device with a red "!" ("encrypted by
a device not verified by its owner"): the device logs in freshly and nobody
vouches for it.  matrix-nio has no cross-signing support, so this module does
the minimum by hand:

1. The three cross-signing keys (master, self-signing, user-signing) are
   derived deterministically from one secret.  Every instance that shares the
   secret therefore holds the same identity -- no key store to distribute.
   The secret is in effect the master key: treat it like a password and never
   log or commit it.  By default it lives in the crypto store
   (see :func:`load_or_create_secret`).
2. If the server does not know this master key yet, the keys are uploaded
   (``/keys/device_signing/upload``).  Synapse accepts the *first* upload
   without user-interactive auth (MSC3967); replacing existing keys of the
   account needs auth a bot cannot provide -- then a server admin must allow it
   once (``_allow_cross_signing_replacement_without_uia``).
3. The current device is signed with the self-signing key
   (``/keys/signatures/upload``), unless it already is.

Clients then see the device as verified by its owner.  Keys are signed over
their canonical JSON (sorted keys, no whitespace, without ``signatures`` /
``unsigned``) with ed25519, as the spec requires.
"""

import copy
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loguru import logger as glogger
from nio import AsyncClient
from olm.pk import PkSigning

logger = glogger.bind(classname="cross_signing")

JsonDict = dict[str, Any]
"""A Matrix JSON object (key/signature payloads)."""

DEFAULT_SEED_INFO = "minimatrix cross-signing {usage}"
"""Default HMAC message per key usage -- changing it changes the account identity."""

SECRET_FILE_NAME = "cross_signing_secret"
"""File name of the persisted secret inside the crypto store directory."""


class CrossSigningError(Exception):
    """Cross-signing could not be set up (the client keeps working without it)."""


@dataclass(frozen=True)
class CrossSigningKeys:
    """The account's three cross-signing key pairs.

    Attributes:
        master: Master key -- the account's identity.
        self_signing: Signs the account's own devices.
        user_signing: Signs other users' master keys (uploaded, not used).
    """

    master: PkSigning
    self_signing: PkSigning
    user_signing: PkSigning

    @classmethod
    def from_secret(cls, secret: str, seed_info: str = DEFAULT_SEED_INFO) -> "CrossSigningKeys":
        """Derive the key pairs from *secret* (HMAC-SHA256 per usage as ed25519 seed).

        Args:
            secret: The cross-signing secret (non-empty).
            seed_info: HMAC message template with a ``{usage}`` placeholder.  It is
                part of the derivation: changing it yields different keys and thus
                a different account identity.  Callers that derived their keys with
                another template (e.g. ``"wachtmeater cross-signing {usage}"``) must
                pass it to keep their existing identity.

        Returns:
            The derived keys; the same secret and seed_info always yield the same keys.

        Raises:
            ValueError: If *secret* is empty.
        """
        if not secret:
            raise ValueError("cross-signing secret must not be empty")

        def _key(usage: str) -> PkSigning:
            seed = hmac.new(secret.encode(), seed_info.format(usage=usage).encode(), hashlib.sha256).digest()
            return PkSigning(seed)

        return cls(master=_key("master"), self_signing=_key("self_signing"), user_signing=_key("user_signing"))


def load_or_create_secret(store_path: str | Path) -> str:
    """Load the cross-signing secret from the crypto store, creating it on first use.

    The secret is kept in ``<store_path>/cross_signing_secret`` (one line, mode 0600).

    Args:
        store_path: Crypto store directory (created if missing).

    Returns:
        The stored or newly generated secret.
    """
    directory = Path(store_path).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / SECRET_FILE_NAME
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(32)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(secret + "\n")
    logger.info(f"Created a new cross-signing identity (secret stored in {path})")
    return secret


def canonical_json(obj: JsonDict) -> str:
    """Encode *obj* as Matrix canonical JSON (sorted keys, compact, UTF-8 kept).

    Args:
        obj: JSON object.

    Returns:
        The canonical JSON string.
    """
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sign_json(obj: JsonDict, key: PkSigning, user_id: str) -> JsonDict:
    """Return a copy of *obj* with *key*'s signature added.

    The signature covers the canonical JSON without ``signatures`` and
    ``unsigned``; existing signatures are kept.

    Args:
        obj: Key object to sign.
        key: Signing key; its public key is the key ID (``ed25519:<pub>``).
        user_id: The signing user.

    Returns:
        The signed copy.
    """
    signed = copy.deepcopy(obj)
    signatures = signed.pop("signatures", {})
    unsigned = signed.pop("unsigned", None)
    signature = key.sign(canonical_json(signed))
    signatures.setdefault(user_id, {})[f"ed25519:{key.public_key}"] = signature
    signed["signatures"] = signatures
    if unsigned is not None:
        signed["unsigned"] = unsigned
    return signed


def _key_object(key: PkSigning, user_id: str, usage: str) -> JsonDict:
    """Build the unsigned cross-signing key object for *key* with the given *usage*."""
    return {"user_id": user_id, "usage": [usage], "keys": {f"ed25519:{key.public_key}": key.public_key}}


def device_signing_upload_body(keys: CrossSigningKeys, user_id: str) -> JsonDict:
    """Build the ``/keys/device_signing/upload`` body (sub-keys signed by the master key).

    Args:
        keys: The account's cross-signing keys.
        user_id: The account's MXID.

    Returns:
        The request body (without ``auth``).
    """
    return {
        "master_key": _key_object(keys.master, user_id, "master"),
        "self_signing_key": sign_json(_key_object(keys.self_signing, user_id, "self_signing"), keys.master, user_id),
        "user_signing_key": sign_json(_key_object(keys.user_signing, user_id, "user_signing"), keys.master, user_id),
    }


def _master_public(query: JsonDict, user_id: str) -> str | None:
    """Return the server's master public key of *user_id* from a ``/keys/query`` response."""
    master = query.get("master_keys", {}).get(user_id)
    if not master:
        return None
    return next(iter(master.get("keys", {}).values()), None)


def is_device_signed(device_keys: JsonDict, keys: CrossSigningKeys, user_id: str) -> bool:
    """Tell whether *device_keys* already carry the self-signing key's signature.

    Args:
        device_keys: The device's key object from ``/keys/query``.
        keys: The account's cross-signing keys.
        user_id: The account's MXID.

    Returns:
        ``True`` if the signature is present.
    """
    sigs = device_keys.get("signatures", {}).get(user_id, {})
    return f"ed25519:{keys.self_signing.public_key}" in sigs


async def _request(client: AsyncClient, path: str, body: JsonDict) -> tuple[int, JsonDict]:
    """POST *body* to the client-server API with the client's access token.

    Args:
        client: Logged-in nio client.
        path: API path below the homeserver URL.
        body: JSON body.

    Returns:
        HTTP status and the decoded JSON response.
    """
    resp = await client.send(
        "POST",
        path,
        data=json.dumps(body),
        headers={"Authorization": f"Bearer {client.access_token}", "Content-Type": "application/json"},
    )
    try:
        data: JsonDict = await resp.json()
    except Exception:
        data = {}
    return resp.status, data


async def ensure_device_cross_signed(client: AsyncClient, secret: str, seed_info: str = DEFAULT_SEED_INFO) -> str:
    """Make sure the account's cross-signing keys exist and this device is signed.

    Args:
        client: Logged-in nio client whose device keys are uploaded.
        secret: The cross-signing secret (non-empty).
        seed_info: HMAC message template for the key derivation (see
            :meth:`CrossSigningKeys.from_secret`).

    Returns:
        A short English summary of what was done.

    Raises:
        CrossSigningError: If the keys or the signature could not be uploaded.
    """
    user_id, device_id = client.user_id, client.device_id
    keys = CrossSigningKeys.from_secret(secret, seed_info)

    status, query = await _request(client, "/_matrix/client/v3/keys/query", {"device_keys": {user_id: []}})
    if status != 200:
        raise CrossSigningError(f"keys/query failed ({status}): {query}")

    done: list[str] = []
    server_master = _master_public(query, user_id)
    if server_master != keys.master.public_key:
        status, resp = await _request(
            client, "/_matrix/client/v3/keys/device_signing/upload", device_signing_upload_body(keys, user_id)
        )
        if status == 401:
            raise CrossSigningError(
                f"{user_id} already has different cross-signing keys (master {server_master}). Replacing them needs "
                "user-interactive auth, which a bot cannot provide. Options: (a) disable self-signing "
                "(--no-self-sign-keys / SELF_SIGN_KEYS=false); (b) use the same CROSS_SIGNING_SECRET as the instance "
                "that already set up the account; (c) once, as Synapse admin, allow the replacement: POST "
                f"/_synapse/admin/v1/users/{user_id}/_allow_cross_signing_replacement_without_uia. Note that "
                "replacing the keys changes the account's identity, so other clients and contacts will see "
                "'identity changed'."
            )
        if status != 200:
            raise CrossSigningError(f"Cross-signing key upload failed ({status}): {resp}")
        done.append("cross-signing keys uploaded" if server_master is None else "cross-signing keys replaced")

    device = query.get("device_keys", {}).get(user_id, {}).get(device_id)
    if device is None:
        raise CrossSigningError(f"Device keys of {device_id} are not known to the server yet")
    if is_device_signed(device, keys, user_id):
        done.append(f"device {device_id} already signed")
    else:
        signed = sign_json(device, keys.self_signing, user_id)
        signed.pop("unsigned", None)
        status, resp = await _request(
            client, "/_matrix/client/v3/keys/signatures/upload", {user_id: {device_id: signed}}
        )
        failures = resp.get("failures") if status == 200 else None
        if status != 200 or failures:
            raise CrossSigningError(f"Device signature upload failed ({status}): {failures or resp}")
        done.append(f"device {device_id} signed")
    logger.info(f"Cross-signing: {', '.join(done)} (master {keys.master.public_key})")
    return ", ".join(done)
