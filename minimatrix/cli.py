#!/usr/bin/env python3
"""Standalone Matrix CLI — send, listen, and list rooms using the MatrixClientHandler.

Config:   ~/.config/minimatrix/config.yaml (optional)

Priority: CLI args > environment variables > config file
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger as glogger

from minimatrix import configure_logging, print_banner
from minimatrix.matrix_client import MatrixClientHandler

CONFIG_DIR = Path("~/.config/minimatrix").expanduser()
DEFAULT_CONFIG_FILE = CONFIG_DIR / "config.yaml"
DEFAULT_CRYPTO_STORE = Path("~/.local/share/minimatrix/crypto_store").expanduser()

# Mapping: config-file key -> env var name
_ENV_MAP: dict[str, str] = {
    "homeserver": "MATRIX_HOMESERVER",
    "user": "MATRIX_USER",
    "password": "MATRIX_PASSWORD",
    "crypto_store_path": "CRYPTO_STORE_PATH",
    "auth_method": "AUTH_METHOD",
    "keycloak_url": "KEYCLOAK_URL",
    "keycloak_realm": "KEYCLOAK_REALM",
    "keycloak_client_id": "KEYCLOAK_CLIENT_ID",
    "keycloak_client_secret": "KEYCLOAK_CLIENT_SECRET",
    "jwt_login_type": "JWT_LOGIN_TYPE",
    "auto_join": "AUTO_JOIN",
}

logger = glogger.bind(classname="matrix_cli")


# ---------------------------------------------------------------------------
# Config loading (YAML < env < CLI)
# ---------------------------------------------------------------------------


def _load_yaml_config(path: Path) -> dict[str, Any]:
    """Load config from YAML file, return empty dict if missing or unreadable."""
    if not path.is_file():
        return {}
    try:
        import yaml

        with open(path) as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.warning("Could not read config file {}: {}", path, exc)
        return {}


def _merge_env(cfg: dict[str, Any]) -> dict[str, Any]:
    """Override config values with environment variables where set."""
    for key, env_var in _ENV_MAP.items():
        val = os.environ.get(env_var)
        if val is not None:
            cfg[key] = val
    return cfg


def _merge_cli(cfg: dict[str, Any], ns: argparse.Namespace) -> dict[str, Any]:
    """Override config values with explicitly provided CLI args."""
    for key in _ENV_MAP:
        cli_val = getattr(ns, key, None)
        if cli_val is not None:
            cfg[key] = cli_val
    return cfg


def resolve_config(ns: argparse.Namespace) -> dict[str, Any]:
    """Build final config dict: YAML < env < CLI."""
    config_file = Path(getattr(ns, "config", None) or DEFAULT_CONFIG_FILE).expanduser()
    cfg = _load_yaml_config(config_file)
    cfg = _merge_env(cfg)
    cfg = _merge_cli(cfg, ns)

    # Defaults
    cfg.setdefault("homeserver", "http://synapse.matrix.svc.cluster.local:8008")
    cfg.setdefault("crypto_store_path", str(DEFAULT_CRYPTO_STORE))
    cfg.setdefault("auth_method", "password")
    cfg.setdefault("keycloak_url", "")
    cfg.setdefault("keycloak_realm", "")
    cfg.setdefault("keycloak_client_id", "")
    cfg.setdefault("keycloak_client_secret", "")
    cfg.setdefault("jwt_login_type", "com.famedly.login.token.oauth")
    cfg.setdefault("auto_join", False)

    # Normalize auto_join to bool (env vars come in as strings)
    aj = cfg["auto_join"]
    if isinstance(aj, str):
        cfg["auto_join"] = aj.lower() in ("1", "true", "yes")

    # Expand ~ in crypto store path
    cfg["crypto_store_path"] = str(Path(cfg["crypto_store_path"]).expanduser())

    return cfg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_handler(cfg: dict[str, Any]) -> MatrixClientHandler:
    """Create a MatrixClientHandler, login, and run initial sync."""
    user = cfg.get("user", "")
    password = cfg.get("password", "")
    if not user or not password:
        logger.error("user and password are required")
        sys.exit(1)

    handler = MatrixClientHandler(
        homeserver=cfg["homeserver"],
        user=user,
        crypto_store_path=cfg["crypto_store_path"],
    )
    await handler.login(
        auth_method=cfg["auth_method"],
        password=password,
        keycloak_url=cfg.get("keycloak_url") or None,
        keycloak_realm=cfg.get("keycloak_realm") or None,
        keycloak_client_id=cfg.get("keycloak_client_id") or None,
        keycloak_client_secret=cfg.get("keycloak_client_secret") or None,
        jwt_login_type=cfg.get("jwt_login_type") or None,
    )
    await handler.initial_sync(auto_join=bool(cfg.get("auto_join")))
    return handler


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _format_invite(room_id: str, room: Any, handler: MatrixClientHandler) -> str:
    """Format a single invited room for display."""
    from datetime import datetime, timezone

    display_name = getattr(room, "display_name", room_id) or room_id
    inviter = getattr(room, "inviter", None) or "unknown"
    meta = handler.get_invite_metadata(room_id)
    kind = "DM" if meta["is_dm"] else "Room"
    member_count = getattr(room, "member_count", "?")
    invite_ts = meta["invite_ts"]
    ts_str = datetime.fromtimestamp(invite_ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if invite_ts else "?"
    return f"  {room_id}  {display_name}  ({kind}, members: {member_count}, invited by {inviter}, at {ts_str})"


async def cmd_rooms(cfg: dict[str, Any]) -> None:
    """List joined rooms and pending invites."""
    handler = await _create_handler(cfg)
    try:
        rooms = handler.rooms
        invited = handler.invited_rooms
        if not rooms and not invited:
            print("No joined rooms or pending invites.")
            return
        if rooms:
            print("Joined rooms:")
            for room_id, room in rooms.items():
                display_name = getattr(room, "display_name", room_id) or room_id
                member_count = getattr(room, "member_count", "?")
                print(f"  {room_id}  {display_name}  (members: {member_count})")
        if invited:
            print("Pending invites:")
            for room_id, room in invited.items():
                print(_format_invite(room_id, room, handler))
    finally:
        await handler.close()


async def cmd_invites_list(cfg: dict[str, Any]) -> None:
    """List pending room invitations."""
    handler = await _create_handler(cfg)
    try:
        invited = handler.invited_rooms
        if not invited:
            print("No pending invites.")
            return
        for room_id, room in invited.items():
            print(_format_invite(room_id, room, handler))
    finally:
        await handler.close()


async def cmd_invites_accept(cfg: dict[str, Any], room_id: str) -> None:
    """Accept a single room invitation."""
    handler = await _create_handler(cfg)
    try:
        invited = handler.invited_rooms
        if room_id not in invited:
            logger.error("No pending invite for room {}", room_id)
            sys.exit(1)
        room = invited[room_id]
        meta = handler.get_invite_metadata(room_id)
        inviter = getattr(room, "inviter", None) or "unknown"
        kind = "DM" if meta["is_dm"] else "Room"
        logger.info("Accepting invite to {} {} (invited by {})", kind, room_id, inviter)
        await handler.join_room(room_id)
        logger.info("Joined room {}", room_id)
    finally:
        await handler.close()


async def cmd_send(cfg: dict[str, Any], room_id: str, message: str) -> None:
    """Send a text message to a room."""
    handler = await _create_handler(cfg)
    try:
        await handler.trust_devices_in_room(room_id)
        await handler.send_message(room_id, message)
        logger.info("Message sent to {}", room_id)
    finally:
        await handler.close()


async def cmd_listen(cfg: dict[str, Any], room_id: str) -> None:
    """Listen for messages in a room and print them to stdout."""
    from nio import MegolmEvent, RoomMessageText

    handler = await _create_handler(cfg)
    own_user_id = handler.user_id

    async def _on_message(room: Any, event: RoomMessageText) -> None:
        if event.sender == own_user_id:
            return
        ts = datetime.fromtimestamp(event.server_timestamp / 1000, tz=timezone.utc)
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts_str}] <{event.sender}> {event.body}", flush=True)

    async def _on_megolm(room: Any, event: MegolmEvent) -> None:
        ts = datetime.fromtimestamp(event.server_timestamp / 1000, tz=timezone.utc)
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts_str}] <{event.sender}> [encrypted, unable to decrypt]", flush=True)

    handler.add_event_callback(_on_message, RoomMessageText)
    handler.add_event_callback(_on_megolm, MegolmEvent)

    await handler.trust_devices_in_room(room_id)

    logger.info("Listening in {} — press Ctrl+C to stop", room_id)
    try:
        await handler.sync_forever(timeout=30000)
    except asyncio.CancelledError:
        pass
    finally:
        await handler.close()


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="minimatrix",
        description="minimatrix — standalone Matrix CLI client: send, listen, list rooms.",
    )
    parser.add_argument("--config", "-c", help=f"YAML config file (default: {DEFAULT_CONFIG_FILE})")
    parser.add_argument("--homeserver", help="Matrix homeserver URL")
    parser.add_argument("--user", help="Matrix username (localpart or full MXID)")
    parser.add_argument("--password", help="Matrix password")
    parser.add_argument("--crypto-store-path", dest="crypto_store_path", help="Path for E2E crypto store")
    parser.add_argument(
        "--auth-method",
        dest="auth_method",
        choices=["password", "sso", "jwt"],
        help="Authentication method",
    )
    parser.add_argument("--keycloak-url", dest="keycloak_url", help="Keycloak base URL (for jwt auth)")
    parser.add_argument("--keycloak-realm", dest="keycloak_realm", help="Keycloak realm (for jwt auth)")
    parser.add_argument("--keycloak-client-id", dest="keycloak_client_id", help="Keycloak client ID (for jwt auth)")
    parser.add_argument(
        "--keycloak-client-secret", dest="keycloak_client_secret", help="Keycloak client secret (for jwt auth)"
    )
    parser.add_argument("--jwt-login-type", dest="jwt_login_type", help="Matrix login type for JWT")
    parser.add_argument(
        "--auto-join",
        dest="auto_join",
        action="store_true",
        default=None,
        help="Automatically accept pending room invitations on startup",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- send ---
    sp_send = subparsers.add_parser("send", help="Send a message to a room")
    sp_send.add_argument("--room", "-r", required=True, help="Room ID (e.g. !abc:example.com)")
    sp_send.add_argument("message", nargs="?", default=None, help="Message text (reads from stdin if omitted)")

    # --- listen ---
    sp_listen = subparsers.add_parser("listen", help="Listen for messages in a room")
    sp_listen.add_argument("--room", "-r", required=True, help="Room ID (e.g. !abc:example.com)")

    # --- rooms ---
    subparsers.add_parser("rooms", help="List joined rooms and pending invites")

    # --- invites ---
    sp_invites = subparsers.add_parser("invites", help="Manage room invitations")
    inv_sub = sp_invites.add_subparsers(dest="invites_command")
    inv_sub.add_parser("list", help="List pending invitations (default)")
    sp_inv_accept = inv_sub.add_parser("accept", help="Accept a room invitation")
    sp_inv_accept.add_argument("--room", "-r", required=True, help="Room ID to accept (e.g. !abc:example.com)")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _handle_signal() -> None:
    logger.info("Received shutdown signal")
    for task in asyncio.all_tasks():
        task.cancel()


def main() -> None:
    os.environ.setdefault("LOGURU_LEVEL", "INFO")
    configure_logging()
    glogger.enable("minimatrix")

    print_banner()

    parser = build_parser()
    args = parser.parse_args()
    cfg = resolve_config(args)

    loop = asyncio.new_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal)

    try:
        if args.command == "rooms":
            loop.run_until_complete(cmd_rooms(cfg))
        elif args.command == "invites":
            if getattr(args, "invites_command", None) == "accept":
                loop.run_until_complete(cmd_invites_accept(cfg, args.room))
            else:
                loop.run_until_complete(cmd_invites_list(cfg))
        elif args.command == "send":
            message = args.message
            if message is None:
                if sys.stdin.isatty():
                    parser.error("No message provided — pass as argument or pipe via stdin")
                message = sys.stdin.read().strip()
                if not message:
                    parser.error("Empty message from stdin")
            loop.run_until_complete(cmd_send(cfg, args.room, message))
        elif args.command == "listen":
            loop.run_until_complete(cmd_listen(cfg, args.room))
    finally:
        loop.close()


if __name__ == "__main__":
    main()
