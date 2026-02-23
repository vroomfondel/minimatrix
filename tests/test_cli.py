"""Tests for minimatrix.cli — argparse, config resolution, YAML loading."""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path
from typing import Any

import pytest

from minimatrix.cli import (
    _load_yaml_config,
    _merge_cli,
    _merge_env,
    build_parser,
    resolve_config,
)

# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


def test_build_parser_rooms() -> None:
    """Verifies that the 'rooms' subcommand is recognised by the argument parser."""
    parser = build_parser()
    args = parser.parse_args(["rooms"])
    assert args.command == "rooms"


def test_build_parser_send_with_message() -> None:
    """Verifies that 'send' with --room and a positional message argument is parsed correctly."""
    parser = build_parser()
    args = parser.parse_args(["send", "--room", "!abc:example.com", "Hello"])
    assert args.command == "send"
    assert args.room == "!abc:example.com"
    assert args.message == "Hello"


def test_build_parser_send_without_message() -> None:
    """Verifies that 'send' without a message argument sets message to None."""
    parser = build_parser()
    args = parser.parse_args(["send", "--room", "!abc:example.com"])
    assert args.command == "send"
    assert args.message is None


def test_build_parser_listen() -> None:
    """Verifies that the 'listen' subcommand with the -r room flag is parsed correctly."""
    parser = build_parser()
    args = parser.parse_args(["listen", "-r", "!room:example.com"])
    assert args.command == "listen"
    assert args.room == "!room:example.com"


def test_build_parser_global_options() -> None:
    """Verifies that global options --user, --password, and --homeserver are parsed correctly."""
    parser = build_parser()
    args = parser.parse_args(["--user", "bot", "--password", "pw", "--homeserver", "https://hs.example.com", "rooms"])
    assert args.user == "bot"
    assert args.password == "pw"
    assert args.homeserver == "https://hs.example.com"


def test_build_parser_auth_method_choices() -> None:
    """Verifies that --auth-method accepts valid choices such as 'jwt'."""
    parser = build_parser()
    args = parser.parse_args(["--auth-method", "jwt", "rooms"])
    assert args.auth_method == "jwt"


def test_build_parser_missing_subcommand() -> None:
    """Verifies that invoking the parser with no subcommand causes a SystemExit."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


# ---------------------------------------------------------------------------
# _load_yaml_config
# ---------------------------------------------------------------------------


def test_load_yaml_config_valid(tmp_path: Path) -> None:
    """Verifies that a well-formed YAML config file is loaded into a dict correctly."""
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(textwrap.dedent("""\
        homeserver: "https://matrix.example.com"
        user: "mybot"
        password: "s3cret"
        """))
    cfg = _load_yaml_config(cfg_file)
    assert cfg["homeserver"] == "https://matrix.example.com"
    assert cfg["user"] == "mybot"
    assert cfg["password"] == "s3cret"


def test_load_yaml_config_missing_file(tmp_path: Path) -> None:
    """Verifies that a missing config file returns an empty dict without raising."""
    cfg = _load_yaml_config(tmp_path / "nonexistent.yaml")
    assert cfg == {}


def test_load_yaml_config_invalid_yaml(tmp_path: Path) -> None:
    """Verifies that invalid YAML content does not raise and returns a dict."""
    cfg_file = tmp_path / "bad.yaml"
    cfg_file.write_text("not: [valid: yaml: {")
    # Should not raise, just return empty or partial
    cfg = _load_yaml_config(cfg_file)
    assert isinstance(cfg, dict)


def test_load_yaml_config_non_dict(tmp_path: Path) -> None:
    """YAML that parses to a list should return empty dict."""
    cfg_file = tmp_path / "list.yaml"
    cfg_file.write_text("- item1\n- item2\n")
    cfg = _load_yaml_config(cfg_file)
    assert cfg == {}


# ---------------------------------------------------------------------------
# _merge_env
# ---------------------------------------------------------------------------


def test_merge_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that present env vars override existing config values while absent ones preserve them."""
    monkeypatch.setenv("MATRIX_USER", "envuser")
    monkeypatch.setenv("MATRIX_HOMESERVER", "https://env.example.com")
    monkeypatch.delenv("MATRIX_PASSWORD", raising=False)

    cfg: dict[str, Any] = {"user": "yamluser", "homeserver": "https://yaml.example.com", "password": "yamlpw"}
    result = _merge_env(cfg)

    assert result["user"] == "envuser"
    assert result["homeserver"] == "https://env.example.com"
    # password was not set in env, so yaml value survives
    assert result["password"] == "yamlpw"


def test_merge_env_no_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """When no env vars are set, config passes through unchanged."""
    for var in ("MATRIX_HOMESERVER", "MATRIX_USER", "MATRIX_PASSWORD", "CRYPTO_STORE_PATH", "AUTH_METHOD"):
        monkeypatch.delenv(var, raising=False)

    cfg: dict[str, Any] = {"user": "original"}
    result = _merge_env(cfg)
    assert result["user"] == "original"


# ---------------------------------------------------------------------------
# _merge_cli
# ---------------------------------------------------------------------------


def test_merge_cli_overrides() -> None:
    """Verifies that non-None CLI namespace values override config while None values leave config intact."""
    ns = argparse.Namespace(user="cliuser", homeserver="https://cli.example.com", password=None)
    cfg: dict[str, Any] = {"user": "old", "homeserver": "https://old.example.com", "password": "oldpw"}
    result = _merge_cli(cfg, ns)

    assert result["user"] == "cliuser"
    assert result["homeserver"] == "https://cli.example.com"
    # password was None on CLI, so old value survives
    assert result["password"] == "oldpw"


# ---------------------------------------------------------------------------
# resolve_config (integration)
# ---------------------------------------------------------------------------


def test_resolve_config_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """With no config file, no env, and no CLI args, defaults are applied."""
    # Point to a nonexistent config file
    for var in (
        "MATRIX_HOMESERVER",
        "MATRIX_USER",
        "MATRIX_PASSWORD",
        "CRYPTO_STORE_PATH",
        "AUTH_METHOD",
        "KEYCLOAK_URL",
        "KEYCLOAK_REALM",
        "KEYCLOAK_CLIENT_ID",
        "KEYCLOAK_CLIENT_SECRET",
        "JWT_LOGIN_TYPE",
    ):
        monkeypatch.delenv(var, raising=False)

    ns = argparse.Namespace(config=str(tmp_path / "no.yaml"))
    # Set all _ENV_MAP keys to None so CLI doesn't override
    for key in ("homeserver", "user", "password", "crypto_store_path", "auth_method"):
        setattr(ns, key, None)
    for key in ("keycloak_url", "keycloak_realm", "keycloak_client_id", "keycloak_client_secret", "jwt_login_type"):
        setattr(ns, key, None)

    cfg = resolve_config(ns)
    assert cfg["homeserver"] == "http://synapse.matrix.svc.cluster.local:8008"
    assert cfg["auth_method"] == "password"
    assert cfg["keycloak_url"] == ""
    assert cfg["jwt_login_type"] == "com.famedly.login.token.oauth"


def test_resolve_config_priority_cli_over_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verifies that CLI args take precedence over environment variables in config resolution."""
    monkeypatch.setenv("MATRIX_USER", "envuser")
    # Clear others
    for var in ("MATRIX_HOMESERVER", "MATRIX_PASSWORD", "AUTH_METHOD"):
        monkeypatch.delenv(var, raising=False)

    ns = argparse.Namespace(config=str(tmp_path / "no.yaml"), user="cliuser")
    for key in ("homeserver", "password", "crypto_store_path", "auth_method"):
        setattr(ns, key, None)
    for key in ("keycloak_url", "keycloak_realm", "keycloak_client_id", "keycloak_client_secret", "jwt_login_type"):
        setattr(ns, key, None)

    cfg = resolve_config(ns)
    assert cfg["user"] == "cliuser"


def test_resolve_config_yaml_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Config file values are used when no env or CLI override."""
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text('homeserver: "https://yaml.example.com"\nuser: "yamlbot"\n')

    for var in ("MATRIX_HOMESERVER", "MATRIX_USER", "MATRIX_PASSWORD", "AUTH_METHOD"):
        monkeypatch.delenv(var, raising=False)

    ns = argparse.Namespace(config=str(cfg_file))
    for key in ("homeserver", "user", "password", "crypto_store_path", "auth_method"):
        setattr(ns, key, None)
    for key in ("keycloak_url", "keycloak_realm", "keycloak_client_id", "keycloak_client_secret", "jwt_login_type"):
        setattr(ns, key, None)

    cfg = resolve_config(ns)
    assert cfg["homeserver"] == "https://yaml.example.com"
    assert cfg["user"] == "yamlbot"
