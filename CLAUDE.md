# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**minimatrix** is a standalone Matrix protocol CLI client with E2E encryption support. It uses `matrix-nio[e2e]` for Matrix protocol operations and supports three authentication methods: password, SSO (Keycloak), and JWT (Keycloak ROPC).

Requires Python 3.14+.

## Build & Development Commands

```bash
make install          # Create venv and install deps (requirements-build.txt includes dev + hatch)
make tests            # Run pytest
make lint             # Format code with black
make isort            # Sort imports with isort
make tcheck           # Static type checking with mypy (strict mode)
make commit-checks    # Run all pre-commit hooks (black --check, mypy, gitleaks)
make prepare          # tests + commit-checks
make pypibuild        # Build sdist + wheel via hatch
```

Run a single test: `pytest tests/test_foo.py::test_name`

The venv lives at `.venv/` and uses Python 3.14. The Makefile auto-activates it unless `VIRTUAL_ENV` or `GITHUB_RUN_ID` is already set.

## Code Style

- **black** with line-length 120, target py313
- **isort** with black profile, line-length 120
- **mypy** in strict mode with pydantic plugin; `nio` and `nio.*` modules have `ignore_missing_imports = true`
- Logging via **loguru** — each module creates a bound logger with `glogger.bind(classname="...")`. Logging is disabled by default in `__init__.py` and explicitly enabled via `configure_logging()` + `glogger.enable("minimatrix")` at CLI entry.

### Comments

- Default: no comment. A comment has to earn its line.
- **One line maximum** per comment, except a file header. No multi-line prose blocks.
- A comment may state a *constraint* (what breaks, which version, which upstream issue).
  It may NOT explain motivation, history, alternatives considered, or current deployment
  state. That belongs in the commit message, an issue, or a doc file.
- Banned openings: "This is how ...", "Without it ...", "We do/don't ...", "Note that ...",
  "The reason ...".
- No comment referring to volatile state (current version, current workload, current tag).
- No comments that restate what the line already says.
- No docstrings unless explicitly asked for.
- No section banners (`# ---- Helper ----`).
- No meta comments about the editing process itself ("newly added", "adjusted as requested").
- When in doubt: no comment.

## Architecture

### Entry Point

`minimatrix.cli:main` (installed as `minimatrix` console script). Config resolution order: YAML file (`~/.config/minimatrix/config.yaml`) < environment variables < CLI args.

### Module Responsibilities

- **`__init__.py`** — Version (`__version__`), loguru configuration (`configure_logging()`).
- **`cli.py`** — CLI entry point (argparse). Subcommands: `send` (text and/or files via `--file`/`-f`, optional `--html`), `listen`, `chat`, `rooms`, `invites` (with `list`/`accept` sub-subcommands), `devices` (`list`/`purge`/`import-keys`/`cross-sign`). Handles config merging (YAML/env/CLI) and the asyncio event loop. Uses `MatrixClientHandler` for all Matrix operations.
- **`matrix_client.py`** — `MatrixClientHandler` class wrapping `nio.AsyncClient`. Handles login dispatch (password/SSO/JWT), E2E key management, TOFU device trust, encrypted text messaging, file uploads (images, documents, audio, video with automatic MIME detection), sync loops. SSO and JWT login handlers are lazily imported.
- **`config.py`** — `MiniMatrixConfig` frozen dataclass, loaded from env vars via `from_env()`. Currently not used by the CLI (which has its own config resolution in `cli.py`).
- **`cross_signing.py`** — Hand-rolled cross-signing (nio has none): derives master/self-signing/user-signing keys from a secret (HMAC-SHA256 → ed25519 seed), uploads them on first use (`/keys/device_signing/upload`, no UIA thanks to MSC3967) and signs the own device (`/keys/signatures/upload`). `load_or_create_secret()` keeps a generated secret in `<crypto_store>/cross_signing_secret` when none is configured. Pure functions (`canonical_json`, `sign_json`, ...) use `cryptography` ed25519 (`SigningKey` reproduces libolm's `PkSigning` byte-for-byte; a known-answer test pins the derived keys).
- **`jwt_login.py`** — `JWTLoginHandler`: Keycloak ROPC token acquisition + Matrix JWT login via `login_raw()`. Supports three login types (`com.famedly.login.token.oauth`, `com.famedly.login.token`, `org.matrix.login.jwt`).
- **`sso_login.py`** — `SSOLoginHandler`: Programmatic Keycloak SSO flow via HTML form parsing. Fragile; JWT auth is preferred.

### Key Design Patterns

- `MatrixClientHandler.login()` dispatches to `_login_sso()` or `_login_jwt()` which lazily import their respective handler modules to avoid loading aiohttp at import time.
- E2E encryption uses TOFU (Trust On First Use) — devices are automatically verified on first encounter via `trust_devices_in_room()`.
- `MatrixClientHandler.login()` has a **mandatory** keyword-only `self_sign_keys: bool` so every caller decides explicitly whether the device gets cross-signed after login (CLI default: on). Cross-signing failures at login are logged, never fatal; `devices cross-sign` makes them fatal.
- `sync_forever()` loops around nio's benign `LocalProtocolError("No key query required.")` race (nio schedules its own `keys_query` task in `sync_forever` while `trust_devices_for_user()` runs one too); any other `LocalProtocolError` propagates.
- `send_message()`/`send_file()` return a bool and swallow errors by default; `strict=True` raises `MessageSendError` for callers that must retry. `send_message(html=...)` adds `formatted_body`.
- `join_room()` accepts `!id:server` or `#alias:server` and returns the resolved room ID.
- The CLI creates a fresh `MatrixClientHandler` per subcommand invocation (connect, login, sync, act, close).
- **Cross-run persistence**: `_recover_device_id()` reads the `device_id` from the SQLite crypto store DB (`<user>_*.db`) so reconnections reuse the same device. After login, credentials are cached in `session.json` (inside the crypto store dir); `_try_restore_login()` restores from this cache on subsequent runs, skipping full re-authentication.

### Pre-commit Hooks

`.pre-commit-config.yaml` runs (with `fail_fast: true`): `check-yaml`, `black --check`, `mypy`, and **gitleaks** for secret scanning. Be careful not to commit Matrix credentials or tokens.

## Testing

Tests are pure unit tests — no Matrix server or network access required, safe to run freely. They test argument parsing, config merging, env var handling, and HTML parsing using `monkeypatch` for environment variables and `tmp_path` for file fixtures. Run with `make tests` or target a single test with `pytest tests/test_foo.py::test_name`.

## Environment Variables

Config resolution: YAML (`~/.config/minimatrix/config.yaml`) < env vars < CLI args. Key env vars (mapped via `_ENV_MAP` in `cli.py`):

| Variable | Default |
|---|---|
| `MATRIX_HOMESERVER` | `http://synapse.matrix.svc.cluster.local:8008` |
| `MATRIX_USER` | *(required)* |
| `MATRIX_PASSWORD` | *(required for password auth)* |
| `CRYPTO_STORE_PATH` | `~/.local/share/minimatrix/crypto_store` |
| `AUTH_METHOD` | `password` (also: `sso`, `jwt`) |
| `KEYCLOAK_URL` | — |
| `KEYCLOAK_REALM` | — |
| `KEYCLOAK_CLIENT_ID` | — |
| `KEYCLOAK_CLIENT_SECRET` | — |
| `JWT_LOGIN_TYPE` | `com.famedly.login.token.oauth` |
| `AUTO_JOIN` | `false` (truthy: `1`, `true`, `yes`) |
| `SELF_SIGN_KEYS` | `true` (CLI: `--no-self-sign-keys`) |
| `CROSS_SIGNING_SECRET` | — (generated once per crypto store when empty) |
