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

## Architecture

### Entry Point

`minimatrix.cli:main` (installed as `minimatrix` console script). Config resolution order: YAML file (`~/.config/minimatrix/config.yaml`) < environment variables < CLI args.

### Module Responsibilities

- **`__init__.py`** — Version (`__version__`), loguru configuration (`configure_logging()`).
- **`cli.py`** — CLI entry point (argparse). Subcommands: `send`, `listen`, `rooms`, `invites` (with `list`/`accept` sub-subcommands). Handles config merging (YAML/env/CLI) and the asyncio event loop. Uses `MatrixClientHandler` for all Matrix operations.
- **`matrix_client.py`** — `MatrixClientHandler` class wrapping `nio.AsyncClient`. Handles login dispatch (password/SSO/JWT), E2E key management, TOFU device trust, encrypted messaging, sync loops. SSO and JWT login handlers are lazily imported.
- **`config.py`** — `MiniMatrixConfig` frozen dataclass, loaded from env vars via `from_env()`. Currently not used by the CLI (which has its own config resolution in `cli.py`).
- **`jwt_login.py`** — `JWTLoginHandler`: Keycloak ROPC token acquisition + Matrix JWT login via `login_raw()`. Supports three login types (`com.famedly.login.token.oauth`, `com.famedly.login.token`, `org.matrix.login.jwt`).
- **`sso_login.py`** — `SSOLoginHandler`: Programmatic Keycloak SSO flow via HTML form parsing. Fragile; JWT auth is preferred.

### Key Design Patterns

- `MatrixClientHandler.login()` dispatches to `_login_sso()` or `_login_jwt()` which lazily import their respective handler modules to avoid loading aiohttp at import time.
- E2E encryption uses TOFU (Trust On First Use) — devices are automatically verified on first encounter via `trust_devices_in_room()`.
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
