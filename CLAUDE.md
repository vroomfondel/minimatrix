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
- **`cli.py`** — CLI entry point (argparse). Subcommands: `send`, `listen`, `rooms`. Handles config merging (YAML/env/CLI) and the asyncio event loop. Uses `MatrixClientHandler` for all Matrix operations.
- **`matrix_client.py`** — `MatrixClientHandler` class wrapping `nio.AsyncClient`. Handles login dispatch (password/SSO/JWT), E2E key management, TOFU device trust, encrypted messaging, sync loops. SSO and JWT login handlers are lazily imported.
- **`config.py`** — `MiniMatrixConfig` frozen dataclass, loaded from env vars via `from_env()`. Currently not used by the CLI (which has its own config resolution in `cli.py`).
- **`jwt_login.py`** — `JWTLoginHandler`: Keycloak ROPC token acquisition + Matrix JWT login via `login_raw()`. Supports three login types (`com.famedly.login.token.oauth`, `com.famedly.login.token`, `org.matrix.login.jwt`).
- **`sso_login.py`** — `SSOLoginHandler`: Programmatic Keycloak SSO flow via HTML form parsing. Fragile; JWT auth is preferred.

### Key Design Patterns

- `MatrixClientHandler.login()` dispatches to `_login_sso()` or `_login_jwt()` which lazily import their respective handler modules to avoid loading aiohttp at import time.
- E2E encryption uses TOFU (Trust On First Use) — devices are automatically verified on first encounter via `trust_devices_in_room()`.
- The CLI creates a fresh `MatrixClientHandler` per subcommand invocation (connect, login, sync, act, close).
