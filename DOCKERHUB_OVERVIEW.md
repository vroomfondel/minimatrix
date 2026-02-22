[![black-lint](https://github.com/vroomfondel/minimatrix/actions/workflows/checkblack.yml/badge.svg)](https://github.com/vroomfondel/minimatrix/actions/workflows/checkblack.yml)
[![mypy and pytests](https://github.com/vroomfondel/minimatrix/actions/workflows/mypynpytests.yml/badge.svg)](https://github.com/vroomfondel/minimatrix/actions/workflows/mypynpytests.yml)
[![BuildAndPushMultiarch](https://github.com/vroomfondel/minimatrix/actions/workflows/buildmultiarchandpush.yml/badge.svg)](https://github.com/vroomfondel/minimatrix/actions/workflows/buildmultiarchandpush.yml)
[![Cumulative Clones](https://img.shields.io/endpoint?logo=github&url=https://gist.githubusercontent.com/vroomfondel/e2b37502d2c026d6b3c103eba37b16ac/raw/minimatrix_clone_count.json)](https://github.com/vroomfondel/minimatrix)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/minimatrix?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=PyPi+Downloads)](https://pepy.tech/projects/minimatrix)

[![Gemini_Generated_Image_2bsor82bsor82bso_250x250.png](https://raw.githubusercontent.com/vroomfondel/minimatrix/main/Gemini_Generated_Image_2bsor82bsor82bso_250x250.png)](https://github.com/vroomfondel/minimatrix)

# minimatrix

Standalone Matrix CLI client with E2E encryption. Send messages, listen to rooms,
and list joined rooms — all from the command line.

- **Source**: [GitHub](https://github.com/vroomfondel/minimatrix)
- **PyPI**: [minimatrix](https://pypi.org/project/minimatrix/)
- **License**: LGPLv3

## Features

- **Send** encrypted messages to Matrix rooms
- **Listen** for incoming messages in real-time (prints to stdout)
- **List** joined rooms with display names and member counts
- **E2E encryption** via matrix-nio with persistent crypto store
- **TOFU device trust** — automatically trusts all devices in a room
- **Multiple auth methods**: password, SSO, or JWT via Keycloak (ROPC + JWKS)
- **Flexible config**: YAML file, environment variables, and CLI args (in ascending priority)

## Quick Start

```bash
docker run --rm xomoxcc/minimatrix:latest
```

### Usage Examples

```bash
# List joined rooms
minimatrix --user myuser --password mypass --homeserver https://matrix.example.com rooms

# Send a message
minimatrix --user myuser --password mypass send --room '!abc:example.com' "Hello!"

# Listen for messages
minimatrix --user myuser --password mypass listen --room '!abc:example.com'
```

Or use a config file at `~/.config/minimatrix/config.yaml`:

```yaml
homeserver: "https://matrix.example.com"
user: "myuser"
password: "mypassword"
```

## Configuration

| Variable | Description | Default |
|---|---|---|
| `MATRIX_HOMESERVER` | Matrix homeserver URL | `http://synapse.matrix.svc.cluster.local:8008` |
| `MATRIX_USER` | Matrix username (**required**) | — |
| `MATRIX_PASSWORD` | Matrix password (**required**) | — |
| `CRYPTO_STORE_PATH` | Path for E2E encryption crypto store | `~/.local/share/minimatrix/crypto_store` |
| `AUTH_METHOD` | Auth method (`password`, `sso`, or `jwt`) | `password` |
| `LOGURU_LEVEL` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, ...) | `DEBUG` |

### JWT Authentication (Keycloak)

Set `AUTH_METHOD=jwt` to authenticate via Keycloak ROPC grant instead of direct Matrix password login.

| Variable | Description | Default |
|---|---|---|
| `KEYCLOAK_URL` | Keycloak base URL (required if `jwt`) | — |
| `KEYCLOAK_REALM` | Keycloak realm name (required if `jwt`) | — |
| `KEYCLOAK_CLIENT_ID` | Keycloak client ID (required if `jwt`) | — |
| `KEYCLOAK_CLIENT_SECRET` | Keycloak client secret | `""` |
| `JWT_LOGIN_TYPE` | Matrix login type for JWT auth | `com.famedly.login.token.oauth` |

Requires [synapse-token-authenticator](https://github.com/famedly/synapse-token-authenticator) on the Synapse side. See the [README](https://github.com/vroomfondel/minimatrix#jwt-authentication) for a full setup guide.

## Image Details

- Base: `python:3.14-slim-trixie`
- Non-root user (`pythonuser`)
- Entrypoint: `tini --`
- Multi-arch: `linux/amd64`, `linux/arm64`

## Building the Image

```bash
# Simple local build
docker build -t minimatrix .

# Multi-arch build & push (via GitHub Actions or local script)
./repo_scripts/build-container-multiarch.sh
```

## License
This project is licensed under the LGPL where applicable/possible — see [LICENSE.md](LICENSE.md). Some files/parts may use other licenses: [MIT](LICENSEMIT.md) | [GPL](LICENSEGPL.md) | [LGPL](LICENSELGPL.md). Always check per‑file headers/comments.


## Authors
- Repo owner (primary author)
- Additional attributions are noted inline in code comments


## Acknowledgments
- Inspirations and snippets are referenced in code comments where appropriate.


## ⚠️ Note

This is a development/experimental project. For production use, review security settings, customize configurations, and test thoroughly in your environment. Provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software. Use at your own risk.
