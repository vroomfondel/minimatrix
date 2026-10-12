[![black-lint](https://github.com/vroomfondel/minimatrix/actions/workflows/checkblack.yml/badge.svg)](https://github.com/vroomfondel/minimatrix/actions/workflows/checkblack.yml)
[![mypy and pytests](https://github.com/vroomfondel/minimatrix/actions/workflows/mypynpytests.yml/badge.svg)](https://github.com/vroomfondel/minimatrix/actions/workflows/mypynpytests.yml)
[![BuildAndPushMultiarch](https://github.com/vroomfondel/minimatrix/actions/workflows/buildmultiarchandpush.yml/badge.svg)](https://github.com/vroomfondel/minimatrix/actions/workflows/buildmultiarchandpush.yml)
[![Cumulative Clones](https://img.shields.io/endpoint?logo=github&url=https://gist.githubusercontent.com/vroomfondel/e2b37502d2c026d6b3c103eba37b16ac/raw/minimatrix_clone_count.json)](https://github.com/vroomfondel/minimatrix)
[![Docker Pulls](https://img.shields.io/docker/pulls/xomoxcc/minimatrix?logo=docker)](https://hub.docker.com/r/xomoxcc/minimatrix/tags)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/minimatrix?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=PyPi+Downloads)](https://pepy.tech/projects/minimatrix)
[![PyPI](https://img.shields.io/pypi/v/minimatrix?logo=pypi&logoColor=white)](https://pypi.org/project/minimatrix/)

[![Gemini_Generated_Image_2bsor82bsor82bso_250x250.png](https://raw.githubusercontent.com/vroomfondel/minimatrix/main/Gemini_Generated_Image_2bsor82bsor82bso_250x250.png)](https://hub.docker.com/r/xomoxcc/minimatrix/tags)

# minimatrix

Standalone Matrix CLI client with E2E encryption. Send messages, listen to rooms,
manage invitations, manage devices, and list joined rooms — all from the command line.

## Features

- **Send** encrypted messages to Matrix rooms
- **Send files** — upload and send images, documents, audio, and video with automatic MIME type detection and E2E encryption
- **Listen** for incoming messages in real-time (prints to stdout)
- **List** joined rooms with display names and member counts
- **Manage invites** — list pending invitations (with inviter, type, timestamp) and accept individually
- **Auto-join** — optionally accept all pending room invitations on startup (`--auto-join`)
- **Device management** — list registered devices, purge orphaned devices, and import E2E keys from old crypto stores
- **Session caching** — persists Matrix access tokens to avoid re-authentication on every run
- **E2E encryption** via matrix-nio with persistent crypto store and device reuse
- **TOFU device trust** — automatically trusts all devices in a room
- **Self-signing (cross-signing)** — signs its own device with the account's cross-signing keys after login, so Element and friends stop flagging its messages with a red "!" (on by default, see below)
- **HTML messages** — optional `formatted_body` next to the plain text (`send --html`)
- **Multiple auth methods**: password, SSO, or JWT via Keycloak (ROPC + JWKS)
- **Flexible config**: YAML file, environment variables, and CLI args (in ascending priority)
- Structured logging via loguru

## Installation

### From PyPI

```bash
pip install minimatrix
```

### From source

```bash
git clone https://github.com/vroomfondel/minimatrix.git
cd minimatrix
make install
source .venv/bin/activate
```

### Docker

```bash
docker build -t minimatrix .
```

## Quick Start

### 1. Create a config file (optional)

```yaml
# ~/.config/minimatrix/config.yaml
homeserver: "https://matrix.example.com"
user: "myuser"
password: "mypassword"
```

### 2. List joined rooms and pending invites

```bash
minimatrix rooms
```

### 3. Manage invitations

```bash
# List pending invites
minimatrix invites
minimatrix invites list

# Accept a specific invite
minimatrix invites accept --room '!abc123:example.com'
```

### 4. Send a message

```bash
minimatrix send --room '!abc123:example.com' "Hello from minimatrix!"

# Or pipe from stdin
echo "Hello from a pipe" | minimatrix send --room '!abc123:example.com'
```

### 5. Send files

```bash
# Send a single file
minimatrix send --room '!abc123:example.com' --file /path/to/image.png

# Send multiple files
minimatrix send --room '!abc123:example.com' -f photo.jpg -f document.pdf

# Send a file with a text message
minimatrix send --room '!abc123:example.com' --file photo.jpg "Check this out!"
```

Files are automatically uploaded with the correct MIME type (`m.image`, `m.audio`, `m.video`, or `m.file`) and encrypted for E2E rooms. Image dimensions are included in metadata when Pillow is installed.

### 6. Listen for messages

```bash
minimatrix listen --room '!abc123:example.com'
# [2026-02-22 14:30:01] <@alice:example.com> Hi there!
# Press Ctrl+C to stop
```

### 7. Manage devices

```bash
# List all registered devices
minimatrix devices
minimatrix devices list

# Import E2E keys from old crypto store DBs
minimatrix devices import-keys
minimatrix devices import-keys --delete-old-stores

# Purge all devices except the current one
minimatrix devices purge

# Cross-sign this device explicitly (fails loudly, exit 1, unlike the implicit signing at login)
minimatrix devices cross-sign
```

### 8. Self-signing / cross-signing

A device nobody vouches for is flagged by Element as *"encrypted by a device not verified by its owner"*
(red "!" on every message). matrix-nio has no cross-signing support, so minimatrix does the minimum itself
after every login (`minimatrix/cross_signing.py`):

1. The three cross-signing keys (master, self-signing, user-signing) are derived deterministically from one secret.
   Without `CROSS_SIGNING_SECRET` a random secret is generated once and kept in `<crypto_store_path>/cross_signing_secret`
   (mode 0600). Set the same `CROSS_SIGNING_SECRET` on every instance that shares one Matrix account
   (e.g. several pods or a separate crypto store per process) — otherwise the second instance derives a different
   master key and cannot sign.
2. If the server does not know the master key yet, the keys are uploaded. Synapse (>= 1.110) accepts the first upload
   without user-interactive auth (MSC3967, Matrix spec v1.11); re-uploading identical keys is always allowed.
   Replacing *existing* keys needs user-interactive auth, which minimatrix does not perform. With password login a
   client such as Element can complete it; JWT/SSO accounts have no browserless UIA stage, so on such accounts a
   master key cannot be replaced via the API at all. The Synapse admin endpoint
   `POST /_synapse/admin/v1/users/<mxid>/_allow_cross_signing_replacement_without_uia` only takes effect when
   Synapse delegates authentication to MAS (Matrix Authentication Service); on a plain Synapse it has no effect.
   **Choose `CROSS_SIGNING_SECRET` before the first run and keep it safe.** Replacing the keys changes the account's
   identity: every contact sees a "digital identity reset" warning and previously verified contacts must re-verify.
3. The current device is signed with the self-signing key.

The secret *is* the master key — treat it like a password. Failures during login are only logged
(the bot keeps working, its messages just stay flagged); `minimatrix devices cross-sign` makes them fatal.
Use `--no-self-sign-keys` / `SELF_SIGN_KEYS=false` for personal accounts that already have cross-signing
set up in another client, unless you deliberately want to replace that identity.

Two processes that use the same Matrix account at the same time must use different `CRYPTO_STORE_PATH`
directories (nio's SQLite store is not safe for concurrent writers) — and therefore need an explicit, shared
`CROSS_SIGNING_SECRET`.

## Configuration

Configuration is resolved in this order (later overrides earlier):

1. **YAML config file** (`~/.config/minimatrix/config.yaml` by default)
2. **Environment variables**
3. **CLI arguments**

### General Options

| Variable / Config Key | CLI Argument | Default |
|---|---|---|
| `MATRIX_HOMESERVER` / `homeserver` | `--homeserver` | `http://synapse.matrix.svc.cluster.local:8008` |
| `MATRIX_USER` / `user` | `--user` | — (**required**) |
| `MATRIX_PASSWORD` / `password` | `--password` | — (**required**) |
| `CRYPTO_STORE_PATH` / `crypto_store_path` | `--crypto-store-path` | `~/.local/share/minimatrix/crypto_store` |
| `AUTH_METHOD` / `auth_method` | `--auth-method` | `password` |
| `AUTO_JOIN` / `auto_join` | `--auto-join` | `false` |
| `SELF_SIGN_KEYS` / `self_sign_keys` | `--no-self-sign-keys` | `true` |
| `CROSS_SIGNING_SECRET` / `cross_signing_secret` | `--cross-signing-secret` | — (generated per crypto store) |
| `LOGURU_LEVEL` | — | `DEBUG` |

### CLI Subcommands

| Subcommand | Description |
|---|---|
| `rooms` | List joined rooms and pending invites |
| `invites [list]` | List pending room invitations (with inviter, DM/Room type, timestamp) |
| `invites accept --room ROOM_ID` | Accept a specific room invitation |
| `send --room ROOM_ID [--file FILE]... [--html HTML] [MESSAGE]` | Send a text message and/or files (reads message from stdin if omitted and no `--file` given); `--html` adds a `formatted_body` |
| `listen --room ROOM_ID` | Listen for messages and print to stdout |
| `devices [list]` | List all devices registered on the homeserver |
| `devices purge` | Delete all devices except the current one |
| `devices import-keys [--delete-old-stores]` | Import megolm sessions from old crypto store DBs |
| `devices cross-sign` | Upload cross-signing keys (if missing) and sign this device; exit 1 on failure |

Use `minimatrix --help` or `minimatrix <subcommand> --help` for full usage.

## JWT Authentication

When `AUTH_METHOD=jwt` is set, minimatrix authenticates via Keycloak ROPC (Resource Owner Password Credentials) grant instead of direct Matrix password login. This enables centralized identity management through Keycloak while allowing non-interactive authentication.

### Authentication Flow

```mermaid
sequenceDiagram
    participant CLI as minimatrix
    participant KC as Keycloak
    participant Syn as Synapse

    CLI->>KC: 1. ROPC grant (username + password)
    KC-->>CLI: 2. JWT access token
    CLI->>Syn: 3. Matrix login (JWT)
    Syn->>KC: 4. Validate JWT (JWKS or introspection)
    KC-->>Syn: JWT valid
    Syn-->>CLI: 5. Matrix access token
```

### Supported Login Types

| Login Type | Synapse Config | Validation Method | Use Case |
|---|---|---|---|
| `com.famedly.login.token.oauth` (default) | synapse-token-authenticator `oauth:` | JWKS endpoint | **Recommended** — automatic key rotation |
| `com.famedly.login.token` | synapse-token-authenticator `jwt:` | Symmetric secret (HS512) | Internal services with shared secret |
| `org.matrix.login.jwt` | Native `jwt_config:` | Public key (RS256) | Simple setup, manual key management |

### JWT Environment Variables

| Variable / Config Key | CLI Argument | Default |
|---|---|---|
| `AUTH_METHOD` / `auth_method` | `--auth-method` | `password` |
| `KEYCLOAK_URL` / `keycloak_url` | `--keycloak-url` | — (required if jwt) |
| `KEYCLOAK_REALM` / `keycloak_realm` | `--keycloak-realm` | — (required if jwt) |
| `KEYCLOAK_CLIENT_ID` / `keycloak_client_id` | `--keycloak-client-id` | — (required if jwt) |
| `KEYCLOAK_CLIENT_SECRET` / `keycloak_client_secret` | `--keycloak-client-secret` | `""` (empty for public clients) |
| `JWT_LOGIN_TYPE` / `jwt_login_type` | `--jwt-login-type` | `com.famedly.login.token.oauth` |

Requires [synapse-token-authenticator](https://github.com/famedly/synapse-token-authenticator) on the Synapse side for the `com.famedly.login.token.*` login types.

## Synapse Setup for JWT Authentication

### Prerequisites

- Keycloak instance (any recent version)
- Synapse homeserver
- Admin access to both Keycloak and Synapse

### Step 1: Keycloak Realm Setup

Create a dedicated realm for Matrix (or use an existing one).

**Recommended realm settings:**
- `registrationAllowed: false` — disable self-registration
- `loginWithEmailAllowed: false` — use usernames, not emails (Matrix localparts)
- `registrationEmailAsUsername: false` — important for Matrix username compatibility

### Step 2: Create OAuth Client

Create a **confidential client** with ROPC (Direct Access Grants) enabled:

| Setting | Value | Reason |
|---|---|---|
| `publicClient` | `false` | Confidential client with secret |
| `clientAuthenticatorType` | `client-secret` | Use client secret for auth |
| `directAccessGrantsEnabled` | `true` | **Required** — enables ROPC grant |
| `standardFlowEnabled` | `false` | No browser redirects needed |
| `serviceAccountsEnabled` | `false` | Not using service account |

After creation, copy the **Client secret** from the **Credentials** tab.

### Step 3: Create User in Keycloak

Create a user account in your Keycloak realm. The Keycloak username must match the desired Matrix localpart — Synapse extracts it from the `preferred_username` JWT claim.

### Step 4: Configure Synapse

#### Option A: OAuth with JWKS Validation (Recommended)

```yaml
modules:
  - module: synapse_token_authenticator.TokenAuthenticator
    config:
      oauth:
        jwt_validation:
          jwks_endpoint: "https://keycloak.example.com/realms/<realm>/protocol/openid-connect/certs"
          localpart_path: "preferred_username"
          require_expiry: true
          validator:
            type: exist
        registration_enabled: true
```

#### Option B: JWT with Symmetric Secret

```yaml
modules:
  - module: synapse_token_authenticator.TokenAuthenticator
    config:
      jwt:
        secret: "your-256-bit-secret-here"
        algorithm: HS512
        allow_registration: false
        require_expiry: true
```

#### Option C: Native Synapse JWT (No Module Required)

```bash
# Get the realm public key
curl -s "https://keycloak.example.com/realms/<realm>" | jq -r '.public_key'
```

```yaml
jwt_config:
  enabled: true
  secret: |
    -----BEGIN PUBLIC KEY-----
    <paste the public key here>
    -----END PUBLIC KEY-----
  algorithm: "RS256"
  subject_claim: "preferred_username"
  issuer: "https://keycloak.example.com/realms/<realm>"
```

### Login Type Comparison

| Feature | `com.famedly.login.token.oauth` | `com.famedly.login.token` | `org.matrix.login.jwt` |
|---|---|---|---|
| Key management | Automatic (JWKS) | Manual (shared secret) | Manual (public key) |
| Key rotation | Automatic | Manual secret update | Manual config update |
| Algorithm | RS256 (asymmetric) | HS512 (symmetric) | RS256 (asymmetric) |
| Module required | Yes | Yes | No |
| **Recommended for** | **Production** | Internal services | Simple setups |

## Troubleshooting

**"Invalid username or password" from Synapse:**
- Verify the Keycloak user exists and password is correct
- Check that `preferred_username` in JWT matches an existing Matrix user (or `registration_enabled: true`)
- Verify JWKS endpoint is accessible from Synapse

**"ROPC grant failed" from Keycloak:**
- Ensure `directAccessGrantsEnabled: true` on the client
- Verify client secret is correct
- Check user is enabled in Keycloak

**"JWT signature validation failed":**
- For JWKS: verify the endpoint URL is correct and accessible
- For native JWT: ensure public key is correctly formatted with PEM headers
- Check `issuer` matches the JWT `iss` claim

### Useful Keycloak Endpoints

| Endpoint | Purpose |
|---|---|
| `/realms/<realm>/.well-known/openid-configuration` | OIDC discovery document |
| `/realms/<realm>/protocol/openid-connect/certs` | JWKS endpoint (public keys) |
| `/realms/<realm>/protocol/openid-connect/token` | Token endpoint (ROPC) |
| `/realms/<realm>` | Realm info (includes public key) |

## Development

| Target | Description |
|---|---|
| `make install` | Create virtualenv and install all dependencies |
| `make tests` | Run pytest |
| `make lint` | Format code with black (line length 120) |
| `make isort` | Sort imports with isort |
| `make tcheck` | Static type checking with mypy (strict) |
| `make commit-checks` | Run pre-commit hooks on all files |
| `make prepare` | Run tests + commit-checks |
| `make pypibuild` | Build sdist + wheel with hatch |
| `make pypipush` | Publish to PyPI with hatch |

Tests are pure unit tests (no Matrix server or network access required) and can be run freely with `make tests`. Pre-commit hooks (`.pre-commit-config.yaml`) include **gitleaks** for secret scanning — be careful not to commit Matrix credentials or tokens.

## License
This project is licensed under the LGPL where applicable/possible — see [LICENSE.md](LICENSE.md). Some files/parts may use other licenses: [MIT](LICENSEMIT.md) | [GPL](LICENSEGPL.md) | [LGPL](LICENSELGPL.md). Always check per‑file headers/comments.


## Authors
- Repo owner (primary author)
- Additional attributions are noted inline in code comments


## Acknowledgments
- Inspirations and snippets are referenced in code comments where appropriate.


## ⚠️ Note

This is a development/experimental project. For production use, review security settings, customize configurations, and test thoroughly in your environment. Provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software. Use at your own risk.
