# Keycloak mock server in go

This repository contains a Go application that implements API endpoints that mock a Keycloak instance by providing JWT and JWKS, but **without actually being secure**. Everything that would normally be secret is hardcoded, and nothing is validated. Signed tokens are given out as the user requests them.

This is helpful for E2E tests where we need a valid token from an issuer that is signed, but don't want to deal with logging in or managing test user roles.

The realm name defaults to `"mock"` but is configurable via `config.json`.

## Features

- **PKCE Authorization Code Flow** - Used by keycloak-js. When multiple users are configured, presents a user-selection page; otherwise redirects immediately with an authorization code
- **Client Credentials Grant** - For service-to-service authentication
- **Refresh Token Grant** - For token renewal
- **Custom Token Endpoint** - Generate tokens with custom claims via JSON API

## Running

```bash
go run ./cmd/mock-keycloak/
```

By default, reads configuration from `config.json`. Override with `CONFIG_PATH` environment variable:

```bash
CONFIG_PATH=/path/to/config.json go run ./cmd/mock-keycloak/
```

## Running in Docker

```bash
docker build -t mock-keycloak .
docker run --rm -p 10101:10101 -v "$PWD/my-config.json:/config/config.json:ro" mock-keycloak
```

The mounted config must set `"addr": ":10101"`: the image exposes 10101 and the examples here map and health-check that port, while the server's default is `:8080`. Its `baseURL` must be the URL clients use to reach the container (for the command above, `http://localhost:10101`), because it becomes the tokens' `iss`.

The image reads its config from `/config/config.json` (`CONFIG_PATH`) and runs as a non-root user (uid 10001) with `/data` as its working directory. A relative `signingKeyFile` (the default is `jwt-signing.key`) therefore resolves into `/data`, and so do relative `tls` paths. Mount a volume at `/data` to keep the signing key, and with it the JWKS, stable when the container is recreated. The server creates the key file on first start but not its directory: a `signingKeyFile` of `certs/jwt-signing.key` needs `/data/certs` to exist and be writable by uid 10001.

A compose file can build the image straight from git, without a local checkout:

```yaml
services:
  keycloak:
    build:
      context: git@gitlab.streamonkey.net:testing/mock-keycloak.git#master
    ports:
      - "127.0.0.1:10101:10101"
    volumes:
      - ./mock-keycloak.json:/config/config.json:ro
      - mock-keycloak-data:/data
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:10101/healthz"]
      interval: 5s

volumes:
  mock-keycloak-data:
```

BuildKit clones the repository over SSH using the host's SSH agent (`$SSH_AUTH_SOCK`), so the agent needs a key with access to the repository. The healthcheck calls the busybox `wget` of the alpine base image and assumes a plain-HTTP config (no `tls` block).

## Configuration

Create a `config.json` file:

```json
{
  "baseURL": "https://local.streamonkey.net:10101",
  "addr": ":10101",
  "realm": "mock",
  "signingKeyFile": "certs/jwt-signing.key",
  "tls": {
    "certFile": "/path/to/cert.pem",
    "keyFile": "/path/to/key.pem"
  },
  "users": [
    {
      "sub": "00000000-0000-0000-0000-000000000000",
      "name": "Mock User",
      "email": "mock@example.com",
      "email_verified": true,
      "preferred_username": "mockuser",
      "given_name": "Mock",
      "family_name": "User",
      "groups": [],
      "realm_access": {
        "roles": ["user"]
      },
      "resource_access": {}
    },
    {
      "sub": "00000000-0000-0000-0000-000000000001",
      "name": "Alice Admin",
      "email": "alice@example.com",
      "email_verified": true,
      "preferred_username": "alice",
      "given_name": "Alice",
      "family_name": "Admin",
      "groups": ["admins"],
      "realm_access": {
        "roles": ["admin"]
      },
      "resource_access": {
        "dashboard": { "roles": ["essentials", "pro"] }
      }
    }
  ],
  "clients": {
    "backend-service": {
      "sub": "11111111-1111-1111-1111-111111111111",
      "name": "Backend Service",
      "email": "service@example.com",
      "email_verified": true,
      "preferred_username": "backend-service",
      "given_name": "Backend",
      "family_name": "Service",
      "groups": [],
      "realm_access": {
        "roles": ["service"]
      },
      "resource_access": {}
    }
  }
}
```

| Field            | Description                                                                                                                                                                                            |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `baseURL`        | The externally-reachable URL of the mock server. Used as the `iss` (issuer) claim in tokens.                                                                                                           |
| `addr`           | The address to listen on (e.g., `:8080` or `127.0.0.1:8080`)                                                                                                                                           |
| `realm`          | The Keycloak realm name used in URL paths and the issuer claim. Defaults to `"mock"`.                                                                                                                  |
| `signingKeyFile` | Path to RSA private key for JWT signing. If not set, defaults to `jwt-signing.key`. See below.                                                                                                         |
| `tls`            | Optional TLS configuration. If both `certFile` and `keyFile` are set, the server starts with HTTPS. **Recommended**                                                                                    |
| `users`          | **Required.** Array of user objects (at least one). The first user is the default fallback. When multiple users are configured, the PKCE flow shows a user-selection page.                             |
| `clients`        | Optional map of `client_id` to user claims. When a token is requested, the server looks up the `client_id` and uses the matching user configuration. Falls back to the first user for unknown clients. |

### User Selection

The `users` array defines the available users for the PKCE authorization code flow:

- **Single user** — The authorization endpoint immediately redirects with an authorization code (no login page). The single configured user's claims are used.
- **Multiple users** — The authorization endpoint renders a user-selection page where you pick which user to log in as. The selected user's claims are embedded in the resulting tokens.

The first user in the array acts as the default fallback for client credentials grants and unknown client IDs.

```json
{
  "users": [
    {
      "sub": "user-1",
      "name": "Alice",
      "preferred_username": "alice",
      "resource_access": { "dashboard": { "roles": ["admin"] } }
    },
    {
      "sub": "user-2",
      "name": "Bob",
      "preferred_username": "bob",
      "resource_access": { "dashboard": { "roles": ["viewer"] } }
    }
  ]
}
```

### Per-Client Users

When a service receives requests from both frontend users and backend services, you may need different token claims for each. The `clients` map allows you to configure a different user for each OAuth client:

```json
{
  "users": [{ "..." : "..." }],
  "clients": {
    "frontend-app": {
      "sub": "user-1",
      "name": "Frontend User",
      "resource_access": { "dashboard": { "roles": ["user"] } }
    },
    "backend-service": {
      "sub": "service-1", 
      "name": "Service Account",
      "realm_access": { "roles": ["service"] }
    }
  }
}
```

- Requests with `client_id=frontend-app` will receive tokens with "Frontend User" claims
- Requests with `client_id=backend-service` will receive tokens with "Service Account" claims
- Requests with any other `client_id` will use the first entry in `users`

### Signing Key Persistence

The server uses an RSA key pair to sign JWTs. The key is persisted to disk so that the JWKS remains stable across restarts, allowing other services to cache the public key.

**Behavior:**
- On startup, the server attempts to load the private key from `signingKeyFile`
- If the file doesn't exist, a new 2048-bit RSA key pair is generated and saved (PKCS#8 PEM format)
- The key ID (`kid`) is derived deterministically from the public key (SHA-256 hash), ensuring stability

**Generating a key manually:**

```bash
openssl genpkey -algorithm RSA -out jwt-signing.key -pkeyopt rsa_keygen_bits:2048
```

The server also accepts PKCS#1 format (`BEGIN RSA PRIVATE KEY`).

## Endpoints

All endpoints are served under `/realms/{realm}/`, where `{realm}` is the configured realm name (default: `mock`).

| Endpoint                                                           | Method   | Description                                                            |
| ------------------------------------------------------------------ | -------- | ---------------------------------------------------------------------- |
| `/realms/{realm}/.well-known/openid-configuration`                 | GET      | OpenID Connect discovery document                                      |
| `/realms/{realm}/protocol/openid-connect/certs`                    | GET      | JWKS endpoint with public keys                                         |
| `/realms/{realm}/protocol/openid-connect/auth`                     | GET/POST | Authorization endpoint (PKCE flow) - shows user selection or redirects |
| `/realms/{realm}/protocol/openid-connect/token`                    | POST     | Token endpoint (authorization_code, client_credentials, refresh_token) |
| `/realms/{realm}/protocol/openid-connect/token/introspect`         | POST     | Token introspection (RFC 7662) - the token's claims, or `active:false` |
| `/realms/{realm}/protocol/openid-connect/userinfo`                 | GET/POST | OIDC userinfo - profile claims from the Bearer access token            |
| `/realms/{realm}/protocol/openid-connect/logout`                   | GET      | Logout endpoint - redirects to post_logout_redirect_uri if provided    |
| `/realms/{realm}/protocol/openid-connect/login-status-iframe.html` | GET      | Session status iframe for keycloak-js (always returns "unchanged")     |
| `/realms/{realm}/protocol/openid-connect/3p-cookies/step1.html`    | GET      | 3rd-party cookie check step 1 (always returns "supported")             |
| `/realms/{realm}/protocol/openid-connect/3p-cookies/step2.html`    | GET      | 3rd-party cookie check step 2 (always returns "supported")             |
| `/realms/{realm}/get-signed-mock-token`                            | POST     | Custom endpoint to generate tokens with specific claims                |

## Usage Examples

### Client Credentials Grant

```bash
curl -X POST https://local.streamonkey.net:10101/realms/mock/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-service&client_secret=any-secret&scope=openid"
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid"
}
```

### PKCE Authorization Code Flow

This flow is used by keycloak-js. When only one user is configured, the authorization endpoint immediately redirects with a code. When multiple users are configured, it presents a selection page first.

```
GET /realms/mock/protocol/openid-connect/auth?
  client_id=my-app&
  redirect_uri=http://localhost:3000/callback&
  response_type=code&
  response_mode=fragment&
  scope=openid&
  state=random-state&
  nonce=random-nonce&
  code_challenge=...&
  code_challenge_method=S256
```

Redirects to: `http://localhost:3000/callback#code=...&state=random-state`

Exchange code for tokens:
```bash
curl -X POST https://local.streamonkey.net:10101/realms/mock/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<code>&redirect_uri=http://localhost:3000/callback&client_id=my-app&code_verifier=..."
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 300,
  "refresh_token": "eyJ...",
  "refresh_expires_in": 1800,
  "id_token": "eyJ...",
  "session_state": "...",
  "scope": "openid"
}
```

### Custom Token Generation

Generate a token with custom claims:

```bash
curl -X POST https://local.streamonkey.net:10101/realms/mock/get-signed-mock-token \
  -H "Content-Type: application/json" \
  -d '{
    "sub": "user-123",
    "name": "Test User",
    "email": "test@example.com",
    "preferred_username": "testuser",
    "realm_access": {"roles": ["admin", "user"]},
    "resource_access": {"my-app": {"roles": ["editor"]}},
    "scope": "openid profile email",
    "exp_seconds": 3600
  }'
```

Returns the signed JWT token as plain text.

### Userinfo

```bash
curl https://local.streamonkey.net:10101/realms/mock/protocol/openid-connect/userinfo \
  -H "Authorization: Bearer <access_token>"
```

Response:
```json
{
  "sub": "00000000-0000-0000-0000-000000000000",
  "name": "Mock User",
  "preferred_username": "mockuser",
  "given_name": "Mock",
  "family_name": "User",
  "email": "mock@example.com",
  "email_verified": true
}
```

The claims are read from the access token itself, so a token from `get-signed-mock-token` works too. Empty profile claims are left out; `sub` and `email_verified` are always present. A POST with the form parameter `access_token=<access_token>` works as well. A bad, expired or foreign token, an ID or refresh token, a token without `sub`, or no token at all gets `401` with an RFC 6750 `WWW-Authenticate: Bearer ...` challenge and a JSON `error` body. Like Keycloak 20 and later, the endpoint also requires `openid` in the token's `scope`: a token without it (e.g. a `client_credentials` token requested without `scope=openid`) gets `403` with `error="insufficient_scope"`.

### Token Introspection

```bash
curl -X POST https://local.streamonkey.net:10101/realms/mock/protocol/openid-connect/token/introspect \
  -u my-service:any-secret \
  -d "token=<token>"
```

Response for a valid token (abridged: every claim of the token is included):
```json
{
  "active": true,
  "client_id": "my-service",
  "username": "mockuser",
  "token_type": "Bearer",
  "sub": "00000000-0000-0000-0000-000000000000",
  "iss": "https://local.streamonkey.net:10101/realms/mock",
  "exp": 1770384165,
  "scope": "openid"
}
```

`client_id` is the token's `azp`, `username` its `preferred_username` and `token_type` its `typ`, each only when the token has it. Access, ID and refresh tokens are all introspected; `token_type_hint` is ignored. A token that is expired, carries a different issuer, is not signed RS256 with the mock key, or does not parse returns `{"active":false}` and nothing else. The calling client may authenticate via HTTP Basic or `client_id`/`client_secret` form fields, or not at all; nothing is checked. A request without a `token` parameter gets `400 invalid_request`.

## Token Structure

Access tokens include claims matching Keycloak's format:

```json
{
  "iss": "https://local.streamonkey.net:10101/realms/{realm}",
  "sub": "00000000-0000-0000-0000-000000000000",
  "aud": ["client-id", "account"],
  "exp": 1770384165,
  "iat": 1770383865,
  "auth_time": 1770383865,
  "typ": "Bearer",
  "azp": "client-id",
  "sid": "session-id",
  "acr": "0",
  "realm_access": {"roles": ["user"]},
  "resource_access": {},
  "scope": "openid",
  "email_verified": true,
  "name": "Mock User",
  "preferred_username": "mockuser",
  "given_name": "Mock",
  "family_name": "User",
  "email": "mock@example.com"
}
```

ID tokens include the `nonce` claim (echoed from the authorization request) for OIDC compliance.

## Notes

- A new RSA key pair is generated on each startup (key ID changes between restarts)
- All client IDs and secrets are accepted without validation
- Authorization codes are stored in-memory and consumed on use
- PKCE code_challenge/code_verifier are accepted but not validated
- CORS headers are set to allow cross-origin requests from any origin
- Session iframe always returns "unchanged" (no real session management)
- 3rd-party cookie checks always return "supported"
- Userinfo and introspection verify the token's RS256 signature against the mock key, `exp` and `iss`, and userinfo also requires `typ` `Bearer`, a `sub` and the `openid` scope; neither authenticates the calling client, and userinfo returns profile claims only, no roles or groups

## Test Commands

The repository includes test commands to verify the mock server works correctly:

### Test Client Credentials Grant

```bash
go run ./cmd/test-client-credentials/ \
  -issuer https://local.streamonkey.net:10101/realms/mock \
  -client-id my-client \
  -client-secret any-secret \
  -scopes openid
```

This uses `golang.org/x/oauth2` to request a token via the client credentials grant and displays the decoded token payload.

### Test PKCE Flow (keycloak-js)

```bash
go run ./cmd/test-pkce/ \
  -addr :3000 \
  -keycloak-url https://local.streamonkey.net:10101 \
  -client-id my-client
```

Then open http://localhost:3000 in your browser. This serves a web UI that uses keycloak-js to:
- Initialize Keycloak with PKCE (S256)
- Login via the authorization code flow
- Display the decoded access token and ID token
- Refresh tokens
