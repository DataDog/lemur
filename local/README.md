# Local Development Environment

This directory contains all configuration and scripts for local Lemur development.

## Quick Start

### Standard Setup
```bash
source .venv/bin/activate && make develop
cd local
docker-compose up -d
```

## Testing Scripts

```bash
# Create test certificates and destinations
docker exec -i local-lemur python3 /opt/lemur/local/testing/create_test_certs_and_destinations.py
```

**Proxy auth integration test** (create certificate and destination as a target user via proxy):

- Guide: [local/testing/PROXY_AUTH_INTEGRATION_TEST.md](testing/PROXY_AUTH_INTEGRATION_TEST.md)
- Run: `./local/testing/proxy_auth_create_cert_and_destination.sh` (from repo root; optional: `BEHALF_OF=user@email.com`, `LEMUR_URL=https://localhost:8447`)

## Proxy auth – local integration

To run an integration that uses **proxy authentication** (a service acting on behalf of a user), use the defaults created when `LEMUR_CREATE_DEFAULTS=true`.

### 1. Default users (created by `create_defaults.py`)

| Purpose | Username | Password | Email | Roles |
|--------|----------|----------|--------|--------|
| **Proxy user** (service account; holds the API token) | `nom` | `pass` | `nom@email.com` | `proxy` |
| **Target user** (admin) | `user` | `pass` | `user@email.com` | `admin` |
| **Target user** (operator) | `operator` | `pass` | `operator@email.com` | `operator` |

### 2. Information needed by the integration

- **Base URL**  
  When running locally: `https://localhost:8447`.

- **Get an API token for the proxy user**  
  `POST /auth/login` with JSON body:
  ```json
  { "username": "nom", "password": "pass" }
  ```
  Response: `{ "token": "<JWT>" }`. Use this token as the service account’s API token.

- **Validate proxy authorization (optional)**  
  `POST /auth/proxy-auth` with JSON body:
  ```json
  { "api_token": "<token from login>", "behalf_of": "user@email.com" }
  ```
  `behalf_of` can be **email** (`user@email.com`) or **username** (`user`).  
  Success: `200` with `{ "authorized": true, "user": { ... } }`.

- **Call APIs as the target user**  
  - Send the **same** API token in the header: `Authorization: Bearer <token>`.
  - Include **`behalf_of`** in the request body for endpoints that support proxy (e.g. create certificate, edit certificate, create destination):
    ```json
    { "behalf_of": "user@email.com", ...other fields... }
    ```
  The server treats the request as if the target user (`user@email.com`) is acting; the token still belongs to `nom`.

### 3. Summary for integration config (local)

| Item | Value (local defaults) |
|------|-------------------------|
| Lemur base URL | `https://localhost:8447` |
| Proxy user (service account) | username `nom`, password `pass` |
| API token | From `POST /auth/login` with `nom` / `pass` |
| Example target user (by email) | `user@email.com` |
| Example target user (by username) | `user` |
| Proxy-auth endpoint | `POST /auth/proxy-auth` |
| Request body for proxy-auth | `{"api_token": "<token>", "behalf_of": "user@email.com"}` |
| Request body for proxy-aware APIs | Include `"behalf_of": "user@email.com"` (or `"operator"`) with the same Bearer token |