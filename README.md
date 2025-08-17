# iam-kit

An opinionated Identity and Access Management (IAM) microservice written in Go. It provides email/phone/username/CPF/CNPJ based authentication, JWT access tokens with role claims, refresh token rotation, password recovery, basic OAuth link support, and minimal user administration APIs.

Built with Gin, GORM, and MySQL. Ships with Docker and sensible defaults so you can get running quickly.

## Features

- **Flexible login**: Configure allowed identifier combinations (e.g., email+password, phone+DOB, username only) in the database.
- **Dynamic registration**: Choose which fields are required for sign-up (email, password, phone, username, cpf, cnpj, date_of_birth).
- **JWT access tokens**: HS256 tokens with `uid` and `roles` claims; default TTL 15 minutes.
- **Refresh tokens**: Opaque, random tokens stored hashed in DB with rotation.
- **Roles**: Seeded roles (`admin`, `customer`, `receptionist`, `professional`) and role-restricted routes.
- **Password recovery**: Token-based reset, with SMTP email in prod or debug link in non-prod.
- **CORS + security headers**: Reasonable defaults for local dev.
- **Debug endpoints**: Inspect current login/register configs and users (not for production use).

## Quick start

### With Docker Compose

Prerequisites: Docker Desktop 4.x+.

```bash
make docker-up
# or
docker compose up --build
```

Services:
- MySQL 8.0 on `localhost:3306`
- API on `http://localhost:8080`

Health check:

```bash
curl http://localhost:8080/healthz
```

Tear down:

```bash
make docker-down
# or
docker compose down -v
```

### Local development (without Docker)

Prerequisites: Go 1.22+, MySQL 8.x.

1) Create a database named `iamkit` (or set `DB_NAME`).
2) Export environment variables (see below) or create a `.env` in the repo root.
3) Run the API:

```bash
make run
# or
go run ./cmd/iamkit
```

The server listens on `:${APP_PORT}` (default `8080`). On first run, it auto-migrates tables and seeds roles and default auth configs.

## Configuration

Environment variables and their defaults:

- **APP_ENV**: `dev`
- **APP_PORT**: `8080`
- **DB_HOST**: `127.0.0.1`
- **DB_PORT**: `3306`
- **DB_USER**: `root`
- **DB_PASS**: `` (empty)
- **DB_NAME**: `iamkit`
- **JWT_SECRET**: `super-secret-change-me`
- **JWT_ACCESS_TTL_MIN**: `15`
- **JWT_REFRESH_TTL_H**: `720` (30 days)
- **PASSWORD_RESET_TTL_MIN**: `30`
- **APP_BASE_URL**: `http://localhost:8080` (used to build password reset links)
- **SMTP_HOST**: ``
- **SMTP_PORT**: `587`
- **SMTP_USER**: ``
- **SMTP_PASS**: ``

Example `.env` for local dev:

```env
APP_ENV=dev
APP_PORT=8080

DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASS=
DB_NAME=iamkit

JWT_SECRET=change-me-in-prod
JWT_ACCESS_TTL_MIN=15
JWT_REFRESH_TTL_H=720
PASSWORD_RESET_TTL_MIN=30

APP_BASE_URL=http://localhost:8080

# Optional for email in prod
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
```

## API

Base URL: `http://localhost:8080`

### Health
- `GET /healthz` → `{ "status": "ok" }`

### Auth
- `POST /v1/auth/register`
  - Body (dynamic, defaults): `email` (required), `password` (required), `phone_number`, `username`, `cpf`, `cnpj`, `date_of_birth` (`YYYY-MM-DD`), `role` (defaults to `customer`), `provider`, `provider_user_id` (to link OAuth at sign-up).
  - Response: `{ "user": { "uuid", "email", "emailVerified" } }`

- `POST /v1/auth/login`
  - Body (dynamic): one or more identifiers from `email`, `phone_number`, `username`, `cpf`, `cnpj`, optionally `password` and/or `date_of_birth` depending on configured combo.
  - Response: `{ "accessToken", "accessExp", "refreshToken", "user": { "uuid", "email", "roles" } }`

- `POST /v1/auth/login/oauth`
  - Body: `{ "provider": string, "provider_user_id": string }`
  - Response: tokens + user (same as login).

- `POST /v1/auth/register/oauth`
  - Body: registration fields + `{ "provider", "provider_user_id" }` to create the user and link provider.

- `POST /v1/auth/refresh`
  - Body: `{ "refreshToken": string }`
  - Rotates the refresh token and returns a new `{ accessToken, accessExp, refreshToken }`.

- `POST /v1/auth/logout`
  - Body (optional): `{ "refreshToken": string }` to best-effort revoke.

### Password recovery
- `POST /v1/auth/password/recover` → accepts `{ "email" }` or `{ "phone_number" }`.
  - In `APP_ENV=prod` with SMTP configured, sends an email.
  - In other envs, returns `{ "status": "ok", "debugResetLink": "...", "expiresAt": "..." }`.

- `POST /v1/auth/password/reset` → `{ "token", "new_password" }`.

### Users
- `GET /v1/users/me` → Requires `Authorization: Bearer <accessToken>`.
- `GET /v1/users` → Requires auth + role `admin`.
- `PATCH /v1/users/:uuid` → Admin-only. Fields: `email`, `phone_number`, `username`, `cpf`, `cnpj` with uniqueness checks.

### Debug (dev only)
- `GET /v1/debug/login-configs`
- `GET /v1/debug/register-configs`
- `GET /v1/debug/oauth-providers`
- `GET /v1/debug/users`
- `GET /v1/debug/roles`
- `GET /v1/debug/user-roles`

### Curl examples

```bash
# Register
curl -sS -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"StrongP@ssw0rd"}'

# Login (email + password)
curl -sS -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"StrongP@ssw0rd"}'

# Extract access token (jq) and call /me
ACCESS=$(curl -sS -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"StrongP@ssw0rd"}' | jq -r .accessToken)
curl -sS http://localhost:8080/v1/users/me -H "Authorization: Bearer $ACCESS"

# Refresh
curl -sS -X POST http://localhost:8080/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<paste refresh token>"}'
```

## Data model (high level)

- `users`: identity fields + `UUID` (public identifier) and `IsEmailVerified`.
- `roles`, `user_roles`: role assignments, used for authorization.
- `refresh_tokens`: hashed tokens, expiration, rotation tracking.
- `password_reset_tokens`: hashed tokens with TTL and usage tracking.
- `login_config`: permitted login field combinations and requirements.
- `register_config`: required fields for registration.
- `user_oauth_providers`: links provider name and provider user id to a user.

On startup, the service auto-migrates and seeds base roles and default login/register configurations.

## Security notes

- Change `JWT_SECRET` in all environments; use a strong, random value.
- CORS is wide-open (`*`) by default for development. Lock this down before production.
- Debug routes expose internal data; disable or restrict them in production environments.
- Consider shorter refresh TTLs and stronger SMTP settings for production.

## Examples

Minimal web clients are available in `examples/client-web` and `examples/client-web2` to exercise the endpoints during development.

## Project layout

- `cmd/iamkit`: main entrypoint
- `internal/http`: Gin router, middleware, and handlers
- `internal/models`: GORM models and seeders
- `internal/auth`: JWT and password utilities
- `internal/database`: DB connection and auto-migrations
- `internal/config`: environment configuration loader
- `internal/mailer`: SMTP mailer (optional)
- `examples`: sample clients

## License

See `LICENSE`.
