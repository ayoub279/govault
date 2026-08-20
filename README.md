# govault

A small secrets / password-manager REST API written in Go.

- **Auth:** PASETO v2 local tokens (not JWT); passwords hashed with bcrypt (cost 12).
- **Encryption at rest:** secret values are encrypted with AES-256-GCM before hitting the database — plaintext is never stored.
- **Storage:** PostgreSQL via [pgx](https://github.com/jackc/pgx).
- **Router:** [chi](https://github.com/go-chi/chi).

## Requirements

- Go 1.26+
- PostgreSQL 13+ (for `gen_random_uuid()` / `pgcrypto`)

## Project layout

```
govault/
├── cmd/
│   ├── api/          # HTTP server entrypoint
│   └── migrate/      # minimal SQL migration runner
├── internal/
│   ├── auth/         # bcrypt + PASETO token maker
│   ├── config/       # env-based configuration
│   ├── crypto/       # AES-256-GCM encryptor
│   ├── db/           # pgx data-access layer
│   ├── handlers/     # HTTP handlers + validation
│   ├── middleware/   # PASETO auth middleware
│   └── models/       # domain types & request/response shapes
├── migrations/       # plain SQL migrations
└── .env.example
```

## Setup

### 1. Configure environment

Copy the example and fill in real values:

```bash
cp .env.example .env
```

Required variables:

| Variable         | Purpose                                                        |
| ---------------- | -------------------------------------------------------------- |
| `DATABASE_URL`   | PostgreSQL connection string                                   |
| `ENCRYPTION_KEY` | 32-byte AES-256 key, **hex-encoded** (64 hex chars)            |
| `PASETO_KEY`     | 32-byte PASETO symmetric key, **hex-encoded** (64 hex chars)   |
| `PORT`           | HTTP port (optional, defaults to `8080`)                       |

Generate the two keys with:

```bash
openssl rand -hex 32
```

The server refuses to start if either key is missing or not exactly 32 bytes.
`.env` is loaded automatically on startup (real environment variables win over
`.env` values).

### 2. Install dependencies

```bash
go mod download
```

### 3. Run migrations

Two tables are created: `users` and `secrets`.

**Option A — built-in runner (simplest):**

```bash
go run ./cmd/migrate          # apply all .up.sql migrations
go run ./cmd/migrate -down    # roll back with .down.sql
```

It records applied migrations in a `schema_migrations` table so each runs once.

**Option B — [golang-migrate](https://github.com/golang-migrate/migrate):**

```bash
# install the CLI once
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# apply / roll back
migrate -path ./migrations -database "$DATABASE_URL" up
migrate -path ./migrations -database "$DATABASE_URL" down
```

The migration files use golang-migrate's `NNNN_name.up.sql` / `.down.sql`
naming, so both options work against the same files.

### 4. Run the server

```bash
go run ./cmd/api
```

You should see `govault listening on :8080`. Health check:

```bash
curl localhost:8080/healthz
```

## API

All errors use the shape `{"error": "message"}`. All `/secrets` routes require a
`Authorization: Bearer <token>` header.

### `POST /auth/register`

```bash
curl -X POST localhost:8080/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"hunter2hunter2"}'
```

Returns `201` with the created user (no password).

### `POST /auth/login`

```bash
curl -X POST localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"hunter2hunter2"}'
```

Returns `200` with `{"token":"v2.local...","expires_at":"..."}`.

### `POST /secrets`

```bash
curl -X POST localhost:8080/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"github-pat","value":"ghp_xxx"}'
```

Encrypts `value` and stores it. Returns `201` with the secret's metadata (no value).

### `GET /secrets`

Lists the current user's secrets — **names/metadata only, no decrypted values**.

```bash
curl localhost:8080/secrets -H "Authorization: Bearer $TOKEN"
```

### `GET /secrets/{id}`

Returns a single secret **with its decrypted `value`**, only if owned by the
requesting user. `404` otherwise.

```bash
curl localhost:8080/secrets/<id> -H "Authorization: Bearer $TOKEN"
```

### `DELETE /secrets/{id}`

Deletes a secret if owned by the requesting user. Returns `204`.

```bash
curl -X DELETE localhost:8080/secrets/<id> -H "Authorization: Bearer $TOKEN"
```

## Notes

- Validation: emails are format-checked; passwords must be 8–128 chars; secret
  names are non-empty and ≤200 chars; secret values are non-empty and ≤64 KiB.
- Ownership is enforced in SQL (`WHERE user_id = $current`), so one user can
  never read or delete another's secrets.
- Docker / CI / deployment are intentionally out of scope for this phase.
