# govault: Architecture & Design Reference

This is a study document, not a portfolio skim doc — that's what
[`SECURITY.md`](SECURITY.md) is for. This file exists so that every design
decision in govault can be explained, not just pointed at. It assumes you
(the reader, and the author) want to be able to answer "why did you do it
that way" for anything in this codebase, in an interview or otherwise,
without having to go re-derive the reasoning from scratch.

---

## 1. System overview

govault is a small REST API for storing secrets — think a minimal, self-hosted
password manager backend. A user registers with an email/password, logs in
to get an auth token, and then creates, lists, retrieves, and deletes named
secret values (API keys, credentials, anything sensitive) under their own
account. The three pillars of the design are:

- **PASETO** (not JWT) for session tokens
- **AES-256-GCM** for encrypting secret values before they ever touch disk
- **bcrypt** for password hashing

Everything else — the chi router, PostgreSQL via pgx, the Docker image, the
7-job CI pipeline — exists to support those three decisions safely and to
prove, continuously, that they haven't regressed.

### 1.1 Full request lifecycle: `POST /secrets`

This is the most instructive request to trace end to end, because it touches
every layer of the system: auth, validation, encryption, and storage. Here's
exactly what happens, in order, when a client sends:

```
POST /secrets
Authorization: Bearer v2.local.<...>
Content-Type: application/json

{"name": "github-pat", "value": "ghp_super_secret_token"}
```

**Layer 1 — the HTTP server.** `cmd/api/main.go` builds a plain
`*http.Server` with `ReadHeaderTimeout: 10 * time.Second` (a deliberate
defense against slowloris-style attacks — a client that trickles headers in
one byte at a time gets cut off rather than holding a connection open
indefinitely) and hands it a `chi.Router` as the handler.

**Layer 2 — global middleware chain**, applied to *every* request before
routing even happens:

```go
r := chi.NewRouter()
r.Use(chimw.RequestID)
r.Use(chimw.RealIP)
r.Use(chimw.Logger)
r.Use(chimw.Recoverer)
r.Use(chimw.Timeout(15 * time.Second))
r.Use(middleware.SecurityHeaders)
```

- `RequestID` generates a unique ID per request and stores it in context —
  lets you correlate one request's log lines even under concurrent load.
- `RealIP` reads `X-Forwarded-For`/`X-Real-IP` to determine the client's
  actual IP when govault sits behind a proxy or load balancer, instead of
  logging the proxy's own IP for every request. (Worth knowing: this exact
  middleware has a real, disclosed CVE for IP-spoofing via an unvalidated
  `X-Forwarded-For` header — see §5's Dependency Scan row and §6. It's
  low-severity for govault today, since nothing in the app makes an
  authorization decision based on client IP, but it's a real finding this
  pipeline caught in a dependency it was already using.)
- `Logger` writes a structured access log line per request.
- `Recoverer` catches panics anywhere downstream and converts them into a
  `500` instead of crashing the whole process — one bad request shouldn't
  take down every other in-flight request.
- `Timeout(15s)` bounds how long any single request is allowed to run.
- `SecurityHeaders` (govault's own middleware, added in response to a real
  DAST finding — see §5's DAST row) sets `Cache-Control: no-store` and a
  handful of other response headers on every response, unconditionally.

**Layer 3 — route-scoped middleware.** `/secrets` is mounted as its own
sub-router with an additional middleware layer that only applies to this
group:

```go
r.Route("/secrets", func(r chi.Router) {
    r.Use(authenticator.RequireAuth)
    r.Post("/", secretsHandler.Create)
    ...
})
```

`RequireAuth` (`internal/middleware/auth.go`) does the actual authentication
work: pulls the `Authorization` header, requires a `Bearer <token>` shape,
calls `TokenMaker.VerifyToken` (§2 explains exactly what that does
cryptographically), and — critically — stores the resulting `user_id` in the
request's `context.Context` rather than, say, a struct field or a global. If
verification fails at any point, it writes a `401` immediately and the
handler never runs. This is the entire authorization boundary for every
protected route in the app: by the time `SecretsHandler.Create` executes, an
authenticated, verified user ID is guaranteed to already be sitting in
context.

**Layer 4 — the handler.** `internal/handlers/secrets.go`'s `Create` method:

```go
func (h *SecretsHandler) Create(w http.ResponseWriter, r *http.Request) {
    userID, ok := middleware.UserID(r.Context())
    if !ok {
        writeError(w, http.StatusUnauthorized, "authentication required")
        return
    }

    var req models.CreateSecretRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid JSON body")
        return
    }

    name, ok := validateSecretName(req.Name)
    if !ok { /* 400 */ }
    if !validateSecretValue(req.Value) { /* 400 */ }

    ciphertext, err := h.enc.Encrypt([]byte(req.Value))
    ...
    sec, err := h.store.CreateSecret(r.Context(), userID, name, ciphertext)
    ...
    writeJSON(w, http.StatusCreated, models.SecretListItem{...}) // no value, no ciphertext
}
```

The `userID, ok := middleware.UserID(...)` check is technically redundant
with `RequireAuth` already having rejected unauthenticated requests — but
it's cheap, and it means `Create` never silently proceeds with a zero-value
UUID if something about the middleware wiring ever changes. The body is
decoded, then validated (`internal/handlers/validation.go` — plain length
and non-emptiness checks: `maxSecretNameLen = 200`,
`maxSecretValueLen = 64 * 1024`), *before* any crypto or DB work happens —
reject cheap, fail fast.

**Layer 5 — encryption.** `h.enc.Encrypt([]byte(req.Value))` — this is
where the plaintext secret value stops existing as plaintext for the rest
of its life in this system. See §3 for exactly what this call does
(fresh random nonce, AES-256-GCM seal, `nonce||ciphertext||tag` as one
byte slice).

**Layer 6 — the database write.** `h.store.CreateSecret` runs a single
parameterized `INSERT`:

```go
const q = `
    INSERT INTO secrets (user_id, name, encrypted_value)
    VALUES ($1, $2, $3)
    RETURNING id, user_id, name, created_at, updated_at`
```

Note what's *not* in the `RETURNING` clause: `encrypted_value`. The
ciphertext goes in, but the handler never reads it back out of this call —
there's no code path in `Create` that could accidentally echo ciphertext
(or, worse, plaintext) into the response even by mistake.

**Layer 7 — the response.** `writeJSON(w, http.StatusCreated,
models.SecretListItem{...})` — `SecretListItem` is a deliberately narrow
struct: `ID`, `Name`, `CreatedAt`, `UpdatedAt`. There is no `Value` field on
it at all. The response the client gets back confirms the secret was
created and gives back its metadata — never its value, never its
ciphertext. (Compare this to `Get` — §3.2 traces the one code path where a
decrypted value *does* get returned, and only there.)

That's the full path: 15-second request timeout → 5 pieces of global
middleware → auth check → route-scoped auth middleware → JSON decode →
validation → encrypt → parameterized insert → narrow response. Every layer
exists because of a specific thing that could otherwise go wrong, not as
boilerplate.

---

## 2. Authentication deep dive

### 2.1 What PASETO actually is

PASETO (**P**latform-**A**gnostic **SE**curity **TO**kens) is a token format
designed as a direct response to the failure modes JWT enabled. A PASETO
token is a dot-separated string: `version.purpose.payload` (optionally with
a fourth `.footer` segment). govault's tokens look like:

```
v2.local.9jhdEWAGNVNdYwahEMQWDLXLp9fljXX_JdGjmy5-nd7Z...
```

- **`v2`** — the protocol version. Each version fixes *one specific,
  non-negotiable* set of cryptographic primitives. There is no field
  anywhere in a PASETO token that says "trust me, use this algorithm" — the
  version number *is* the algorithm declaration, and it's set by the code
  that verifies the token, not read out of the token itself.
- **`local`** — the "purpose." PASETO has exactly two: `local` (symmetric —
  the token is *encrypted*, not just signed, with a shared secret key that
  both issues and verifies tokens) and `public` (asymmetric — signed with a
  private key, verified with a public key, for cases where the verifier
  shouldn't be able to forge tokens). govault uses `local` because it's both
  the issuer and the sole verifier of its own tokens — there's no
  third-party service that needs to check a token's validity without also
  holding the ability to create one, so there's no reason to pay for
  asymmetric crypto's extra complexity.

### 2.2 What v2.local actually does cryptographically

```go
// internal/auth/paseto.go
type TokenMaker struct {
    v2  *paseto.V2
    key []byte // 32-byte symmetric key
}

func (m *TokenMaker) CreateToken(userID uuid.UUID) (string, time.Time, error) {
    jsonToken := paseto.JSONToken{
        IssuedAt:   now,
        NotBefore:  now,
        Expiration: expiresAt,
    }
    jsonToken.Set("user_id", userID.String())
    token, err := m.v2.Encrypt(m.key, jsonToken, nil)
    ...
}
```

Under the hood, `v2.local` encryption uses **XChaCha20-Poly1305** — an AEAD
cipher (see §3.1 for what AEAD means in depth; the same principle applies
here as it does to secret-value encryption). "X" here means *extended
nonce*: standard ChaCha20-Poly1305 uses a 12-byte nonce, XChaCha20-Poly1305
extends that to 24 bytes. The practical effect is that a 24-byte *randomly
generated* nonce has an astronomically low collision probability even across
huge numbers of tokens, which matters because PASETO's spec has the library
derive the nonce via a keyed BLAKE2b hash of *random bytes plus the message
being encrypted*, not pure randomness — a deliberate nonce-misuse-resistance
design choice (if the random-number generator were ever weak or predictable,
distinct messages still tend to produce distinct nonces, because the message
content itself feeds into the derivation). Contrast that with govault's own
`crypto.Encryptor` (§3), which uses a plain, purely random 12-byte GCM
nonce — a deliberate, different tradeoff appropriate to that use case, and
worth being able to explain the difference between the two if asked.

The payload — the JSON claims (`user_id`, `exp`, `iat`, `nbf`) — is fully
*encrypted*, not just base64-encoded like a JWT payload is. Anyone who
intercepts a govault token cannot read the `user_id` inside it without the
symmetric key; a JWT's payload, by contrast, is plaintext-readable to
anyone who has the token, since JWT only signs (doesn't encrypt) by default.

`VerifyToken` mirrors this: `v2.Decrypt` fails closed on any tampering
(AEAD's authentication tag makes this a hard guarantee, not a "probably"),
and `jsonToken.Validate()` separately checks the time-based claims
(`IssuedAt`/`NotBefore`/`Expiration`) so an old or not-yet-valid token is
rejected even if the crypto checks out.

### 2.3 Why PASETO over JWT — the actual historical vulnerabilities

This isn't a stylistic preference. JWT's flexibility directly enabled two
real, disclosed vulnerability classes that PASETO's design makes
*structurally impossible*, not just patched:

**1. The `alg: none` attack.** A JWT's header declares its own algorithm:
`{"alg":"HS256","typ":"JWT"}`. The JWT spec (RFC 7519) technically permits
`alg: none` as a valid value, meaning "this token is unsecured, don't verify
a signature at all." Several early and popular JWT libraries (across
Node.js, Python, Java, PHP ecosystems) implemented verification by reading
the algorithm *out of the attacker-supplied token* and dispatching to the
matching verification routine — so an attacker could take any legitimate
token, strip its signature, rewrite the header to `alg: none`, and the
library would accept the token as valid with **attacker-controlled claims**,
including things like `role: admin`. This was exploitable across multiple
real libraries, not a theoretical concern.

PASETO has no algorithm field in the token at all. `v2.local` is a fixed
protocol; the verifying code (`m.v2.Decrypt(...)`) is hard-compiled to do
exactly one thing. There's no field an attacker can flip, because the
"algorithm" isn't data inside the token — it's a decision baked into which
Go function you call.

**2. Algorithm confusion (RS256/HS256 confusion).** A JWT signed with
`RS256` (asymmetric: a private key signs, a *public* key verifies) can, in
libraries that dispatch on the token's own declared algorithm, be forged by
an attacker who knows the server's public key (which is, by definition,
public — often published at a `/.well-known/jwks.json` endpoint or embedded
in a client app). The attacker rewrites the header to `alg: HS256`
(symmetric — same key signs and verifies) and signs a forged token using
the RS256 public key *as if it were an HMAC secret*. If the server's
verification code says "read the algorithm from the token, then verify
using `key`" without hard-pinning which algorithm is expected for that
key, it ends up computing `HMAC(publicKey, forgedPayload)` and finding it
matches — because that's exactly what the attacker also computed. This was
publicly documented (notably by Auth0 in 2015) and led to real CVEs across
multiple JWT libraries.

PASETO prevents this two ways at once: there's no algorithm field to
manipulate (as above), *and* `local` and `public` tokens are entirely
separate types with non-interchangeable verification code paths — there is
no single `verify(key, token)` function generic enough that a symmetric key
could accidentally be fed in where an asymmetric public key was expected.
The type system and the API shape make the confusion impossible to express,
not just wrong to do.

The underlying lesson, worth stating explicitly for an interview: **JWT's
flexibility is exactly its own vulnerability surface.** Every algorithm JWT
supports, and every place it lets the token itself declare which one to use,
is a decision an attacker gets to influence. PASETO's rigidity — one
version, one fixed algorithm, no negotiation, ever — isn't a limitation,
it's a deliberate response to having watched what JWT's flexibility
actually enabled in production systems.

### 2.4 bcrypt: why, and what "cost 12" means

```go
// internal/auth/password.go
const BcryptCost = 12

func HashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
    ...
}
```

bcrypt's cost parameter controls the number of key-derivation rounds as
**2^cost**. Cost 12 means **4,096 rounds** of bcrypt's Eksblowfish-based key
schedule. Each increment of cost *doubles* the computation time — cost 13
would be 8,192 rounds, twice as slow. Cost 12 is a widely-used, currently
OWASP-recommended baseline, landing around 200–300ms per hash on typical
server hardware — deliberately, intentionally slow.

**Why not just SHA-256?** SHA-256 is *designed* to be fast — that's a
feature for its actual intended purposes (file integrity checks, digital
signatures, Merkle trees, anywhere you need to hash gigabytes of data
quickly). That exact speed is a liability for password hashing: if an
attacker steals the `password_hash` column, a fast, unsalted-by-default hash
like raw SHA-256 can be brute-forced or dictionary-attacked at *billions* of
guesses per second on commodity GPU hardware — SHA-256 is deliberately
hardware-accelerable (purpose-built ASICs for it already exist, because it's
also what Bitcoin mining uses). bcrypt is deliberately slow *and*
memory/CPU-bound in a way that resists that kind of parallelization far
better (though, in the interest of being precise rather than just favorable:
Argon2id, OWASP's current top recommendation, resists it even better still,
being memory-hard by design — bcrypt remains an acceptable, still-secure
choice, and is what govault uses, but it's honest to know it's not the
newest best-in-class option — see §8).

bcrypt also bakes a random salt into its own output format automatically
(`$2a$12$<22-char-salt><31-char-hash>` — `CheckPassword` doesn't need to
manage a separate salt column at all), which prevents rainbow-table attacks
and guarantees two users with the same password get different stored
hashes — a property you'd have to hand-roll yourself with a bare hash
function.

The **tunable cost factor** is the real long-term defense: as hardware gets
faster, `BcryptCost` can be incremented to keep the *time cost per guess*
roughly constant over the years. A fixed-speed hash has no equivalent dial.

---

## 3. Encryption deep dive

### 3.1 AES-256-GCM: what makes it authenticated encryption

```go
// internal/crypto/crypto.go
func New(key []byte) (*Encryptor, error) {
    block, err := aes.NewCipher(key)       // AES-256 block cipher
    aead, err := cipher.NewGCM(block)      // wrap it in GCM
    return &Encryptor{aead: aead}, nil
}
```

AES (Advanced Encryption Standard) with a 256-bit key is the block cipher.
GCM (**G**alois/**C**ounter **M**ode) is the *mode of operation* — and it's
the mode choice, not the key size, that determines whether this is
authenticated encryption or not.

GCM combines two things in one operation:

1. **CTR-mode encryption** — turns the AES block cipher (which only
   natively encrypts fixed 128-bit blocks) into a stream cipher capable of
   encrypting arbitrary-length plaintext, by encrypting a counter value and
   XORing the result with the plaintext.
2. **GHASH-based authentication** — a MAC computed over the ciphertext
   (using polynomial multiplication in `GF(2^128)`), producing a 16-byte
   **authentication tag** appended to the output.

The result: a single `Seal()` call produces ciphertext *and* a tag that
cryptographically commits to "this exact ciphertext, unmodified." That's
what "authenticated" means, and it's the entire reason GCM was chosen over
plain AES-CBC.

**Why this matters vs. AES-CBC specifically:** CBC alone provides
confidentiality (an attacker can't read the plaintext) but gives **no
integrity guarantee whatsoever**. An attacker who can modify ciphertext
bytes — in transit, or (more relevant here) sitting in a compromised
database — can flip bits in the corresponding decrypted plaintext in
predictable ways (a classic CBC bit-flipping attack), and historically,
systems built on padded CBC without separate authentication have been
broken via padding-oracle attacks (the POODLE and Lucky13 vulnerability
families are the well-known real-world instances) — where an attacker uses
a service's own error behavior ("padding valid" vs. "padding invalid") as
an oracle to decrypt ciphertext byte-by-byte, without ever learning the key
directly. Plain CBC has no way to detect tampering at all — decryption just
silently produces different (potentially attacker-steered) plaintext.

For govault concretely: if an attacker with write access to the
`encrypted_value` column (a compromised DB, a malicious insider, a SQL
injection bug somewhere else in the stack) tampered with stored ciphertext,
GCM guarantees `Decrypt` fails loudly —

```go
func (e *Encryptor) Decrypt(data []byte) ([]byte, error) {
    nonce, ciphertext := data[:ns], data[ns:]
    plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, fmt.Errorf("crypto: decrypt: %w", err)
    }
    ...
}
```

— rather than silently returning corrupted or manipulated plaintext to a
user who'd have no way to know it had been tampered with.

### 3.2 The nonce, and why it must never repeat

GCM requires a **nonce** ("number used once") — 12 bytes here, the standard
size `cipher.NewGCM` expects. govault generates a fresh, cryptographically
random nonce for **every single call** to `Encrypt`:

```go
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
    nonce := make([]byte, e.aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil { ... }
    return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}
```

**Why reuse is catastrophic, precisely:** GCM's keystream is derived from
`AES(key, nonce || counter)`. If the *same* `(key, nonce)` pair is ever used
to encrypt two *different* plaintexts, both ciphertexts are XORed against
the **identical keystream**. XOR the two resulting ciphertexts together and
the keystream cancels out entirely, leaving the XOR of the two plaintexts
exposed — a textbook "two-time pad" break, trivially exploitable with any
known-plaintext assumption or basic statistical analysis of natural-language
or structured secret data.

It gets worse: GCM nonce reuse doesn't just break confidentiality, it breaks
the *authentication* guarantee too. Reusing a nonce leaks the authentication
subkey `H` (this is the published "forbidden attack," Joux 2006, extended by
later researchers), which lets an attacker **forge valid authentication
tags for ciphertext of their own choosing** — the exact property that was
supposed to make tampering detectable becomes attacker-exploitable instead.

This is precisely why the nonce is generated randomly, fresh, every call —
never derived from something like a row ID or an incrementing counter that
could theoretically collide across restarts, migrations, or concurrent
writes. With a 96-bit (12-byte) random nonce, the birthday-bound collision
probability stays acceptably low up to roughly `2^32` encryptions under a
single key (per NIST SP 800-38D's guidance) — far beyond what this
application will perform under one `ENCRYPTION_KEY` before a key rotation
would be warranted for other reasons anyway.

### 3.3 The storage format, traced exactly

`Seal(nonce, nonce, plaintext, nil)` — Go's `cipher.AEAD.Seal` signature is
`Seal(dst, nonce, plaintext, additionalData) []byte`. Passing `nonce` as
*both* the `dst` prefix and the `nonce` argument is the idiomatic Go pattern
for "prepend the nonce to the output": the existing contents of `dst` (the
nonce bytes) are preserved, and the sealed ciphertext+tag get appended after
them. The result is one byte slice: **`nonce || ciphertext || tag`**. That
exact slice — no separate columns, no JSON wrapping, no extra encoding — is
what's written straight into the `encrypted_value BYTEA` column via a
parameterized query; pgx handles `[]byte → BYTEA` binary encoding
automatically.

The full round trip for a secret's `value`, end to end:

1. Client sends `{"value": "ghp_super_secret_token"}` to `POST /secrets`.
2. Handler validates length (non-empty, ≤64 KiB).
3. `crypto.Encrypt([]byte(value))` → `nonce||ciphertext||tag` as `[]byte`.
4. `db.CreateSecret` inserts that `[]byte` directly as `encrypted_value`.
5. On `GET /secrets/{id}`, `db.GetSecret` selects `encrypted_value` back out
   as `[]byte` (pgx decodes `BYTEA` → `[]byte` automatically — no manual
   hex/base64 handling at the SQL layer at all).
6. `crypto.Decrypt(encryptedValue)` slices off the first `NonceSize()`
   bytes as the nonce, calls `Open` on the rest, and returns plaintext.
7. Only `Get` ever populates `sec.Value`. Critically, `ListSecrets`'s SQL
   never selects `encrypted_value` in the first place:

   ```go
   const q = `SELECT id, name, created_at, updated_at
              FROM secrets WHERE user_id = $1 ORDER BY created_at DESC`
   ```

   There is no decrypted value, and not even ciphertext, anywhere in the
   list response — not because the handler chooses not to serialize it, but
   because the query never fetches it from the database at all. That's a
   stronger guarantee than "the JSON struct doesn't have a `Value` field" —
   it means a future refactor that accidentally serializes the whole row
   still can't leak a value it never queried.

---

## 4. Database & ownership model

### 4.1 Why ownership checks live in the `WHERE` clause

Compare two ways to implement "fetch secret X, but only if the requester
owns it":

```sql
-- What govault actually does:
SELECT id, user_id, name, encrypted_value, created_at, updated_at
FROM secrets WHERE id = $1 AND user_id = $2
```

versus the alternative — fetch by ID alone, then check ownership in Go:

```go
// NOT what govault does:
secret := fetchByID(id)
if secret.UserID != requestingUserID {
    return forbidden()
}
```

The `WHERE`-clause version is correct for reasons that go beyond "it's
fewer lines":

**1. The two designs fail in opposite directions.** If a future refactor
ever *forgets* the ownership check in the app-code version — a genuinely
easy mistake: someone adds a new endpoint, copies the fetch-by-ID helper,
and doesn't realize a second check was needed — the bug silently returns
another user's data. That's the worst possible failure mode: it fails
*open*, toward disclosure. The `WHERE`-clause version can't fail that way at
all: `GetSecret(ctx, id, userID)`'s Go signature *requires* a `userID`
argument to compile, and if that argument were ever wrong or omitted, the
query would return zero rows — `ErrNotFound` — never someone else's row. One
design fails toward "you saw something you shouldn't have"; the other fails
toward "not found." Those are not equally bad outcomes.

**2. There's no window where the app holds data it hasn't verified
ownership of.** In the check-after-fetch pattern, the row exists in an
in-memory struct *before* the ownership check has run. Any code that
executes in that window — logging the fetched struct, a cache write, a
webhook, a second code branch a future developer adds without noticing the
check comes later — can leak the row before the check ever happens. In the
`WHERE`-clause version, an unauthorized row is never fetched into the
process's memory in the first place. There is no window, because there's
no separate step.

### 4.2 Why 404, not 403 — the actual information-disclosure reasoning

```go
sec, err := h.store.GetSecret(r.Context(), id, userID)
if err != nil {
    if errors.Is(err, db.ErrNotFound) {
        writeError(w, http.StatusNotFound, "secret not found")
        return
    }
    ...
}
```

A `403 Forbidden` response makes an explicit, positive claim: *this
resource exists, you're just not allowed to see it.* That confirmation is
itself a disclosure. An attacker who has obtained a candidate secret ID
through some *other* channel — a leaked log line, a URL visible in a bug
report screenshot, a `Referer` header, browser history on a shared machine,
a support ticket — can use a 403-vs-404 split as an oracle: request the ID,
and the response tells them whether it corresponds to a *real* secret that
belongs to *someone*, even though they're not authorized to see its
content. That's confirmed-existence leakage without content leakage — and
it's a real, named category: OWASP's Broken Access Control class (A01:2021
in the OWASP Top 10) explicitly calls this pattern out.

govault's secret IDs are UUIDv4 (122 bits of actual randomness), so blind
enumeration of the ID space alone isn't practical — but the reasoning
matters regardless of ID predictability, because the attacker in the
scenario above isn't guessing; they already have a candidate ID from
elsewhere. Returning a uniform `404` for *both* "doesn't exist" and "exists
but isn't yours" collapses those two cases into one indistinguishable
response and denies that oracle entirely.

This is the same principle behind govault's login endpoint returning an
identical `"invalid email or password"` message whether the email doesn't
exist or the password is simply wrong — same enumeration-prevention logic,
applied to authentication instead of authorization.

**The elegant part, worth stating explicitly:** §4.1's `WHERE`-clause
design and this 404-not-403 decision aren't two separate choices — they're
the *same* one. `WHERE id = $1 AND user_id = $2` produces **zero rows** for
both the not-found case and the wrong-owner case; from `pgx`'s perspective
those are identical (`pgx.ErrNoRows`), which is why `db.go` maps *both* to
one sentinel error, `ErrNotFound`, and the handler needs no special-casing
at all to get the security-correct behavior — there's no
"check-exists-then-check-owned-then-pick-a-status-code" branch that a future
refactor could get subtly wrong. The secure behavior isn't a rule someone
has to remember to follow — it falls directly out of how the query itself
is written.

---

## 5. The full pipeline, job by job

Every push and PR against `main` runs 7 GitHub Actions jobs. Six run fully
in parallel; one is sequential — and the reasoning for that split matters as
much as any individual job.

### Why 6 jobs are parallel and 1 isn't

`build-and-test`, `docker-build` (image build + scan), `secrets-scan`,
`sast-scan`, `dependency-scan`, and `policy-check` all have **no `needs:`**
and start simultaneously. Each one only needs the checked-out source (or, for
`docker-build`, its own from-scratch image build) — nothing about running
any of them depends on another finishing first, so making them wait on each
other would only add wall-clock time for zero correctness benefit. They're
all forms of *static* analysis: source code, dependency manifests, a
Dockerfile, or a freshly-built image, examined without needing the
*application itself to be running*.

`dast-scan` is the sole exception:

```yaml
dast-scan:
  needs: [build-and-test, docker-build]
```

DAST fundamentally requires a **working, running instance** of the app —
there's no such thing as statically analyzing runtime HTTP behavior. Gating
it behind `build-and-test` and `docker-build` succeeding first is a
fast-fail optimization: there's no reason to spend ~2 minutes standing up
`docker-compose` and running a ZAP scan against an app that doesn't even
compile. Important nuance: `needs:` here is a *fast-fail gate*, not an
artifact-sharing mechanism — each GitHub Actions job runs on its own fresh
VM with its own local Docker daemon, so `dast-scan`'s own
`docker compose up --build` rebuilds the image completely from scratch
regardless of what `docker-build` already built. Passing a built image
between jobs would require `docker save` → `upload-artifact` →
`download-artifact` → `docker load`, judged not worth the added complexity
for this project's scale.

### Job 1 — Build & Test

**What:** `go build ./...`, `go vet ./...`, then `go test ./...` — but only
if any `*_test.go` files exist (they currently don't; the job prints a
`::notice::` explaining that plainly rather than pretending). **Tool:** the
Go toolchain itself — no third-party scanner. This job isn't a security
gate; it's the foundation the *other* jobs (and specifically `dast-scan`'s
`needs:`) assume: a binary that actually compiles and passes static
analysis.

### Job 2 — Docker Build & Scan

**What:** builds the real multi-stage Dockerfile via
`docker/build-push-action` (`load: true` so the image lands in this
runner's local Docker daemon), reports its size, then runs **Trivy in image
mode** (`scanners: vuln,misconfig`, `severity: HIGH,CRITICAL`) against the
built image, plus a separate non-root verification step. **Tool:** Trivy,
chosen because it's the standard, actively-maintained OSS container scanner
with a broad vulnerability DB covering OS packages specifically (distinct
from govulncheck/Trivy-fs in Job 5, which scan Go *dependencies*, not OS
packages — this job scans what actually ships).

**The real finding+fix story:** to prove the vulnerability gate actually
works (not just "should work"), the final base image was temporarily
swapped to `debian:9` on a throwaway branch — verified locally first via
the real `trivy` CLI: **30 vulnerabilities, 28 High + 2 Critical.** That
commit failed the job live; reverting to the real base
(`gcr.io/distroless/static-debian12:nonroot`) passed clean — **0
vulnerabilities, 5 packages total**, also verified via the real scan output,
not asserted.

The non-root check has its own story, covered in depth in §6 — Trivy's own
`misconfig` scanner, despite being explicitly enabled, turned out **not** to
evaluate an image's runtime `USER` at all, discovered empirically before
that assumption was ever shipped into the pipeline.

### Job 3 — Secrets Scan

**What:** Gitleaks scans the diff introduced by the push or PR for
credential-shaped strings (regex + Shannon entropy). **Tool:** Gitleaks —
the standard purpose-built secret scanner, chosen because it runs first in
the security sequencing logic (conceptually, if not literally first in
execution order, since this job is parallel too): there's no point running
SAST/dependency analysis on a commit that already leaked a real credential.
`fetch-depth: 0` in the checkout step is there so `gitleaks-action` can
resolve the exact commit range (`event.before..event.after` for a push, or
PR base..head) — **not** so it scans the whole repo history; it only
examines the commits actually introduced by that push/PR.

**The real finding+fix story:** a fake AWS access key was planted in a test
file on a throwaway branch to prove the gate works — but the first attempt
silently didn't trigger anything at all, which led to the discovery
detailed fully in §6.1 (Gitleaks' AWS rule uses a restricted base32
charset). Once corrected, the corrected key failed the job with a real,
redacted finding (`RuleID: aws-access-token`); removing it passed clean.

### Job 4 — SAST Scan

**What:** Semgrep, run inside the official `semgrep/semgrep` container
image directly (not the marketplace `semgrep-action`, which is oriented
around Semgrep's paid SaaS platform and expects a `SEMGREP_APP_TOKEN` this
project doesn't have or need), with `p/golang` and `p/security-audit` rule
packs. `p/secrets` is deliberately **excluded** — Gitleaks already owns
that category as its own dedicated job; adding Semgrep's secrets ruleset
too would just duplicate findings with zero new signal.

**The real finding+fix story:** a genuine SQL-injection pattern — an HTTP
query parameter concatenated directly into a query string instead of a
parameterized query — was planted as a throwaway-branch fixture. The first
version produced *zero* findings, which led directly to the taint-source
discovery covered fully in §6.2. Once the tainted value was sourced from
`*http.Request` (a recognized taint source) instead of a bare function
parameter, the exact same vulnerable sink fired:
`go.lang.security.injection.tainted-sql-string.tainted-sql-string`, real
and redacted in the log.

### Job 5 — Dependency Scan

**What:** two tools, run as independent steps: **govulncheck**
(`golang.org/x/vuln/cmd/govulncheck`) and **Trivy in filesystem mode**
(`scan-type: fs`, `scanners: vuln` only — `misconfig` deliberately excluded
here, since Dockerfile-config scanning isn't this job's job, and secrets
scanning is Gitleaks'). govulncheck does **call-graph reachability
analysis** on top of the official Go vulnerability database
(`vuln.go.dev`): it only flags a CVE if the code under analysis actually
*calls into* the vulnerable code path — not merely because a vulnerable
version happens to sit somewhere in `go.sum`. That makes it dramatically
lower-noise than a naive "is this version ever vulnerable" scan, which would
also flag transitive dependencies the code never actually touches. Trivy
`fs` is the complementary second layer: a broader vulnerability database
that flags a known-bad version straight from `go.mod`/`go.sum` even in
cases where govulncheck's reachability analysis can't establish a call
path (e.g., non-Go-specific advisories, or code paths reachable only
through reflection/plugins that a static call graph can miss).

**The real finding+fix story, in two parts:**

1. A real, historical CVE — **CVE-2021-38561** (GO-2021-0113, an
   out-of-bounds read in `golang.org/x/text/language.Parse`, fixed in
   v0.3.7) — was force-pinned to the vulnerable v0.3.6 via a Go `replace`
   directive and proven reachable, after a first attempt that failed
   silently for reasons covered fully in §6.3 (dead code isn't part of the
   real call graph). Both tools independently caught it in the same CI run
   (`govulncheck outcome=failure, trivy outcome=failure`) — but only after
   fixing the `continue-on-error` design flaw covered in §6.6, which had
   caused the *second* tool to silently never run at all in the first
   version of this job.
2. **Three real, pre-existing CVEs**, unrelated to any deliberate fixture,
   were discovered on `main` itself while validating this job: **chi's
   `RealIP` middleware** (IP spoofing via unvalidated `X-Forwarded-For`,
   `github.com/go-chi/chi/v5@v5.1.0`, fixed in v5.3.0 — the exact middleware
   traced in §1's request lifecycle), **pgx** (SQL injection via
   placeholder confusion with dollar-quoted string literals,
   `github.com/jackc/pgx/v5@v5.7.1`, fixed in v5.9.2), and **x/text**
   (infinite loop on invalid input, present even at the then-current
   v0.21.0, fixed in v0.39.0). All three were confirmed via govulncheck's
   reachability traces (not just "version is old" — actual call paths from
   this project's own code, e.g. `api.run calls chi.Mux.Get, which
   eventually calls middleware.RealIP`), then fixed by bumping all three
   dependencies before this job ever landed on `main` — so `main`'s first
   run of the new job was already green, not red-then-fixed.

### Job 6 — Policy Check

**What:** Conftest (`openpolicyagent/conftest` container image, same
"official image ships the binary, don't `go install` it fresh every run"
pattern as the SAST job) evaluates the Dockerfile against custom Rego
policy files in `/policy/`, parsed into structured instruction data (`Cmd`,
`Stage`, `Value`, `Flags` per Dockerfile line) rather than treated as text.
**Tool choice reasoning:** this is the one job whose entire *purpose* is
different in kind from the other five — it's not detecting a known-bad
pattern (a CVE, a leaked secret, a code smell); it's enforcing *this
project's own explicit, written-down rules* about what a Dockerfile must
look like. Five rules are implemented, each with its own file explaining
what it prevents:

- **No root user** (`no_root_user.rego`) — overlaps intentionally with
  Job 2's `docker inspect` check, as defense-in-depth at an earlier,
  cheaper layer (source, before a build even runs, versus post-build).
- **`ADD` vs `COPY`** (`no_add.rego`) — this is the rule the job actually
  exists to prove, covered next.
- **No package installs in the final stage** (`no_install_in_final_stage.rego`).
- **`HEALTHCHECK` required** (`healthcheck_required.rego`).
- **No hardcoded-looking secrets in `ENV`/`ARG`** (`no_hardcoded_secrets.rego`)
  — explicitly framed as a backstop to Gitleaks, not a replacement.

**The real finding+fix story — the one that proves this layer's distinct
value:** `COPY . .` was swapped for `ADD . .` in the builder stage on a
throwaway branch. This change is functionally identical (a plain local
directory copy — `ADD`'s risky behaviors, archive auto-extraction and
remote URL fetching, only apply to different source shapes) — the build
succeeds, the resulting image is byte-for-byte the same. In the same live
CI run, `policy-check` **failed** while `Build & Test`, `Docker Build &
Scan` (including its non-root check), `Secrets Scan`, `SAST Scan`, and
`Dependency Scan` **all reported clean**. That's not a coincidence to be
proud of — it's the entire point: none of those five jobs parse Dockerfile
*instruction semantics* at all (Gitleaks does regex/entropy over bytes,
Semgrep runs Go-source rule packs, Trivy's misconfig scanning is either
scoped off or only checks for stray IaC files baked into image layers, not
the Dockerfile that built the image). Only a tool that reads the Dockerfile
as structured data, evaluated against rules this project wrote itself,
catches it.

### Job 7 — DAST Scan

**What:** `docker-compose` brings up Postgres and the app for real (not
mocked), migrations run against the compose-started database, a genuine
test user is registered and a test secret created via `curl` so there's
real authenticated data for ZAP to exercise (not just the unauthenticated
`/healthz` and `/auth` endpoints), then `zaproxy/action-baseline` scans the
live instance. The auth token is handed to ZAP via the documented
`ZAP_AUTH_HEADER`/`ZAP_AUTH_HEADER_VALUE`/`ZAP_AUTH_HEADER_SITE` env vars,
so authenticated routes are actually reachable by the scan.

**Baseline vs. full-scan, the actual tradeoff:** baseline is passive-only
(spider + response analysis, no attack payloads sent); full-scan adds
active scanning (real SQLi/XSS/etc. attempts against discovered
parameters). Baseline was the deliberate choice, for three concrete
reasons: govault is a JSON REST API with essentially no HTML links/forms
for ZAP's spider to discover on its own — without an OpenAPI spec (which
this project doesn't have) to seed a proper API-aware scan, active scanning
would mostly attack the same shallow surface baseline already covers, for
several times the runtime; passive analysis is what actually produces this
project's realistic finding class (header/cookie hygiene) regardless of
crawl depth; and baseline is non-destructive against a live, ephemeral,
*authenticated* app — no risk of active payloads corrupting the seeded test
data or hammering the CI-internal Postgres.

**The real finding+fix story:** the actual scan against the actual running
app reported `[Informational] Storable and Cacheable Content` — 2
instances. Real, not staged: govault's responses had no explicit
`Cache-Control: no-store`, meaning a caching proxy sitting in front of the
API could retain a response — and for a secrets manager, a cached response
might contain a decrypted secret value or a live auth token. That's a
specific, legitimate risk tied to what this app actually does, not a
generic checklist item. Fixed with a new `SecurityHeaders` middleware
(§1 already traced where it sits in the request lifecycle); re-scanning the
same live app resolved the finding to ZAP's own confirmatory counterpart,
`[Informational] Non-Storable Content` — proof the fix landed, from the
same tool, against the same running instance, not just a claim.

---

## 6. Tool limitations and mistakes

This is arguably the most valuable section of this document. Every item
below was discovered *empirically*, mid-build, by testing an assumption
against the real tool before trusting it — not by reading a changelog or
assuming the obvious interpretation was correct.

### 6.1 Gitleaks' AWS regex excludes certain digits

The assumption going in was that a fake AWS access key just needed to match
the shape `AKIA` + 16 alphanumeric characters. The first fixture,
`AKIA3F9K2M8P1Q7R4T6W`, produced **zero findings** — both live in CI and,
once tested locally first, against the raw default Gitleaks ruleset with no
custom config involved at all. Reading the actual installed Gitleaks
binary's embedded rule (`go install`ed locally specifically to check this)
revealed the real regex:

```
\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b
```

The suffix character class is `[A-Z2-7]` — a base32-style alphabet that
specifically **excludes `0`, `1`, `8`, `9`**. Real AWS access key IDs are
generated using exactly this charset, to avoid visual ambiguity between
characters like `O`/`0` or `I`/`1`/`l`. The fixture's `9`, `8`, and `1` were
all outside the allowed set, so the regex silently never matched. A
corrected all-letters key, `AKIAQWERTYUIOPASDFGH`, was tested locally
*first* (confirmed to trigger `RuleID: aws-access-token`) before ever being
pushed to CI — the fix that mattered wasn't the new key, it was the habit of
never trusting a "should work" fixture without checking it against the real
tool first.

**Why this matters beyond this one bug:** a regex-based scanner's coverage
is exactly as good as its regex, and that regex is an implementation
detail, not a spec — it can be stricter, or looser, or just *different*
than intuition suggests, and the only way to know is to read it or test
against it directly.

### 6.2 Semgrep's taint mode requires a real, recognized source

The rule in question, `go.lang.security.injection.tainted-sql-string`, is a
**taint-mode** rule — not a simple syntactic pattern match. Semgrep's taint
engine tracks data flow from declared *sources* to declared *sinks* through
a function's control-flow graph. A rule author has to explicitly declare
what counts as a source (specific stdlib types/functions known to carry
attacker-controlled data — `*http.Request`'s header/query/form accessors,
`os.Args`, and so on). A bare function parameter, even one a human reader
would immediately recognize as "obviously untrusted input" from context, is
**not** automatically tainted — Semgrep has no way to infer, from a
function signature alone, that a `string` parameter will eventually be
filled with attacker-controlled data.

The first fixture wrote exactly that: a function taking a plain `name
string` parameter, concatenated into a SQL string. Zero findings. Rewriting
the identical vulnerable sink logic to instead source the value from
`r.URL.Query().Get("name")` inside an HTTP-handler-shaped function — i.e.,
routing the *same* string through `*http.Request`, a source Semgrep's Go
rule set actually recognizes — made the exact same sink fire immediately,
with the exact same rule ID.

**The lesson:** taint analysis reasons about data flow from *known
origins*, not "does this look dangerous." A human reviewer's intuition
about what's obviously attacker-controlled doesn't automatically transfer
to a static analyzer unless the analyzer has explicitly been told the same
thing about that specific source.

### 6.3 govulncheck's reachability analysis correctly ignores dead code

govulncheck runs in "source" analysis mode by default, building a real call
graph rooted at the actual usage in the packages under analysis — not
"does the vulnerable symbol appear anywhere in an imported package's
source." The first CVE-2021-38561 fixture wrote a function that called the
vulnerable `language.Parse`, but nothing else in the codebase ever called
*that function* — it was dead, orphaned code sitting in a package. Running
govulncheck against it still reported the CVE as present (because it's
genuinely reachable through an unrelated path — pgx's own dependency chain
happens to reach the same vulnerable function internally), but the reported
trace pointed entirely through that pgx-driven path, not through anything
the fixture had written.

To prove reachability through code actually written for this project, an
`init()` function had to be added that genuinely called the fixture — with
a safe, non-nil dummy `*http.Request` so nothing would panic if it were
ever accidentally executed at runtime. Only then did govulncheck's trace
explicitly include
`internal/handlers/vuln_test_fixture.go:26:23: handlers.vulnTestFixtureParseAcceptLanguage
calls language.Parse` alongside the pre-existing pgx-driven trace.

**The lesson:** "reachability" is a real, load-bearing claim about the
actual call graph, not marketing language — an uncalled function, no matter
what it imports or calls internally, genuinely isn't part of a program's
real behavior, and a reachability-aware scanner is *correct* to exclude it.
This is also precisely why govulncheck produces far less noise than a naive
dependency-list scanner: a vulnerable transitive dependency nothing in the
call graph ever actually invokes is real, legitimate noise that a
reachability-aware tool correctly declines to report.

### 6.4 Trivy's image misconfig scanner doesn't check runtime `USER`

This is the finding worth leading with in an interview, and the reasoning
is worth having fully internalized, not just summarized. The assumption
going in — reasonable on its face — was that Trivy's `image` scan mode,
with `scanners: misconfig` explicitly enabled, would evaluate whether the
built image runs as root. It does not, and this was proven, not assumed:

- Scanning govault's own correctly-configured `nonroot` image reported
  `Misconfigurations: -` ("not scanned" — no config-shaped files found in
  the image filesystem, which is expected: distroless has none).
- Scanning a **known root-by-default** public image (`alpine:3.19`, zero
  `USER` instruction anywhere in its build history) via the *identical*
  `trivy image --scanners misconfig` invocation reported the **exact same
  thing** — `Misconfigurations: -`.

If Trivy's misconfig scanner genuinely evaluated the runtime `USER`, these
two images — one correctly non-root, one definitely root — should have
produced different results. They didn't. That's what actually proves the
scanner isn't checking what it sounds like it should: not a hunch, not a
docs-reading exercise, a controlled comparison against a known-good and a
known-bad case run through the exact same command.

(For completeness: Trivy's own scan JSON output *does* separately carry
`Metadata.ImageConfig.config.User` as raw metadata — `'65532'` for the
correct image, empty/`None` for the root one — so the underlying data
exists in Trivy's own output. It's simply never surfaced as a misconfig
*finding*.) Given this, govault's actual non-root verification reads the
built image's real post-build user directly:

```bash
USER_ID=$(docker inspect --format='{{.Config.User}}' govault:ci)
if [ -z "$USER_ID" ] || [ "$USER_ID" = "0" ] || [ "$USER_ID" = "root" ]; then
  echo "::error::Container image is NOT configured to run as non-root"
  exit 1
fi
```

**The lesson, stated as plainly as possible:** a security tool that runs
successfully and reports zero findings is not the same thing as a security
tool that checked the thing you assumed it checked. The only way to trust a
clean scan result is to have verified, empirically, that the scanner
actually evaluates the property in question — against both a known-good
and a known-bad input — rather than assuming a clean result means what it
sounds like it means.

### 6.5 The `ADD --from=` Dockerfile syntax mistake

While building the Policy Check throwaway-branch fixture, the first attempt
tried converting an *existing* cross-stage copy —
`COPY --from=build /out/govault /app/govault` — directly to
`ADD --from=build /out/govault /app/govault`. This is not valid Docker
syntax at all: `ADD` does not support a `--from=<stage>` flag; only `COPY`
does. Unlike the other items in this section, this isn't a subtle
behavioral nuance — it's a flatly invalid Dockerfile, and Conftest's own
parser correctly rejected it outright (`unknown flag: --from`) before any
policy logic even ran.

The fix, once understood: instead of trying to convert a *cross-stage*
copy to `ADD` (impossible), the fixture converted a *plain local-directory*
copy in the builder stage instead — `COPY . .` → `ADD . .` — which is
valid, since `ADD` fully supports local-path sources; it just doesn't
support `--from=`.

**The lesson:** even a *deliberately broken* test fixture needs to be built
on accurate knowledge of the syntax and semantics actually being tested. A
fixture that's invalid for reasons unrelated to the policy under test — a
syntax error, not a policy violation — proves nothing and just burns a CI
round-trip on a red herring.

### 6.6 The `continue-on-error` mistake that let a scan tool silently skip

The Dependency Scan job runs two tools as separate sequential steps:
govulncheck, then Trivy. In the first version of this job, the govulncheck
step had no `continue-on-error: true` and no explicit exit-code handling.
GitHub Actions' default behavior: a failing `run:` step immediately halts
the rest of the job's steps, unless later steps are explicitly marked to
run regardless. Since govulncheck exits `3` on any finding, and the
CVE-2021-38561 fixture was designed to trigger exactly that, the job *did*
fail correctly — but the live run revealed something more specific and more
important: the Trivy step that came after govulncheck in the step list
**never executed at all**, because the job aborted at the first failure.

The job's overall red/green status was still technically correct in both
the fail-case and pass-case runs — but the requirement to demonstrate "the
real CVE ID in the findings from at least one of the two tools (ideally
both)" was only ever satisfied by one tool per run. Trivy's independent
confirmation silently never ran. This is exactly the kind of failure that's
easy to miss, because the job's pass/fail *color* looked completely normal;
only reading the actual list of steps that executed — not just the job's
final status — revealed that an entire scanning tool had been skipped.

Fixed by giving both steps `continue-on-error: true` and an `id:`, then
adding an explicit final step:

```yaml
- name: Fail the job if either tool found something
  if: steps.govulncheck.outcome == 'failure' || steps.trivy.outcome == 'failure'
  run: |
    echo "::error::govulncheck outcome=${{ steps.govulncheck.outcome }}, trivy outcome=${{ steps.trivy.outcome }}"
    exit 1
```

This guarantees both tools always run to completion and both sets of
findings always appear in the log, with the job's actual pass/fail
determined explicitly afterward — not as an accidental side effect of step
ordering. The same pattern was proactively applied to the Docker Build &
Scan job's Trivy-image-scan-plus-non-root-check pair once the failure mode
was understood, before it could bite there too.

**The lesson:** in a multi-step CI job, a step's default failure behavior
(halt everything after it) can silently reduce "run N independent checks"
into "run checks until the first one fails" — which is indistinguishable
from the outside by looking at the job's pass/fail badge, but is a
materially weaker guarantee. The difference is invisible unless you
specifically verify which steps actually ran.

### 6.7 Other real mistakes, for completeness

- **A wrong action version tag** (`aquasecurity/trivy-action@0.28.0`,
  missing the `v` prefix that tag actually uses) failed the job immediately
  with "unable to resolve action... unable to find version 0.28.0" before
  anything else in the step could run. Fixed by checking the project's
  actual releases page rather than assuming a version-string convention.
  Small, but a real reminder that a pinned action version has to match the
  *exact* string the publisher tags, not an assumed format.
- **A report-filename conflict in the DAST job.** `zaproxy/action-baseline`
  was first configured to write its report to custom filenames
  (`-J zap-report.json -w zap-report.md -r zap-report.html`) — but the
  action wrapper has its *own* hardcoded expectations
  (`report_html.html`, `report_md.md`, `report_json.json`) that it checks
  for regardless of what's passed through to the underlying script. The
  custom name conflicted, and the job failed at the reporting stage
  (`File .../report_md.md does not exist`) even though the actual ZAP scan
  itself had completed successfully. Fixed by not fighting the action's
  defaults — removed the custom overrides, and had the report-parsing step
  search broadly (`glob`) for `report_json.json` instead of assuming a
  self-chosen name.
- **GitHub's Summary panel became unreliable for an anonymous viewer
  partway through this project** — repeatedly failing to render, and raw
  step logs requiring sign-in outright (a policy state noticed mid-project,
  in contrast to how earlier findings were verified). This wasn't a bug in
  the pipeline; it changed how findings needed to be *surfaced*. The fix
  was to also emit one GitHub Actions annotation
  (`::notice::`/`::warning::`/`::error::`) per individual ZAP finding —
  annotations render reliably on the run page regardless of sign-in state,
  where the step-summary markdown table alone did not. Worth remembering as
  its own category of lesson: the environment you're verifying against can
  change mid-project, and a pipeline's design sometimes has to adapt to
  that, not just to the tools it's running.

---

## 7. What was intentionally scoped out

### 7.1 GCP deployment

Deployment to Google Cloud Platform was planned as its own phase and
deliberately skipped, not forgotten. This project's scope was to build and
prove out a defensible CI/CD security pipeline as a demonstrable artifact —
standing up and *maintaining* a live cloud deployment (a Compute Engine VM
or Cloud Run service, real networking, DNS, TLS certificate lifecycle, IAM,
ongoing billing) is a materially different, ongoing-cost commitment,
orthogonal to demonstrating the pipeline's design quality, and was
consciously deferred rather than attempted poorly under time pressure.

**What a real deployment would actually add, concretely:**

- **Real TLS, and the case for mTLS.** govault currently runs plain HTTP
  throughout — fine for an ephemeral CI-internal instance no external party
  ever reaches, not remotely fine for anything public. A real deployment
  needs a real certificate (Let's Encrypt or a GCP-managed cert), almost
  certainly terminated at a load balancer or reverse proxy in front of the
  container, with HSTS enabled. **mTLS** specifically (mutual TLS — the
  *client* also presents a certificate, not just the server) matters most
  if govault were called by other internal services rather than end users
  directly: it establishes *service identity*, not just server identity,
  which is standard in zero-trust internal architectures. For a secrets
  manager specifically, mTLS on service-to-service calls (the model
  HashiCorp Vault and AWS Secrets Manager both support) is a meaningfully
  stronger guarantee than bearer-token auth alone — a stolen PASETO token
  is usable by anyone holding it, while mTLS ties the connection itself to
  a possessed private key.
- **Real network exposure decisions.** Postgres should never be reachable
  from the public internet — in the current `docker-compose.yml` it's
  published to the host purely for local dev convenience
  (`ports: - "5432:5432"` on the `db` service), which would be actively
  wrong in a real deployment; a VPC/firewall design needs explicit,
  deliberate thought about which ports are internet-facing versus
  internal-only.
- **Real secrets management for `ENCRYPTION_KEY`/`PASETO_KEY`.** These are
  currently generated fresh per CI run, or set manually in a local,
  gitignored `.env` — appropriate for development and for an ephemeral test
  instance, not for production. A real deployment needs a proper secrets
  store (GCP Secret Manager, specifically) with a real key-rotation plan,
  not a value sitting in a VM's environment variables indefinitely.
- **Runtime observability.** The pipeline currently has zero runtime
  monitoring — no metrics, no centralized log aggregation beyond chi's
  per-request access logger, no alerting on error rates or latency. A real
  deployment needs all of that before it's operable, not just correct.

### 7.2 DAST limitations: CI-internal instance vs. a real deployed target

The ZAP scan (§5, Job 7) is genuinely testing a live, running instance of
the app — that's real and worth being confident about. But it's honest to
be equally clear about what it *doesn't* test, precisely because it's not
a real deployment:

- **No real network exposure to test.** ZAP scans entirely over plain HTTP
  to `localhost` inside a single GitHub-hosted runner. A real deployment's
  actual attack surface — which ports are open externally, what sits behind
  a load balancer versus what's directly reachable, whether an internal
  admin endpoint is accidentally internet-facing, whether the TLS
  configuration itself is sound — is completely untested by a scan that
  never leaves localhost.
- **No realistic data or traffic.** Every run starts from a freshly
  migrated, empty database with exactly one seeded test user and one
  seeded test secret, torn down at the end of the job. ZAP can never
  discover issues that only manifest with accumulated state, real data
  volume, or realistic multi-tenant traffic patterns.
- **Simplified authentication.** The `ZAP_AUTH_HEADER*` mechanism hands ZAP
  a valid Bearer token directly, fetched by the CI script beforehand. This
  proves ZAP *can* exercise authenticated routes, which is real and useful
  — but it's closer to component testing with authentication provided than
  true end-to-end black-box testing that includes probing the login flow
  itself. A scan against a real deployment would more realistically
  configure ZAP to perform the login flow independently via its own
  authentication scripting.
- **Passive-only by design (§5).** No attack payloads are ever sent, on
  purpose, for the reasons already covered — but that also means this setup
  deliberately does not attempt what a real external pentest or an active
  scan against a real deployment eventually would.

None of this is stated to undersell the DAST job — the Cache-Control
finding in §5 was a completely real, useful catch. It's stated because
overstating a CI-internal scan as equivalent to testing a live deployment
would be exactly the kind of claim this whole pipeline's design philosophy
(§6.4 especially) argues against making without verification.

---

## 8. Interview prep

Likely questions, and how to answer them using everything above.

**"Why PASETO over JWT?"**
Lead with the mechanism, not just the conclusion: JWT lets the *token
itself* declare which algorithm verifies it, and that flexibility directly
enabled two real, disclosed vulnerability classes — the `alg: none` attack
(some libraries would skip verification entirely if a token simply claimed
no algorithm was in use) and RS256/HS256 algorithm confusion (forging a
token by re-signing it with a public key treated as an HMAC secret).
PASETO removes algorithm negotiation from the token format entirely — the
version number is a fixed, non-negotiable protocol, verified by which
function you call, not by data an attacker controls. It's not a stylistic
preference; it's eliminating a whole class of vulnerability structurally,
rather than patching specific instances of it.

**"Walk me through your pipeline."**
7 jobs, 6 parallel (Build & Test, Docker Build & Scan, Secrets Scan, SAST
Scan, Dependency Scan, Policy Check) plus one sequential (DAST, gated behind
the first two succeeding, because it needs an actual running instance, not
just source to analyze). Name the tool for each and the one-line reason it's
that specific tool, not "a scanner": Gitleaks for regex/entropy secret
detection, Semgrep for Go-source vulnerability patterns, govulncheck for
reachability-scoped CVE checking plus Trivy for broader dependency-DB
coverage, Trivy again for the built container image specifically,
Conftest/OPA for Dockerfile rules nothing else can see, ZAP for actual
runtime behavior. The part worth emphasizing: every one of those six
security jobs has a real, proven fail→fix→pass cycle behind it from actual
development, not a checklist entry added and never exercised — see
`SECURITY.md` for the compressed version with links to the actual CI runs.

**"What was the hardest bug or most interesting finding?"**
The Trivy image-misconfig-scanner one (§6.4) is the strongest answer: it's
not "a scanner found a bug," it's "I discovered a security tool doesn't
check what it sounds like it checks, and I proved that empirically with a
controlled comparison — a known-good image and a known-bad image scanned
identically, both returning 'not scanned' — rather than trusting a clean
result because nothing turned red." A strong second example if asked for
another: govulncheck correctly excluding an uncalled function from its
reachability analysis (§6.3) — a case where the tool being *right* required
understanding call-graph analysis well enough to know the fixture needed
fixing, not the tool.

**"What would you do differently with more time?"**
Be concrete and honest, not vague:
- Add real Go unit and integration tests — `Build & Test` currently prints
  `::notice::No _test.go files found yet` on every single run, and that's
  visible in the pipeline's own output, worth naming directly rather than
  hoping it doesn't come up.
- Add an OpenAPI spec and run an active ZAP scan (or ZAP's API-scan mode)
  against it, instead of baseline-only passive scanning.
- Actually deploy to GCP with real TLS (and evaluate mTLS for
  service-to-service calls), real network segmentation (Postgres never
  internet-facing), and real secrets management via GCP Secret Manager
  with a key-rotation plan.
- Consider Argon2id over bcrypt — OWASP's current top recommendation for
  password hashing, more memory-hard than bcrypt. bcrypt at cost 12 remains
  a secure, defensible choice; Argon2id is simply the newer best-in-class
  option, and it's honest to know the difference rather than imply bcrypt
  was the only reasonable pick.
- Consider PASETO v4 over v2 — v4 uses BLAKE2b for key derivation and is
  the version the PASETO ecosystem is gradually converging on as primary;
  v2 remains secure, but v4 is the more current recommendation.
- Add a token revocation mechanism. PASETO tokens are stateless and can't be
  individually invalidated before their 24-hour expiry short of rotating
  the entire `PASETO_KEY`, which invalidates *every* outstanding token at
  once. A real system would want either a short-lived-token-plus-refresh
  pattern or a lightweight revocation list for compromised-token scenarios.
  This is a genuine, honest architectural tradeoff worth naming unprompted.
- Add rate limiting and centralized logging/metrics — currently zero
  runtime observability beyond per-request access logs.

**"Why does the policy-as-code layer add value on top of Trivy, Semgrep,
and Gitleaks — isn't that redundant?"**
Two of the five policy rules *are* intentionally redundant, as
defense-in-depth at a cheaper/earlier layer (non-root, secrets-in-ENV) —
worth saying plainly rather than pretending every rule is unique. But the
other three (ADD-vs-COPY, no-installs-in-final-stage, HEALTHCHECK-required)
check something structurally invisible to every other tool in the
pipeline: Dockerfile *instruction semantics*. Proven live, not asserted: a
`COPY`→`ADD` swap left every other one of the six jobs reporting clean in
the same CI run — the image is byte-identical, no CVE, no secret, no
Go-source pattern. Only a tool that reads the Dockerfile as structured data
against explicit, project-specific rules catches it. That's the actual
distinction between "detects known-bad patterns" (what the scanners do) and
"enforces our own written standards" (what policy-as-code does) — they're
complementary, not overlapping, for that subset of rules.

**"Explain the ownership/404-vs-403 decision."**
Two things that look like separate choices are actually the same one.
`WHERE id = $1 AND user_id = $2` produces zero rows for both "doesn't
exist" and "exists but isn't yours" — `pgx` can't tell those apart, so both
map to one sentinel error and one `404` response, with no special-casing
required. Returning `403` instead would confirm a resource's existence to
someone not authorized to see it — an information leak on its own, useful
to an attacker who already has a candidate ID from some other leak (a log
line, a URL, browser history) and is using the status code as an oracle to
confirm it's real. The security-correct behavior isn't a rule someone has
to remember to follow in application code; it falls directly out of how the
query itself is written.

**"Why AES-256-GCM specifically, and what does the nonce actually do?"**
GCM is authenticated encryption — it produces ciphertext *and* a tag that
cryptographically commits to that exact ciphertext, so any tampering causes
decryption to fail loudly rather than silently returning corrupted or
attacker-manipulated plaintext (unlike plain AES-CBC, which has no
integrity guarantee at all and historically enabled padding-oracle attacks).
The nonce has to be unique per encryption under a given key because GCM's
keystream is derived from `AES(key, nonce||counter)` — reusing a
`(key, nonce)` pair for two different plaintexts produces identical
keystreams, and XORing the resulting ciphertexts together cancels the
keystream out entirely, exposing the XOR of the two plaintexts (a two-time
pad break). Worse, nonce reuse in GCM specifically also leaks the
authentication subkey, letting an attacker forge valid tags for their own
chosen ciphertext. That's why a fresh random 12-byte nonce is generated for
every single `Encrypt` call, never derived from anything that could
collide.

**"What's the biggest architectural risk in the current design?"**
Two honest answers, either is a good one: (1) a single `ENCRYPTION_KEY`
encrypts every secret for every user — there's no per-tenant or per-secret
key, and no key-rotation mechanism yet, so a compromised key compromises
everything encrypted under it, with no way to selectively invalidate. (2)
PASETO's statelessness cuts both ways — no server-side session storage
needed, but also no way to revoke a single compromised token early without
rotating the key for every user's tokens simultaneously. Both are known,
named tradeoffs, not oversights — naming them unprompted is a stronger
answer than waiting to be asked.
