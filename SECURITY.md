# govault Security Pipeline

govault is a Go REST API for storing secrets — PASETO (not JWT) for auth,
AES-256-GCM for encryption at rest, bcrypt for password hashing, PostgreSQL
for storage. Every push and pull request against `main` runs through a
7-job GitHub Actions pipeline that gates merges on more than "does it
compile": **Build & Test**, **Docker Build & Scan**, **Secrets Scan**,
**SAST Scan**, **Dependency Scan**, **Policy Check**, and **DAST Scan** all
have to pass. Six of those seven are dedicated security gates, and each one
below is backed by a genuine catch made *during* development — a real
fail→fix→pass cycle, proven live in CI — not a checklist item bolted on and
never exercised.

## What each job actually catches

| Job | Tool | What it catches | Real catch during development |
|---|---|---|---|
| Secrets Scan | Gitleaks | Hardcoded credentials/keys anywhere in the repo | A fake AWS access key planted in a test file — [job failed with the real finding](https://github.com/ayoub279/govault/actions/runs/32659618533), removing it passed clean |
| SAST Scan | Semgrep | Code-level vulnerability patterns in Go source | A genuine SQL-injection pattern — an HTTP query parameter concatenated into a query string — [caught](https://github.com/ayoub279/govault/actions/runs/32660770451) as `go.lang.security.injection.tainted-sql-string` |
| Dependency Scan | govulncheck + Trivy | Known CVEs in Go dependencies, reachability-checked | A real CVE, [CVE-2021-38561](https://pkg.go.dev/vuln/GO-2021-0113), forced into `x/text` and [caught by both tools independently](https://github.com/ayoub279/govault/actions/runs/32747530052) — **plus 3 real, pre-existing CVEs found and fixed in dependencies already pinned on `main`**: chi's `RealIP` middleware (IP spoofing via `X-Forwarded-For`), pgx (SQL injection via placeholder confusion with dollar-quoted strings), and x/text (infinite loop on invalid input) |
| Docker Build & Scan | Trivy (image mode) | OS package vulnerabilities in the *built* container image | Swapped the final stage to `debian:9` — [30 real CVEs](https://github.com/ayoub279/govault/actions/runs/32862967745) (28 High, 2 Critical). The image actually shipped (distroless) scans at 0 vulnerabilities, 5 packages |
| Policy Check | OPA / Conftest | Dockerfile instruction-level rules, written as explicit code | `COPY` silently swapped for `ADD` in the builder stage — build succeeds, resulting image is byte-identical, and [every other job in the pipeline reported clean](https://github.com/ayoub279/govault/actions/runs/32866578203). Only the policy layer catches it — that's the point of this job existing |
| DAST Scan | OWASP ZAP | Runtime HTTP behavior against a live instance of the app | Missing `Cache-Control: no-store` — a concrete risk for an API that returns decrypted secrets and auth tokens, not a generic hygiene nag. Fixed with new middleware; [re-scan confirmed resolved](https://github.com/ayoub279/govault/actions/runs/33304957556) |

Every fail-case commit above lived on a throwaway branch, was proven live in
CI, then reverted — none of the deliberately broken states ever touched
`main`. The branches are still on GitHub if you want to see the raw
before/after.

## Lessons learned: tool limitations aren't obvious from the README

Building this surfaced more than the findings above — it surfaced *why*
each tool found (or missed) what it did, which turned out to be the more
useful thing to understand:

- **Gitleaks' AWS-key rule uses a base32 charset** (`[A-Z2-7]`), not
  `[A-Z0-9]`. A test key with an `8`, `9`, or `1` in it silently didn't
  match — found by reading the actual compiled rule, not the docs, after
  a first attempt produced zero findings.
- **Semgrep's taint-mode SQLi rule requires a recognized untrusted
  source.** Passing tainted data through a plain function parameter
  produced no findings; only routing the same string through
  `*http.Request` made the rule fire. The rule isn't "does risky-looking
  data reach a query" — it's "does data from a *known* source reach one."
- **govulncheck's reachability analysis correctly ignores dead code.** A
  call to a vulnerable function that nothing else invokes isn't part of
  the real call graph and is correctly excluded — even with the vulnerable
  import still present. Proving the reachability check meant adding an
  actual call path, not just importing the package.
- **Trivy's image-mode misconfig scanner does not evaluate an image's
  runtime `USER`**, despite that being a reasonable assumption. Confirmed
  by scanning a known root-by-default public image — it reported
  "not scanned" for misconfig, identical to a correctly non-root image.
  This pipeline's actual non-root check reads `docker inspect` output
  directly instead of relying on that scanner.

In every case, the fix wasn't "add another tool" — it was reading exactly
what the tool checks before trusting a pass or a fail.

## Scope note

Phase 9 (deployment to GCP) was intentionally scoped out. DAST (OWASP ZAP)
therefore scans an instance of govault brought up via `docker-compose`
**inside the CI job itself** — migrations run, a test user and secret are
seeded, then ZAP scans that ephemeral instance. This is not a live or
public deployment, and there is no production environment behind this
pipeline yet. Stated plainly: this pipeline validates the application and
its container image thoroughly; it does not validate a real deployed
environment.
