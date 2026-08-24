module govault

go 1.26

require (
	github.com/go-chi/chi/v5 v5.1.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.1
	github.com/joho/godotenv v1.5.1
	github.com/o1egl/paseto v1.0.0
	golang.org/x/crypto v0.31.0
	golang.org/x/text v0.21.0
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/aead/chacha20poly1305 v0.0.0-20170617001512-233f39982aeb // indirect
	github.com/aead/poly1305 v0.0.0-20180717145839-3fee0db0b635 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/pkg/errors v0.8.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)

// TEMP (test/depscan-verify only): force a known-vulnerable x/text version
// (CVE-2021-38561 / GO-2021-0113, fixed in v0.3.7) to verify the
// dependency-scan CI job actually catches it. Removed before this branch is
// done being used; never lands on main.
replace golang.org/x/text => golang.org/x/text v0.3.6
