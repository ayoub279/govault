package handlers

// THIS FILE IS A DELIBERATE TEST FIXTURE for verifying the Semgrep CI job
// (sast-scan) actually catches a real SQL-injection pattern. The function
// below is never called from application code and compiles cleanly (so it
// doesn't disturb the build-and-test job) — only Semgrep should flag it.
// This file is deleted before this branch is done being used; it must never
// be merged into main.

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// vulnTestFixtureSearchSecrets demonstrates SQL injection: an HTTP query
// parameter is concatenated directly into a SQL string instead of using a
// parameterized query ($1), unlike every real query in internal/db/db.go.
func vulnTestFixtureSearchSecrets(pool *pgxpool.Pool, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// VULNERABLE ON PURPOSE — do not copy this pattern.
	query := "SELECT id, name FROM secrets WHERE name = '" + name + "'"

	rows, err := pool.Query(r.Context(), query)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
