// Command migrate is a minimal SQL migration runner for govault.
//
// It applies plain .up.sql files from the ./migrations directory in filename
// order, recording each applied file in a schema_migrations table so it runs
// each migration exactly once. Use "-down" to apply the matching .down.sql
// files in reverse order instead.
//
// Usage:
//
//	DATABASE_URL=postgres://... go run ./cmd/migrate          # apply up
//	DATABASE_URL=postgres://... go run ./cmd/migrate -down     # apply down
//	go run ./cmd/migrate -dir ./migrations
//
// For production use, golang-migrate is recommended (see README).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	dir := flag.String("dir", "./migrations", "directory containing .up.sql/.down.sql files")
	down := flag.Bool("down", false, "apply .down.sql migrations in reverse order")
	flag.Parse()

	_ = godotenv.Load()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		log.Fatalf("create schema_migrations: %v", err)
	}

	suffix := ".up.sql"
	if *down {
		suffix = ".down.sql"
	}

	files, err := filepath.Glob(filepath.Join(*dir, "*"+suffix))
	if err != nil {
		log.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		log.Printf("no %s files found in %s", suffix, *dir)
		return
	}
	sort.Strings(files)
	if *down {
		// Roll back most-recent first.
		reverse(files)
	}

	for _, f := range files {
		version := version(filepath.Base(f), suffix)

		applied, err := isApplied(ctx, pool, version)
		if err != nil {
			log.Fatalf("check %s: %v", version, err)
		}

		if !*down && applied {
			log.Printf("skip  %s (already applied)", version)
			continue
		}
		if *down && !applied {
			log.Printf("skip  %s (not applied)", version)
			continue
		}

		sqlBytes, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("read %s: %v", f, err)
		}

		if _, err := pool.Exec(ctx, string(sqlBytes)); err != nil {
			log.Fatalf("apply %s: %v", version, err)
		}

		if *down {
			_, err = pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, version)
		} else {
			_, err = pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version)
		}
		if err != nil {
			log.Fatalf("record %s: %v", version, err)
		}

		action := "apply"
		if *down {
			action = "revert"
		}
		log.Printf("%s %s", action, version)
	}

	log.Println("migrations complete")
}

func isApplied(ctx context.Context, pool *pgxpool.Pool, version string) (bool, error) {
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, version).
		Scan(&exists)
	return exists, err
}

func version(base, suffix string) string {
	return strings.TrimSuffix(base, suffix)
}

func reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
