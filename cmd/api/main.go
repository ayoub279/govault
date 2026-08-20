// Command api is the govault HTTP server entrypoint.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"govault/internal/auth"
	"govault/internal/config"
	"govault/internal/crypto"
	"govault/internal/db"
	"govault/internal/handlers"
	"govault/internal/middleware"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx := context.Background()

	store, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()

	enc, err := crypto.New(cfg.EncryptionKey)
	if err != nil {
		return err
	}

	maker, err := auth.NewTokenMaker(cfg.PasetoKey)
	if err != nil {
		return err
	}

	authHandler := handlers.NewAuthHandler(store, maker)
	secretsHandler := handlers.NewSecretsHandler(store, enc)
	authenticator := middleware.NewAuthenticator(maker)

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(15 * time.Second))

	// Health check.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Public auth routes.
	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
	})

	// Protected secrets routes.
	r.Route("/secrets", func(r chi.Router) {
		r.Use(authenticator.RequireAuth)
		r.Post("/", secretsHandler.Create)
		r.Get("/", secretsHandler.List)
		r.Get("/{id}", secretsHandler.Get)
		r.Delete("/{id}", secretsHandler.Delete)
	})

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	shutdownErr := make(chan error, 1)
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit

		log.Println("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownErr <- srv.Shutdown(shutdownCtx)
	}()

	log.Printf("govault listening on :%s", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return <-shutdownErr
}
