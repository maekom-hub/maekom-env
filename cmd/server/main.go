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

	"github.com/maekom-hub/maekom-env/internal/api"
	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
	"github.com/maekom-hub/maekom-env/internal/notifier"
)

func main() {
	cipher, err := crypto.LoadMasterKeyFromEnv()
	if err != nil {
		log.Fatalf("failed to load master key: %v", err)
	}

	dbPath := os.Getenv("MAEKOM_DB_PATH")
	if dbPath == "" {
		dbPath = "maekom.db"
	}

	addr := os.Getenv("MAEKOM_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := db.Open(ctx, dbPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Printf("error closing database: %v", err)
		}
	}()

	disp := notifier.NewDispatcher(store)
	disp.StartExpiryScheduler(ctx)

	apiCfg := api.LoadConfigFromEnv()
	if apiCfg.AdminPassword == "" {
		log.Println("warning: ADMIN_PASSWORD is not set; admin login is disabled")
	}

	apiServer, err := api.NewServer(store, cipher, disp, apiCfg)
	if err != nil {
		log.Fatalf("failed to initialize API server: %v", err)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("maekom-env server listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	case err := <-errCh:
		if err != nil {
			log.Fatalf("server error: %v", err)
		}
	}
}
