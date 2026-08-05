package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const (
	serverShutdownTimeout = 10 * time.Second
	// ServerWriteTimeout bounds a single response. It is exported so the
	// auth-state cache tombstone TTL can be sized to outlive any in-flight
	// request, preventing a slow request's stale PUT from re-seeding a revoked
	// token after the tombstone expires.
	ServerWriteTimeout = 10 * time.Second
)

type backgroundWorker interface {
	Run(ctx context.Context) error
}

type httpServer interface {
	ListenAndServe() error
	Shutdown(ctx context.Context) error
}

var newHTTPServer = func(address string, handler http.Handler) httpServer {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout bounds reading the request body: without it a slow body
		// (e.g. an avatar upload trickling in) can hold a connection open
		// indefinitely even though the header arrived on time.
		ReadTimeout: 30 * time.Second,
		// WriteTimeout bounds a single response. The password-hash semaphore
		// queues requests during an auth storm; without this bound the queue
		// grows without backpressure and connections pile up. 10s is a generous
		// ceiling for any legitimate response on a 1-core box.
		WriteTimeout: ServerWriteTimeout,
		IdleTimeout:  60 * time.Second,
	}
}

func serve(ctx context.Context, address string, handler http.Handler, workers []backgroundWorker) error {
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	workerErrors := make(chan error, len(workers))
	var workerGroup sync.WaitGroup
	workerGroup.Add(len(workers))
	for _, background := range workers {
		background := background
		go func() {
			defer workerGroup.Done()
			if err := background.Run(workerCtx); err != nil {
				workerErrors <- err
			}
		}()
	}
	go func() {
		workerGroup.Wait()
		close(workerErrors)
	}()

	server := newHTTPServer(address, handler)
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("serve HTTP: %w", err)
		}
	case err, ok := <-workerErrors:
		if ok {
			runErr = fmt.Errorf("run background worker: %w", err)
		} else if ctx.Err() == nil {
			runErr = fmt.Errorf("background workers stopped unexpectedly")
		}
	}

	cancelWorkers()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), serverShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = fmt.Errorf("shutdown HTTP server: %w", err)
	}
	for {
		select {
		case err, ok := <-workerErrors:
			if !ok {
				return runErr
			}
			if runErr == nil {
				runErr = fmt.Errorf("stop background worker: %w", err)
			}
		case <-shutdownCtx.Done():
			if runErr == nil {
				runErr = fmt.Errorf("stop background workers: %w", shutdownCtx.Err())
			}
			return runErr
		}
	}
}

func setupLogger(level string) {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{Level: slogLevel},
	)))
}

func pingDB(database *gorm.DB) error {
	sqlDB, err := database.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func pingRedis(client *goredis.Client) error {
	return client.Ping(context.Background()).Err()
}
