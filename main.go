package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/AlexandreDeCarli/paloma-fw/internal/api"
	"github.com/AlexandreDeCarli/paloma-fw/internal/db"
	"github.com/AlexandreDeCarli/paloma-fw/internal/fail2ban"
)

//go:embed migrations/*.up.sql
var migrationFS embed.FS

//go:embed web/*
var webFS embed.FS

func main() {
	log.Println("[Paloma Shield] Initializing firewall and defense service...")

	// Environment configuration
	port := getEnv("PORT", "3340")
	dbHost := getEnv("DB_HOST", "10.0.0.159")
	dbPortStr := getEnv("DB_PORT", "3306")
	dbUser := getEnv("DB_USER", "principalUser")
	dbPassword := getEnv("DB_PASSWORD", "rl0ipasT-xAHUzLv-bRa")
	dbName := getEnv("DB_NAME", "paloma_security")
	adminPassword := getEnv("ADMIN_PASSWORD", "sk-litellm-potencial-5KokL8QWU8S6vtx")
	internalSecret := getEnv("INTERNAL_SECRET", "paloma_fw_internal_secret_2026")
	fail2banSock := getEnv("FAIL2BAN_SOCK", "/var/run/fail2ban/fail2ban.sock")

	dbPort, err := strconv.Atoi(dbPortStr)
	if err != nil {
		dbPort = 3306
	}

	// 1. Connect to MySQL HeatWave
	log.Printf("[Database] Connecting to MySQL HeatWave at %s:%d/%s...", dbHost, dbPort, dbName)
	store, err := db.NewStore(db.Config{
		Host:     dbHost,
		Port:     dbPort,
		User:     dbUser,
		Password: dbPassword,
		Database: dbName,
	})
	if err != nil {
		log.Fatalf("[Database Error] Failed to connect to MySQL HeatWave: %v", err)
	}
	defer store.Close()
	log.Println("[Database] Connection pool established successfully.")

	// 2. Run Database Migrations
	ctxMigration, cancelMigration := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelMigration()

	migrator := db.NewMigrator(store.DB(), migrationFS)
	if err := migrator.Apply(ctxMigration); err != nil {
		log.Fatalf("[Migration Error] Failed to apply database migrations: %v", err)
	}
	log.Println("[Database] Migrations verified and up to date.")

	// 3. Initialize Fail2ban Client
	f2bClient := fail2ban.NewClient(fail2banSock)
	ctxPing, cancelPing := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelPing()
	if ok, err := f2bClient.Ping(ctxPing); ok {
		log.Println("[Fail2ban] Connected to server socket successfully.")
	} else {
		log.Printf("[Fail2ban Warn] Socket ping returned: %v (service will continue)", err)
	}

	// 4. Setup Web Assets
	subWebFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("[Assets Error] Failed to prepare web filesystem: %v", err)
	}

	// 5. Configure API Server
	apiServer := api.NewServer(api.Config{
		Store:          store,
		Fail2ban:       f2bClient,
		AdminPassword:  adminPassword,
		InternalSecret: internalSecret,
		WebFS:          subWebFS,
	})

	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)

	// Wrap in security headers
	handler := api.SecurityHeadersMiddleware(mux)

	server := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%s", port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown handling
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[Paloma Shield] HTTP Server listening on http://0.0.0.0:%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Server Error] ListenAndServe failed: %v", err)
		}
	}()

	<-stopChan
	log.Println("[Paloma Shield] Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Server Warn] Shutdown error: %v", err)
	}
	log.Println("[Paloma Shield] Service stopped cleanly.")
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
