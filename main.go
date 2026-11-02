// Copyright (C) 2025 Joshua Goldstein

// main.go
package main

import (
	"fmt"
	"gemini-pwd/pkg/logger"
	"gemini-pwd/pkg/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// dbFilePathFromEnv returns the database file path from PWD_DB_FILE.
// There is no default: the path must be set and must be absolute, so the
// server never silently creates a fresh database based on the working directory.
func dbFilePathFromEnv() (string, error) {
	path := os.Getenv(dbFileEnvVar)
	if path == "" {
		return "", fmt.Errorf("%s environment variable is not set; it must be an absolute path to the database file", dbFileEnvVar)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be an absolute path, got %q", dbFileEnvVar, path)
	}
	return filepath.Clean(path), nil
}

// The 'db' variable is declared in database.go and is accessible here.

// startCleanupRoutines starts background routines to clean up expired sessions and old login attempts
func startCleanupRoutines() {
	// Clean up expired sessions every 10 minutes
	go func() {
		ticker := time.NewTicker(sessionCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			cleanupExpiredSessions()
		}
	}()

	// Clean up old login attempts every hour
	go func() {
		ticker := time.NewTicker(loginAttemptsCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			cleanupOldLoginAttempts()
		}
	}()
}

func main() {
	// Initialize the database connection and tables at the configured path
	dbPath, err := dbFilePathFromEnv()
	if err != nil {
		logger.Fatal("Invalid database configuration. Refusing to start.", err)
	}
	logger.Info("Using database file: %s", dbPath)
	initDB(dbPath)

	// Update any existing tags with empty colors to use the default color
	if err := updateEmptyTagColors(); err != nil {
		logger.Warning("Failed to update empty tag colors: %v", err)
	}

	// Initialize template renderer
	template.InitRenderer("templates", "base.html")

	// Start cleanup routines
	startCleanupRoutines()

	mux := http.NewServeMux()

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public routes (with security headers)
	mux.HandleFunc("/", securityHeaders(loginHandler))
	mux.HandleFunc("/login", securityHeaders(loginHandler))
	mux.HandleFunc("/api/rate-limit-check", securityHeaders(rateLimitCheckHandler))
	// mux.HandleFunc("/test", securityHeaders(testHandler)) // Disabled for production

	// Protected routes (require authentication) - auth middleware already includes security headers
	mux.HandleFunc("/dashboard", authMiddleware(dashboardHandler))
	mux.HandleFunc("/logout", authMiddleware(logoutHandler))
	mux.HandleFunc("/users", authMiddleware(usersHandler))
	mux.HandleFunc("/tags", authMiddleware(tagsHandler))
	mux.HandleFunc("/recent-passwords", authMiddleware(recentPasswordsHandler))
	mux.HandleFunc("/api/users", authMiddleware(usersAPIHandler))
	mux.HandleFunc("/api/user/password", authMiddleware(changeMyPasswordHandler))
	mux.HandleFunc("/api/passwords", authMiddleware(passwordsAPIHandler))
	mux.HandleFunc("/api/passwords/check-duplicate", authMiddleware(checkPasswordDuplicateHandler))
	mux.HandleFunc("/api/tags", authMiddleware(tagsAPIHandler))

	// Import/Export routes
	mux.HandleFunc("/export/tags", authMiddleware(exportTagsHandler))
	mux.HandleFunc("/import/tags", authMiddleware(importTagsHandler))
	mux.HandleFunc("/export/passwords", authMiddleware(exportPasswordsHandler))
	mux.HandleFunc("/import/passwords", authMiddleware(importPasswordsHandler))

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultServerPort
	}
	bindAddr := os.Getenv(bindAddrEnvVar)
	if bindAddr == "" {
		bindAddr = defaultBindAddr
	}
	listenAddr := net.JoinHostPort(bindAddr, port)
	logger.Info("Starting server on %s", listenAddr)
	if !secureCookiesEnabled() {
		logger.Warning("%s is set: session cookies are NOT marked Secure. Do not use this in production.", insecureCookiesEnvVar)
	}
	logger.Info("Security features enabled:")
	logger.Info("- Database-backed sessions")
	logger.Info("- Rate limiting on login attempts")
	logger.Info("- Security headers")
	logger.Info("- Session invalidation on password change")
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		logger.Fatal("Server failed to start: %v", err, nil)
	}
}
