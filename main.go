// main.go
package main

import (
	"gemini_pwd/pkg/logger"
	"gemini_pwd/pkg/template"
	"net/http"
	"os"
	"time"
)

// The 'db' variable is declared in database.go and is accessible here.

// startCleanupRoutines starts background routines to clean up expired sessions and old login attempts
func startCleanupRoutines() {
	// Clean up expired sessions every 10 minutes
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cleanupExpiredSessions()
			}
		}
	}()

	// Clean up old login attempts every hour
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cleanupOldLoginAttempts()
			}
		}
	}()
}

func main() {
	// Initialize the database connection and tables in parent directory
	initDB("../passwords.db")

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
	mux.HandleFunc("/test", securityHeaders(testHandler))

	// Protected routes (require authentication) - auth middleware already includes security headers
	mux.HandleFunc("/dashboard", authMiddleware(dashboardHandler))
	mux.HandleFunc("/logout", authMiddleware(logoutHandler))
	mux.HandleFunc("/users", authMiddleware(usersHandler))
	mux.HandleFunc("/tags", authMiddleware(tagsHandler))
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
		port = "7000"
	}
	logger.Info("Starting server on :%s", port)
	logger.Info("Security features enabled:")
	logger.Info("- Database-backed sessions")
	logger.Info("- Rate limiting on login attempts")
	logger.Info("- Security headers")
	logger.Info("- Session invalidation on password change")
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		logger.Fatal("Server failed to start: %v", err, nil)
	}
}
