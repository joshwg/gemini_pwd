// main.go
package main

import (
	"log"
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
	// Initialize the database connection and tables
	initDB("passwords.db")

	// Update any existing tags with empty colors to use the default color
	if err := updateEmptyTagColors(); err != nil {
		log.Printf("Warning: Failed to update empty tag colors: %v", err)
	}

	// Start cleanup routines
	startCleanupRoutines()

	mux := http.NewServeMux()

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
		port = "8080"
	}
	log.Printf("Starting server on :%s", port)
	log.Println("Security features enabled:")
	log.Println("- Database-backed sessions")
	log.Println("- Rate limiting on login attempts")
	log.Println("- Security headers")
	log.Println("- Session invalidation on password change")
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
