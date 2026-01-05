// Copyright (C) 2025 Joshua Goldstein

// auth.go
package main

import (
	"context"
	"database/sql"
	"fmt"
	"gemini-pwd/pkg/httputil"
	"net"
	"net/http"
	"strings"
	"time"

	"gemini-pwd/pkg/logger"

	"github.com/google/uuid"
)

// Rate limiting constants
const (
	maxLoginAttempts     = 3
	cooldownDuration     = 30 * time.Second
	maxLoginAttemptsHard = 6
	hardCooldownDuration = 5 * time.Minute
)

// Define a custom type for context keys to avoid collisions
type contextKey string

const userContextKey contextKey = "user"

// getUserFromContext is a helper function to extract the user from the request context
func getUserFromContext(r *http.Request) (*User, bool) {
	user, ok := r.Context().Value(userContextKey).(*User)
	return user, ok
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP in the chain
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// recordLoginAttempt records a login attempt in the database
func recordLoginAttempt(username, ipAddress string, successful bool) error {
	_, err := db.Exec(
		"INSERT INTO login_attempts (username, ip_address, successful, attempted_at) VALUES (?, ?, ?, ?)",
		username, ipAddress, successful, time.Now(),
	)
	return err
}

// checkRateLimitByUsername checks if a username is rate limited
func checkRateLimitByUsername(username string) (bool, time.Duration, error) {
	now := time.Now()

	// Check failed attempts for this username in the last 5 minutes
	var failedAttempts int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM login_attempts 
		WHERE username = ? COLLATE NOCASE 
		AND successful = 0 
		AND attempted_at > ?
	`, username, now.Add(-hardCooldownDuration)).Scan(&failedAttempts)

	if err != nil {
		return false, 0, err
	}

	// If 6+ failed attempts, require 5 minute cooldown
	if failedAttempts >= maxLoginAttemptsHard {
		var lastAttempt time.Time
		err = db.QueryRow(`
			SELECT attempted_at FROM login_attempts 
			WHERE username = ? COLLATE NOCASE 
			AND successful = 0 
			ORDER BY attempted_at DESC LIMIT 1
		`, username).Scan(&lastAttempt)

		if err != nil {
			return false, 0, err
		}

		timeLeft := hardCooldownDuration - now.Sub(lastAttempt)
		if timeLeft > 0 {
			return true, timeLeft, nil
		}
	}

	// Check failed attempts for this username in the last 30 seconds
	err = db.QueryRow(`
		SELECT COUNT(*) FROM login_attempts 
		WHERE username = ? COLLATE NOCASE 
		AND successful = 0 
		AND attempted_at > ?
	`, username, now.Add(-cooldownDuration)).Scan(&failedAttempts)

	if err != nil {
		return false, 0, err
	}

	// If 3+ failed attempts, require 30 second cooldown
	if failedAttempts >= maxLoginAttempts {
		var lastAttempt time.Time
		err = db.QueryRow(`
			SELECT attempted_at FROM login_attempts 
			WHERE username = ? COLLATE NOCASE 
			AND successful = 0 
			ORDER BY attempted_at DESC LIMIT 1
		`, username).Scan(&lastAttempt)

		if err != nil {
			return false, 0, err
		}

		timeLeft := cooldownDuration - now.Sub(lastAttempt)
		if timeLeft > 0 {
			return true, timeLeft, nil
		}
	}

	return false, 0, nil
}

// createSession creates a new session for a user in the database
func createSession(w http.ResponseWriter, user *User) error {
	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(30 * time.Minute)

	// Insert session into database
	_, err := db.Exec(
		"INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
		sessionToken, user.ID, expiresAt,
	)
	if err != nil {
		return err
	}

	// Set secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  expiresAt,
		HttpOnly: true,  // Prevent XSS
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	return nil
}

// clearSession removes a user's session from database and cookie
func clearSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		// If the cookie is not found, there's nothing to clear.
		return
	}

	// Delete from database
	_, err = db.Exec("DELETE FROM sessions WHERE id = ?", c.Value)
	if err != nil {
		logger.Error("Error deleting session from database", err)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
}

// clearAllUserSessions removes all sessions for a specific user (used when password changes)
func clearAllUserSessions(userID int) error {
	_, err := db.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	return err
}

// validateSession checks if a session exists and is valid in the database
func validateSession(sessionToken string) (*User, error) {
	var userID int
	var expiresAt time.Time

	err := db.QueryRow(`
		SELECT user_id, expires_at FROM sessions 
		WHERE id = ? AND expires_at > ?
	`, sessionToken, time.Now()).Scan(&userID, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found or expired")
		}
		return nil, err
	}

	// Refresh session expiration (sliding window) with timeout
	newExpiresAt := time.Now().Add(30 * time.Minute)

	// Use a background goroutine to avoid blocking the request
	go func() {
		// Add a timeout to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Retry logic for database locks
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			_, err = db.ExecContext(ctx, "UPDATE sessions SET expires_at = ? WHERE id = ?", newExpiresAt, sessionToken)
			if err == nil {
				return // Success
			}

			// Check if it's a database lock error
			if strings.Contains(err.Error(), "database is locked") && i < maxRetries-1 {
				// Wait a bit before retrying
				time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
				continue
			}

			// For other errors or final retry, log the error
			logger.Error("Error updating session expiration", err, "attempt", fmt.Sprintf("%d/%d", i+1, maxRetries))
			if i == maxRetries-1 {
				logger.Error("Failed to update session expiration after max attempts", nil, "attempts", maxRetries)
			}
		}
	}()

	// Get user details
	user, err := getUserByID(userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// cleanupExpiredSessions removes expired sessions from the database
func cleanupExpiredSessions() {
	_, err := db.Exec("DELETE FROM sessions WHERE expires_at <= ?", time.Now())
	if err != nil {
		logger.Error("Error cleaning up expired sessions", err)
	}
}

// cleanupOldLoginAttempts removes old login attempts (older than 24 hours)
func cleanupOldLoginAttempts() {
	cutoff := time.Now().Add(-24 * time.Hour)
	_, err := db.Exec("DELETE FROM login_attempts WHERE attempted_at <= ?", cutoff)
	if err != nil {
		logger.Error("Error cleaning up old login attempts", err)
	}
}

// securityHeaders adds security headers to all responses
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Updated CSP to allow required CDNs and inline styles/scripts
		// Note: 'unsafe-eval' and 'unsafe-inline' are required for our inline scripts and reduce security
		// For production, consider extracting scripts to separate files or using nonces/hashes
		csp := "default-src 'self'; " +
			"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
			"font-src 'self' https://cdnjs.cloudflare.com; " +
			"img-src 'self' data:; " +
			"connect-src 'self' https://cdn.jsdelivr.net; " +
			"object-src 'none'; " +
			"base-uri 'self'"
		w.Header().Set("Content-Security-Policy", csp)

		// Call the next handler
		next.ServeHTTP(w, r)
	}
} // authMiddleware protects routes that require authentication using database sessions
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		// Helper function to detect AJAX requests
		isAjaxRequest := func(r *http.Request) bool {
			// Check for common AJAX indicators
			if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
				return true
			}
			// Check if request path starts with /api/
			if strings.HasPrefix(r.URL.Path, "/api/") {
				return true
			}
			// Check Accept header for JSON preference
			accept := r.Header.Get("Accept")
			return strings.Contains(accept, "application/json")
		}

		c, err := r.Cookie("session_token")
		if err != nil {
			if err == http.ErrNoCookie {
				if isAjaxRequest(r) {
					httputil.Unauthorized(w, "Authentication required")
				} else {
					http.Redirect(w, r, "/", http.StatusFound)
				}
				return
			}
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		user, err := validateSession(c.Value)
		if err != nil {
			clearSession(w, r)
			if isAjaxRequest(r) {
				httputil.Unauthorized(w, "Session expired")
			} else {
				http.Redirect(w, r, "/?reason=session_expired", http.StatusFound)
			}
			return
		}

		// Update cookie expiration to match session
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    c.Value,
			Expires:  time.Now().Add(30 * time.Minute),
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
