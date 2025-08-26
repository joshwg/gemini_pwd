// auth.go
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
)

var sessions = map[string]session{}

type session struct {
	userID  int
	expires time.Time
}

func (s session) isExpired() bool {
	return s.expires.Before(time.Now())
}

// createSession creates a new session for a user.
func createSession(w http.ResponseWriter, user *User) {
	sessionToken := uuid.NewString()
	expiresAt := time.Now().Add(120 * time.Minute)

	sessions[sessionToken] = session{
		userID:  user.ID,
		expires: expiresAt,
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: expiresAt,
	})
}

// clearSession removes a user's session.
func clearSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		// If the cookie is not found, there's nothing to clear.
		return
	}
	delete(sessions, c.Value)
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Expires: time.Unix(0, 0),
		MaxAge: -1,
	})
}

// authMiddleware protects routes that require authentication.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session_token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		sessionToken := c.Value
		userSession, exists := sessions[sessionToken]
		if !exists || userSession.isExpired() {
			clearSession(w, r)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		user, err := getUserByID(userSession.userID)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
