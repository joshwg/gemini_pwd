// auth_test.go
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCreateSessionAndGetUserFromSession tests session creation and retrieval.
func TestCreateSessionAndGetUserFromSession(t *testing.T) {
	// Setup: Clean database and create a user
	db.Exec("DELETE FROM users")
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")
	user := &User{ID: 1, Username: "testuser", IsAdmin: false}

	// Create a response recorder and a request
	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)

	// Test session creation
	createSession(rr, user)

	// Check if the session cookie is set
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected session cookie to be set, but it was not")
	}
	sessionCookie := cookies[0]
	if sessionCookie.Name != "session_token" {
		t.Errorf("Expected cookie name 'session_token', but got '%s'", sessionCookie.Name)
	}

	// Add the cookie to the request and test session retrieval
	req.AddCookie(sessionCookie)
	
	// We need to simulate the authMiddleware to get the user in the context
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		retrievedUser, ok := r.Context().Value("user").(*User)
		if !ok {
			t.Fatal("User not found in context")
		}
		if retrievedUser.ID != user.ID || retrievedUser.Username != user.Username {
			t.Errorf("Retrieved user does not match original user. Got %+v, want %+v", retrievedUser, user)
		}
	})
	
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

// TestSessionExpiration tests that sessions expire correctly.
func TestSessionExpiration(t *testing.T) {
	// Setup: Clean database and create a user
	db.Exec("DELETE FROM users")
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")
	user := &User{ID: 1, Username: "testuser", IsAdmin: false}

	// Create a session that is already expired
	expiredTime := time.Now().Add(-2 * time.Hour)
	sessions["expired_token"] = session{
		userID:  user.ID,
		expires: expiredTime,
	}

	// Create a request with the expired session token
	req, _ := http.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "expired_token"})

	// We expect the middleware to redirect to the login page
	rr := httptest.NewRecorder()
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// This part should not be reached
		t.Fatal("Handler was called for an expired session")
	})
	handler.ServeHTTP(rr, req)

	// Check for redirect
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("Expected status %v for expired session, but got %v", http.StatusFound, status)
	}
}
