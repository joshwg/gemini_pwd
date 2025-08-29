// handlers_test.go
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Helper function to create a request with a user context
func newRequestWithUser(method, url string, body string, user *User) *http.Request {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), "user", user)
	return req.WithContext(ctx)
}

// TestDashboardHandler tests the main dashboard page.
func TestDashboardHandler(t *testing.T) {
	// Setup: Clean database and create a user
	db.Exec("DELETE FROM users")
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")
	user := &User{ID: 1, Username: "testuser", IsAdmin: false}

	req := newRequestWithUser("GET", "/dashboard", "", user)
	rr := httptest.NewRecorder()

	dashboardHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check if the user's name is in the body
	if !strings.Contains(rr.Body.String(), user.Username) {
		t.Errorf("handler response body does not contain username '%s'", user.Username)
	}
}

// TestUsersAPIHandler_Admin tests the users API as an admin.
func TestUsersAPIHandler_Admin(t *testing.T) {
	// Setup
	db.Exec("DELETE FROM users")
	admin := &User{ID: 1, Username: "admin", IsAdmin: true}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'admin', 'hash', 1)")

	// Test GET all users
	req := newRequestWithUser("GET", "/api/users", "", admin)
	rr := httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/users returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "admin") {
		t.Errorf("GET /api/users response should contain the admin user")
	}

	// Test POST to create a user
	newUserJSON := `{"username": "newbie", "password": "password", "isAdmin": false}`
	req = newRequestWithUser("POST", "/api/users", newUserJSON, admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("POST /api/users returned wrong status code: got %v want %v", status, http.StatusCreated)
	}
}

// TestUsersAPIHandler_NonAdmin tests that a non-admin is forbidden.
func TestUsersAPIHandler_NonAdmin(t *testing.T) {
	// Setup
	db.Exec("DELETE FROM users")
	nonAdmin := &User{ID: 2, Username: "nonadmin", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (2, 'nonadmin', 'hash', 0)")

	req := newRequestWithUser("GET", "/api/users", "", nonAdmin)
	rr := httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("Non-admin GET /api/users returned wrong status code: got %v want %v", status, http.StatusForbidden)
	}
}

// TestPasswordsAPIHandler tests the passwords API.
func TestPasswordsAPIHandler(t *testing.T) {
	// Setup
	db.Exec("DELETE FROM password_entries")
	db.Exec("DELETE FROM users")
	user := &User{ID: 1, Username: "testuser", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Test GET (empty)
	req := newRequestWithUser("GET", "/api/passwords", "", user)
	rr := httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/passwords returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	// Check for empty array `[]` not `null`
	if body := strings.TrimSpace(rr.Body.String()); body != "[]" {
		t.Errorf("Expected empty password list to be '[]', but got '%s'", body)
	}

	// Test POST
	newPassJSON := `{"site":"test.com","username":"tester","password":"pwd","notes":"","tags":[]}`
	req = newRequestWithUser("POST", "/api/passwords", newPassJSON, user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("POST /api/passwords returned wrong status code: got %v want %v", status, http.StatusCreated)
	}
}

// TestTagsAPIHandler tests the tags API.
func TestTagsAPIHandler(t *testing.T) {
	// Setup
	db.Exec("DELETE FROM tags")
	db.Exec("DELETE FROM users")
	user := &User{ID: 1, Username: "testuser", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Test GET (empty)
	req := newRequestWithUser("GET", "/api/tags", "", user)
	rr := httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/tags returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	// Check for empty array `[]` not `null`
	if body := strings.TrimSpace(rr.Body.String()); body != "[]" {
		t.Errorf("Expected empty tag list to be '[]', but got '%s'", body)
	}

	// Test POST
	newTagJSON := `{"name":"Social","description":"Social media","color":"#aabbcc"}`
	req = newRequestWithUser("POST", "/api/tags", newTagJSON, user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("POST /api/tags returned wrong status code: got %v want %v", status, http.StatusCreated)
	}
}
