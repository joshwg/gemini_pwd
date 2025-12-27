// security_test.go - Penetration testing suite for authentication and authorization
// Copyright (C) 2025 Joshua Goldstein

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// TestSecurityBoundaries runs comprehensive penetration tests
func TestSecurityBoundaries(t *testing.T) {
	// Initialize the global database connection for tests
	// This will create all the tables with the correct schema
	initDB("test_passwords.db")

	t.Run("UnauthenticatedAccess", testUnauthenticatedAccess)
	t.Run("CrossUserDataAccess", testCrossUserDataAccess)
	t.Run("SessionSecurity", testSessionSecurity)
	t.Run("APIEndpointSecurity", testAPIEndpointSecurity)
	t.Run("SQLInjectionAttempts", testSQLInjectionAttempts)
}

// Helper function to create a test user
func createTestUser(t *testing.T, username, password string, isAdmin bool) *User {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	result, err := db.Exec(
		"INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
		username, string(hashedPassword), isAdmin,
	)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get user ID: %v", err)
	}

	return &User{
		ID:       int(userID),
		Username: username,
		IsAdmin:  isAdmin,
	}
}

// Helper function to create a test session
func createTestSession(t *testing.T, userID int) string {
	token := uuid.New().String()
	expiresAt := time.Now().Add(30 * time.Minute)

	_, err := db.Exec(
		"INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
		token, userID, expiresAt, time.Now(),
	)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	return token
}

// Helper function to create request with session cookie
func newRequestWithSession(method, url, body, sessionToken string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, url, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, url, nil)
	}

	if sessionToken != "" {
		cookie := &http.Cookie{Name: "session_token", Value: sessionToken}
		req.AddCookie(cookie)
	}

	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	return req
}

// testUnauthenticatedAccess verifies that unauthenticated users cannot access protected resources
func testUnauthenticatedAccess(t *testing.T) {
	ensureTestDB(t)
	mux := setupTestServer()

	protectedEndpoints := []struct {
		method string
		path   string
		desc   string
	}{
		{"GET", "/dashboard", "Dashboard page"},
		{"GET", "/users", "Users management page"},
		{"GET", "/tags", "Tags management page"},
		{"GET", "/api/passwords", "Passwords API"},
		{"POST", "/api/passwords", "Create password API"},
		{"PUT", "/api/passwords?id=1", "Update password API"},
		{"DELETE", "/api/passwords?id=1", "Delete password API"},
		{"GET", "/api/passwords/check-duplicate", "Check duplicate API"},
		{"GET", "/api/tags", "Tags API"},
		{"POST", "/api/tags", "Create tag API"},
		{"PUT", "/api/tags?id=1", "Update tag API"},
		{"DELETE", "/api/tags?id=1", "Delete tag API"},
		{"GET", "/api/users", "Users API"},
		{"POST", "/api/users", "Create user API"},
		{"PUT", "/api/users", "Update user API"},
		{"DELETE", "/api/users", "Delete user API"},
		{"POST", "/api/user/password", "Change password API"},
		{"GET", "/export/passwords", "Export passwords"},
		{"POST", "/import/passwords", "Import passwords"},
		{"GET", "/export/tags", "Export tags"},
		{"POST", "/import/tags", "Import tags"},
	}

	for _, endpoint := range protectedEndpoints {
		t.Run(fmt.Sprintf("%s_%s", endpoint.method, strings.ReplaceAll(endpoint.path, "/", "_")), func(t *testing.T) {
			var req *http.Request
			var err error

			if endpoint.method == "POST" || endpoint.method == "PUT" {
				// Send empty JSON body for POST/PUT requests
				req, err = http.NewRequest(endpoint.method, endpoint.path, bytes.NewBufferString("{}"))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, err = http.NewRequest(endpoint.method, endpoint.path, nil)
			}
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			// Should redirect to login or return 401/403
			if w.Code != http.StatusFound && w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
				t.Errorf("%s %s should deny unauthenticated access, got status %d",
					endpoint.method, endpoint.path, w.Code)
			}

			// API endpoints should return 401, page endpoints should redirect
			if strings.HasPrefix(endpoint.path, "/api/") {
				if w.Code != http.StatusUnauthorized {
					t.Errorf("API endpoint %s should return 401 for unauthenticated access, got %d",
						endpoint.path, w.Code)
				}
			} else {
				if w.Code != http.StatusFound {
					t.Errorf("Page endpoint %s should redirect for unauthenticated access, got %d",
						endpoint.path, w.Code)
				}
			}
		})
	}
}

// testCrossUserDataAccess verifies that users cannot access other users' data
func testCrossUserDataAccess(t *testing.T) {
	ensureTestDB(t)
	mux := setupTestServer()

	// Create two test users with unique names
	user1 := createTestUser(t, "crosstest1", "password123", false)
	user2 := createTestUser(t, "crosstest2", "password456", false)

	// Create test data for user1
	session1 := createTestSession(t, user1.ID)

	// Create a password for user1
	passwordData := map[string]interface{}{
		"site":     "test.com",
		"username": "user1",
		"password": "secret123",
		"notes":    "test notes",
		"tags":     []string{"work"},
	}
	passwordJSON, _ := json.Marshal(passwordData)

	req := newRequestWithSession("POST", "/api/passwords", string(passwordJSON), session1)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("Failed to create test password for user1: %d", w.Code)
	} // Get the created password ID
	var createdPassword PasswordEntry
	json.Unmarshal(w.Body.Bytes(), &createdPassword)
	passwordID := createdPassword.ID

	// Create a tag for user1
	tagData := map[string]interface{}{
		"name":        "user1-tag",
		"description": "User 1's tag",
		"color":       "#FF0000",
	}
	tagJSON, _ := json.Marshal(tagData)

	req = newRequestWithSession("POST", "/api/tags", string(tagJSON), session1)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("Failed to create test tag for user1: %d", w.Code)
	}

	var createdTag Tag
	json.Unmarshal(w.Body.Bytes(), &createdTag)
	tagID := createdTag.ID

	// Now test user2 trying to access user1's data
	session2 := createTestSession(t, user2.ID)

	t.Run("CrossUserPasswordAccess", func(t *testing.T) {
		// Try to get user1's password with user2's session
		req := newRequestWithSession("GET", fmt.Sprintf("/api/passwords?id=%d", passwordID), "", session2)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Error("User2 should not be able to access User1's password")
		}

		// Try to update user1's password with user2's session
		updateData := map[string]interface{}{
			"id":       passwordID,
			"site":     "hacked.com",
			"username": "hacker",
			"password": "hacked",
			"notes":    "hacked",
			"tags":     []string{},
		}
		updateJSON, _ := json.Marshal(updateData)

		req = newRequestWithSession("PUT", fmt.Sprintf("/api/passwords?id=%d", passwordID), string(updateJSON), session2)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Error("User2 should not be able to update User1's password")
		}

		// Try to delete user1's password with user2's session
		req = newRequestWithSession("DELETE", fmt.Sprintf("/api/passwords?id=%d", passwordID), "", session2)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Error("User2 should not be able to delete User1's password")
		}
	})

	t.Run("CrossUserTagAccess", func(t *testing.T) {
		// Try to update user1's tag with user2's session
		updateData := map[string]interface{}{
			"name":        "hacked-tag",
			"description": "Hacked tag",
			"color":       "#000000",
		}
		updateJSON, _ := json.Marshal(updateData)

		req := newRequestWithSession("PUT", fmt.Sprintf("/api/tags?id=%d", tagID), string(updateJSON), session2)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Errorf("User2 should not be able to update User1's tag (got %d)", w.Code)
		} else {
			t.Logf("✅ Update correctly denied with status %d", w.Code)
		}

		// Try to delete user1's tag with user2's session
		req = newRequestWithSession("DELETE", fmt.Sprintf("/api/tags?id=%d", tagID), "", session2)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Errorf("User2 should not be able to delete User1's tag (got %d)", w.Code)
		} else {
			t.Logf("✅ Delete correctly denied with status %d", w.Code)
		}
	})

	t.Run("CrossUserDataListing", func(t *testing.T) {
		// User2 should not see user1's passwords in their list
		req := newRequestWithSession("GET", "/api/passwords", "", session2)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("User2 should be able to get their own password list: %d", w.Code)
		}

		var passwords []PasswordEntry
		json.Unmarshal(w.Body.Bytes(), &passwords)

		for _, p := range passwords {
			if p.ID == passwordID {
				t.Error("User2's password list should not contain User1's passwords")
			}
		}

		// User2 should not see user1's tags in their list
		req = newRequestWithSession("GET", "/api/tags", "", session2)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("User2 should be able to get their own tag list: %d", w.Code)
		}

		var tags []Tag
		json.Unmarshal(w.Body.Bytes(), &tags)

		for _, tag := range tags {
			if tag.ID == tagID {
				t.Error("User2's tag list should not contain User1's tags")
			}
		}
	})
}

// testSessionSecurity verifies session management security
func testSessionSecurity(t *testing.T) {
	ensureTestDB(t)
	mux := setupTestServer()

	user := createTestUser(t, "sessiontest", "password123", false)

	t.Run("InvalidSessionToken", func(t *testing.T) {
		invalidTokens := []string{
			"invalid-token",
			"00000000-0000-0000-0000-000000000000",
			"",
			"malformed",
			"' OR 1=1 --",
		}

		for _, token := range invalidTokens {
			cookie := &http.Cookie{Name: "session_token", Value: token}
			req, _ := http.NewRequest("GET", "/api/passwords", nil)
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				t.Errorf("Invalid session token '%s' should not grant access", token)
			}
		}
	})

	t.Run("ExpiredSession", func(t *testing.T) {
		// Create a session and manually expire it
		session := createTestSession(t, user.ID)

		// Manually update the session to be expired
		_, err := db.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?",
			time.Now().Add(-1*time.Hour), session)
		if err != nil {
			t.Fatalf("Failed to expire session: %v", err)
		}

		cookie := &http.Cookie{Name: "session_token", Value: session}
		req, _ := http.NewRequest("GET", "/api/passwords", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Error("Expired session should not grant access")
		}
	})

	t.Run("SessionReuse", func(t *testing.T) {
		// Test that logged out sessions cannot be reused
		session := createTestSession(t, user.ID)
		cookie := &http.Cookie{Name: "session_token", Value: session}

		// First request should work
		req, _ := http.NewRequest("GET", "/api/passwords", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Valid session should grant access: %d", w.Code)
		}

		// Logout (this should invalidate the session)
		req, _ = http.NewRequest("GET", "/logout", nil)
		req.AddCookie(cookie)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		// Try to reuse the session after logout
		req, _ = http.NewRequest("GET", "/api/passwords", nil)
		req.AddCookie(cookie)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			t.Error("Session should be invalidated after logout")
		}
	})
}

// testAPIEndpointSecurity tests specific API endpoint security
func testAPIEndpointSecurity(t *testing.T) {
	ensureTestDB(t)
	mux := setupTestServer()

	user := createTestUser(t, "apitest", "password123", false)
	session := createTestSession(t, user.ID)
	cookie := &http.Cookie{Name: "session_token", Value: session}

	t.Run("MalformedRequests", func(t *testing.T) {
		malformedBodies := []string{
			`{"invalid": json}`,
			`{unclosed`,
			`malformed`,
			`{"id": "not-a-number"}`,
			`{"password": null}`,
		}

		endpoints := []string{
			"/api/passwords",
			"/api/tags",
			"/api/users",
		}

		for _, endpoint := range endpoints {
			for _, body := range malformedBodies {
				req, _ := http.NewRequest("POST", endpoint, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(cookie)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, req)

				if w.Code == http.StatusOK {
					t.Errorf("Malformed request to %s should not succeed: %s", endpoint, body)
				}
			}
		}
	})

	t.Run("InvalidIDs", func(t *testing.T) {
		invalidIDs := []string{
			"not-a-number",
			"-1",
			"0",
			"999999",
			"' OR 1=1 --",
			"<script>alert('xss')</script>",
		}

		for _, id := range invalidIDs {
			// Test password endpoints
			req, _ := http.NewRequest("GET", "/api/passwords?id="+id, nil)
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				t.Errorf("Invalid password ID '%s' should not return data", id)
			}

			// Test tag endpoints
			req, _ = http.NewRequest("DELETE", "/api/tags?id="+id, nil)
			req.AddCookie(cookie)
			w = httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				t.Errorf("Invalid tag ID '%s' should not allow deletion", id)
			}
		}
	})

	t.Run("ContentTypeValidation", func(t *testing.T) {
		data := `{"site": "test.com", "username": "test", "password": "test"}`

		invalidContentTypes := []string{
			"text/plain",
			"text/html",
			"application/xml",
			"",
		}

		for _, contentType := range invalidContentTypes {
			req, _ := http.NewRequest("POST", "/api/passwords", strings.NewReader(data))
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			// Should reject non-JSON content types for API endpoints
			if w.Code == http.StatusOK {
				t.Errorf("Invalid content type '%s' should be rejected", contentType)
			}
		}
	})
}

// testSQLInjectionAttempts tests for SQL injection vulnerabilities
func testSQLInjectionAttempts(t *testing.T) {
	ensureTestDB(t)
	mux := setupTestServer()

	user := createTestUser(t, "sqltest", "password123", false)
	session := createTestSession(t, user.ID)
	cookie := &http.Cookie{Name: "session_token", Value: session}

	sqlInjectionPayloads := []string{
		"' OR 1=1 --",
		"'; DROP TABLE passwords; --",
		"' UNION SELECT * FROM users --",
		"1' OR '1'='1",
		"1; DELETE FROM sessions; --",
		"' OR 'x'='x",
		"1' AND 1=1 --",
		"admin'--",
		"' OR 1=1#",
		"' OR 1=1/*",
	}

	t.Run("PasswordSearch", func(t *testing.T) {
		for _, payload := range sqlInjectionPayloads {
			req, _ := http.NewRequest("GET", "/api/passwords?q="+payload, nil)
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			// Should not cause a 500 error or expose sensitive data
			if w.Code == http.StatusInternalServerError {
				t.Errorf("SQL injection payload in search caused server error: %s", payload)
			}

			// Check response doesn't contain SQL error messages
			body := w.Body.String()
			sqlErrorKeywords := []string{
				"syntax error",
				"SQL",
				"database",
				"sqlite",
				"constraint",
			}

			for _, keyword := range sqlErrorKeywords {
				if strings.Contains(strings.ToLower(body), strings.ToLower(keyword)) {
					t.Errorf("SQL injection payload '%s' may have exposed database information", payload)
				}
			}
		}
	})

	t.Run("PasswordCreation", func(t *testing.T) {
		for _, payload := range sqlInjectionPayloads {
			data := map[string]interface{}{
				"site":     payload,
				"username": payload,
				"password": "test123",
				"notes":    payload,
				"tags":     []string{payload},
			}
			jsonData, _ := json.Marshal(data)

			req, _ := http.NewRequest("POST", "/api/passwords", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code == http.StatusInternalServerError {
				t.Errorf("SQL injection in password creation caused server error: %s", payload)
			}
		}
	})

	t.Run("TagOperations", func(t *testing.T) {
		for i, payload := range sqlInjectionPayloads {
			// Use unique tag names to avoid duplicate errors
			uniqueName := fmt.Sprintf("%s_%d", payload, i)
			data := map[string]interface{}{
				"name":        uniqueName,
				"description": payload,
				"color":       "#FF0000",
			}
			jsonData, _ := json.Marshal(data)

			req, _ := http.NewRequest("POST", "/api/tags", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			// SQL injection should be prevented - we should get success (201) or validation errors (400)
			// but NOT database/server errors (500) unless it's a legitimate duplicate
			if w.Code == http.StatusInternalServerError {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				errorMsg := response["error"].(string)

				// If it's not a "already exists" error, it might be SQL injection
				if !strings.Contains(errorMsg, "already exists") {
					t.Errorf("SQL injection in tag creation caused unexpected server error: %s (payload: %s)", errorMsg, payload)
				}
			}
		}
	})
}

// Helper function to setup test server
func setupTestServer() *http.ServeMux {
	mux := http.NewServeMux()

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public routes
	mux.HandleFunc("/", securityHeaders(loginHandler))
	mux.HandleFunc("/login", securityHeaders(loginHandler))

	// Protected routes
	mux.HandleFunc("/dashboard", authMiddleware(dashboardHandler))
	mux.HandleFunc("/logout", authMiddleware(logoutHandler))
	mux.HandleFunc("/users", authMiddleware(usersHandler))
	mux.HandleFunc("/tags", authMiddleware(tagsHandler))
	mux.HandleFunc("/api/users", authMiddleware(usersAPIHandler))
	mux.HandleFunc("/api/user/password", authMiddleware(changeMyPasswordHandler))
	mux.HandleFunc("/api/passwords", authMiddleware(passwordsAPIHandler))
	mux.HandleFunc("/api/passwords/check-duplicate", authMiddleware(checkPasswordDuplicateHandler))
	mux.HandleFunc("/api/tags", authMiddleware(tagsAPIHandler))
	mux.HandleFunc("/export/passwords", authMiddleware(exportPasswordsHandler))
	mux.HandleFunc("/import/passwords", authMiddleware(importPasswordsHandler))
	mux.HandleFunc("/export/tags", authMiddleware(exportTagsHandler))
	mux.HandleFunc("/import/tags", authMiddleware(importTagsHandler))

	return mux
}
