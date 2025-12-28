// extra_security_test.go
// Additional security and validation tests for Gemini PWD
// Copyright (C) 2025 Joshua Goldstein

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtraInputValidation(t *testing.T) {
	// Initialize database for tests
	initDB("test_passwords.db")

	mux := setupTestServer()
	user := createTestUser(t, "validuser", "StrongPassword123!", false)
	session := createTestSession(t, user.ID)
	cookie := &http.Cookie{Name: "session_token", Value: session}

	cases := []struct {
		name   string
		body   string
		url    string
		method string
	}{
		{"Missing site", `{"username":"user","password":"pass"}`, "/api/passwords", "POST"},
		{"Site too long", `{"site":"` + strings.Repeat("a", 300) + `","username":"user","password":"pass"}`, "/api/passwords", "POST"},
		{"Username too long", `{"site":"site","username":"` + strings.Repeat("u", 300) + `","password":"pass"}`, "/api/passwords", "POST"},
		{"Password too short", `{"site":"site","username":"user","password":"1"}`, "/api/passwords", "POST"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code == http.StatusOK {
				t.Errorf("Expected validation error for %s, got OK", tc.name)
			}
		})
	}
}

func TestExtraSQLInjection(t *testing.T) {
	// Initialize database for tests
	initDB("test_passwords.db")

	mux := setupTestServer()
	user := createTestUser(t, "sqlitest", "StrongPassword123!", false)
	session := createTestSession(t, user.ID)
	cookie := &http.Cookie{Name: "session_token", Value: session}

	payloads := []string{
		"' OR 1=1 --",
		"'; DROP TABLE users; --",
		"' UNION SELECT * FROM passwords --",
	}

	for _, payload := range payloads {
		t.Run("SQLi:"+payload, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/api/passwords?q="+payload, nil)
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code == http.StatusInternalServerError {
				t.Errorf("SQL injection payload caused server error: %s", payload)
			}
		})
	}
}

func TestExtraSessionInvalidation(t *testing.T) {
	// Initialize database for tests
	initDB("test_passwords.db")

	mux := setupTestServer()
	user := createTestUser(t, "sessiontest2", "StrongPassword123!", false)
	session := createTestSession(t, user.ID)
	cookie := &http.Cookie{Name: "session_token", Value: session}

	// Logout
	req, _ := http.NewRequest("GET", "/logout", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Try to reuse session
	req, _ = http.NewRequest("GET", "/api/passwords", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Error("Session should be invalidated after logout")
	}
}
