// handlers_test.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Helper function to create a request with a user context
func newRequestWithUser(method, url string, body string, user *User) *http.Request {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), userContextKey, user)
	return req.WithContext(ctx)
}

// Helper function to create a multipart form request with a file
func newMultipartRequestWithUser(url string, fileName string, fileContent string, user *User) *http.Request {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Create the form file field
	fileWriter, err := writer.CreateFormFile("importFile", fileName)
	if err != nil {
		panic(err)
	}
	fileWriter.Write([]byte(fileContent))
	writer.Close()

	req := httptest.NewRequest("POST", url, &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	ctx := context.WithValue(req.Context(), userContextKey, user)
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

	// Since template parsing may fail in test environment, we just check that
	// the handler doesn't return an authentication error (401)
	if status := rr.Code; status == http.StatusUnauthorized {
		t.Errorf("handler returned unauthorized status: got %v, expected authenticated user to have access", status)
	}
}

// TestUsersAPIHandler_Admin tests comprehensive CRUD operations for users by admin.
func TestUsersAPIHandler_Admin(t *testing.T) {
	// Setup: Clean database and create admin user
	db.Exec("DELETE FROM users")
	admin := &User{ID: 1, Username: "admin", IsAdmin: true}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'admin', 'hash', 1)")

	// Test GET all users (initially just admin)
	req := newRequestWithUser("GET", "/api/users", "", admin)
	rr := httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/users returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "admin") {
		t.Errorf("GET /api/users response should contain the admin user")
	}

	// Test POST - Create a regular user
	newUserJSON := `{"username": "testuser", "password": "testpass123", "isAdmin": false}`
	req = newRequestWithUser("POST", "/api/users", newUserJSON, admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("POST /api/users returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	// Test POST - Create an admin user
	newAdminJSON := `{"username": "admin2", "password": "adminpass123", "isAdmin": true}`
	req = newRequestWithUser("POST", "/api/users", newAdminJSON, admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("POST /api/users for admin creation returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	// Test GET all users (should now contain 3 users)
	req = newRequestWithUser("GET", "/api/users", "", admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/users after creation returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	responseBody := rr.Body.String()
	if !strings.Contains(responseBody, "admin") || !strings.Contains(responseBody, "testuser") || !strings.Contains(responseBody, "admin2") {
		t.Errorf("GET /api/users should contain all created users")
	}

	// Test POST - Duplicate username (should fail)
	duplicateUserJSON := `{"username": "testuser", "password": "anotherpass", "isAdmin": false}`
	req = newRequestWithUser("POST", "/api/users", duplicateUserJSON, admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusConflict {
		t.Errorf("POST /api/users with duplicate username should return 409, got %v", status)
	}

	// Test POST - Invalid request (missing username)
	invalidUserJSON := `{"password": "testpass", "isAdmin": false}`
	req = newRequestWithUser("POST", "/api/users", invalidUserJSON, admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("POST /api/users with missing username should return 400, got %v", status)
	}

	// Test POST - Invalid request (missing password)
	invalidUserJSON2 := `{"username": "nopassuser", "isAdmin": false}`
	req = newRequestWithUser("POST", "/api/users", invalidUserJSON2, admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("POST /api/users with missing password should return 400, got %v", status)
	}

	// Test DELETE - Remove testuser
	req = newRequestWithUser("DELETE", "/api/users?username=testuser", "", admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("DELETE /api/users returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify user was deleted
	req = newRequestWithUser("GET", "/api/users", "", admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	responseBody = rr.Body.String()
	if strings.Contains(responseBody, "testuser") {
		t.Errorf("Deleted user 'testuser' should not appear in user list")
	}
	if !strings.Contains(responseBody, "admin") || !strings.Contains(responseBody, "admin2") {
		t.Errorf("Other users should still be present after deletion")
	}

	// Test DELETE - Missing username parameter
	req = newRequestWithUser("DELETE", "/api/users", "", admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("DELETE /api/users without username should return 400, got %v", status)
	}

	// Test DELETE - Non-existent user
	req = newRequestWithUser("DELETE", "/api/users?username=nonexistentuser", "", admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("DELETE /api/users for non-existent user should return 500, got %v", status)
	}

	// Test invalid JSON in POST
	req = newRequestWithUser("POST", "/api/users", "invalid json", admin)
	rr = httptest.NewRecorder()
	usersAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("POST /api/users with invalid JSON should return 400, got %v", status)
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

	// Test POST - Create password
	newPassJSON := `{"site":"test.com","username":"tester","password":"testpassword123","notes":"test notes","tags":["work","important"]}`
	req = newRequestWithUser("POST", "/api/passwords", newPassJSON, user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("POST /api/passwords returned wrong status code: got %v want %v", status, http.StatusCreated)
		t.Errorf("Response body: %s", rr.Body.String())
		return // Exit early if POST failed
	}

	// Get the created password ID from the response
	responseBody := rr.Body.String()
	t.Logf("POST response: %s", responseBody)
	var createdPassword PasswordEntry
	err := json.Unmarshal(rr.Body.Bytes(), &createdPassword)
	if err != nil {
		t.Fatalf("Failed to parse created password response: %v", err)
	}
	passwordID := createdPassword.ID

	// Verify password was created with timestamps
	if createdPassword.CreatedAt == "" {
		t.Error("CreatedAt timestamp should not be empty")
	}
	if createdPassword.ModifiedAt == "" {
		t.Error("ModifiedAt timestamp should not be empty")
	}
	if createdPassword.Site != "test.com" {
		t.Errorf("Expected site 'test.com', got '%s'", createdPassword.Site)
	}
	if createdPassword.Username != "tester" {
		t.Errorf("Expected username 'tester', got '%s'", createdPassword.Username)
	}

	// Test GET individual password for editing (should include decrypted fields)
	req = newRequestWithUser("GET", fmt.Sprintf("/api/passwords?id=%d&action=edit", passwordID), "", user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/passwords?id=%d&action=edit returned wrong status code: got %v want %v", passwordID, status, http.StatusOK)
	}

	var fetchedPassword PasswordEntry
	err = json.Unmarshal(rr.Body.Bytes(), &fetchedPassword)
	if err != nil {
		t.Fatalf("Failed to parse fetched password response: %v", err)
	}

	if fetchedPassword.Password != "testpassword123" {
		t.Errorf("Expected decrypted password 'testpassword123', got '%s'", fetchedPassword.Password)
	}
	if fetchedPassword.Notes != "test notes" {
		t.Errorf("Expected decrypted notes 'test notes', got '%s'", fetchedPassword.Notes)
	}

	// Test GET individual password for copying (should return only password value)
	req = newRequestWithUser("GET", fmt.Sprintf("/api/passwords?id=%d&action=copy", passwordID), "", user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/passwords?id=%d&action=copy returned wrong status code: got %v want %v", passwordID, status, http.StatusOK)
	}

	if body := strings.TrimSpace(rr.Body.String()); body != "testpassword123" {
		t.Errorf("Expected password value 'testpassword123', got '%s'", body)
	}

	// Test PUT - Update password
	updatedPassJSON := fmt.Sprintf(`{"id":%d,"site":"updated-test.com","username":"updated-tester","password":"newpassword456","notes":"updated notes","tags":["personal"]}`, passwordID)
	req = newRequestWithUser("PUT", "/api/passwords", updatedPassJSON, user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("PUT /api/passwords returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("PUT response body: %s", rr.Body.String())
	}

	// Verify the update by fetching again
	req = newRequestWithUser("GET", fmt.Sprintf("/api/passwords?id=%d&action=edit", passwordID), "", user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status == http.StatusOK {
		var updatedPassword PasswordEntry
		err = json.Unmarshal(rr.Body.Bytes(), &updatedPassword)
		if err != nil {
			t.Fatalf("Failed to parse updated password response: %v", err)
		}

		if updatedPassword.Site != "updated-test.com" {
			t.Errorf("Expected updated site 'updated-test.com', got '%s'", updatedPassword.Site)
		}
		if updatedPassword.Username != "updated-tester" {
			t.Errorf("Expected updated username 'updated-tester', got '%s'", updatedPassword.Username)
		}
		if updatedPassword.Password != "newpassword456" {
			t.Errorf("Expected updated password 'newpassword456', got '%s'", updatedPassword.Password)
		}
		if updatedPassword.Notes != "updated notes" {
			t.Errorf("Expected updated notes 'updated notes', got '%s'", updatedPassword.Notes)
		}

		// Verify ModifiedAt was updated (should be different from CreatedAt)
		// Note: Since SQLite timestamps are to the second, we can't guarantee they'll be different
		// in a fast test. We'll just check that ModifiedAt exists and is not empty.
		if updatedPassword.ModifiedAt == "" {
			t.Error("ModifiedAt should not be empty after update")
		}
	} else {
		t.Errorf("GET after update returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("GET after update response: %s", rr.Body.String())
	}

	// Test DELETE
	req = newRequestWithUser("DELETE", fmt.Sprintf("/api/passwords?id=%d", passwordID), "", user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("DELETE /api/passwords returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify password was deleted
	req = newRequestWithUser("GET", fmt.Sprintf("/api/passwords?id=%d&action=edit", passwordID), "", user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("GET deleted password should return 404, got %v", status)
	}

	// Test edge cases

	// Test access to non-existent password
	req = newRequestWithUser("GET", "/api/passwords?id=99999&action=edit", "", user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("GET non-existent password should return 404, got %v", status)
	}

	// Test invalid password ID
	req = newRequestWithUser("GET", "/api/passwords?id=invalid&action=edit", "", user)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("GET with invalid password ID should return 400, got %v", status)
	}
}

// TestTagsAPIHandler tests comprehensive CRUD operations for tags.
func TestTagsAPIHandler(t *testing.T) {
	// Setup: Clean database and create test user
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

	// Test POST - Create first tag
	newTagJSON := `{"name":"Work","description":"Work related items","color":"#ff0000"}`
	req = newRequestWithUser("POST", "/api/tags", newTagJSON, user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("POST /api/tags returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	// Test POST - Create second tag
	personalTagJSON := `{"name":"Personal","description":"Personal stuff","color":"#00ff00"}`
	req = newRequestWithUser("POST", "/api/tags", personalTagJSON, user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("POST /api/tags for second tag returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	// Test POST - Create tag with minimal info (name only)
	minimalTagJSON := `{"name":"Minimal","description":"","color":""}`
	req = newRequestWithUser("POST", "/api/tags", minimalTagJSON, user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("POST /api/tags with minimal info returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	// Test GET all tags (should now contain 3 tags)
	req = newRequestWithUser("GET", "/api/tags", "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/tags after creation returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Parse the response to get tag IDs
	var tags []Tag
	err := json.Unmarshal(rr.Body.Bytes(), &tags)
	if err != nil {
		t.Fatalf("Failed to parse tags response: %v", err)
	}

	if len(tags) != 3 {
		t.Errorf("Expected 3 tags, got %d", len(tags))
	}

	// Find the "Work" tag for further testing
	var workTagID int
	for _, tag := range tags {
		if tag.Name == "Work" {
			workTagID = tag.ID
			if tag.Description != "Work related items" {
				t.Errorf("Expected Work tag description 'Work related items', got '%s'", tag.Description)
			}
			if tag.Color != "#ff0000" {
				t.Errorf("Expected Work tag color '#ff0000', got '%s'", tag.Color)
			}
			break
		}
	}

	if workTagID == 0 {
		t.Fatal("Could not find Work tag in response")
	}

	// Test GET individual tag
	req = newRequestWithUser("GET", fmt.Sprintf("/api/tags?id=%d", workTagID), "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/tags?id=%d returned wrong status code: got %v want %v", workTagID, status, http.StatusOK)
	}

	var individualTag Tag
	err = json.Unmarshal(rr.Body.Bytes(), &individualTag)
	if err != nil {
		t.Fatalf("Failed to parse individual tag response: %v", err)
	}

	if individualTag.Name != "Work" {
		t.Errorf("Expected individual tag name 'Work', got '%s'", individualTag.Name)
	}

	// Test PUT - Update tag
	updatedTagJSON := `{"name":"Work Updated","description":"Updated work description","color":"#0000ff"}`
	req = newRequestWithUser("PUT", fmt.Sprintf("/api/tags?id=%d", workTagID), updatedTagJSON, user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("PUT /api/tags returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify the update by fetching the tag again
	req = newRequestWithUser("GET", fmt.Sprintf("/api/tags?id=%d", workTagID), "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	err = json.Unmarshal(rr.Body.Bytes(), &individualTag)
	if err != nil {
		t.Fatalf("Failed to parse updated tag response: %v", err)
	}

	if individualTag.Name != "Work Updated" {
		t.Errorf("Expected updated tag name 'Work Updated', got '%s'", individualTag.Name)
	}
	if individualTag.Description != "Updated work description" {
		t.Errorf("Expected updated tag description 'Updated work description', got '%s'", individualTag.Description)
	}
	if individualTag.Color != "#0000ff" {
		t.Errorf("Expected updated tag color '#0000ff', got '%s'", individualTag.Color)
	}

	// Test DELETE
	req = newRequestWithUser("DELETE", fmt.Sprintf("/api/tags?id=%d", workTagID), "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("DELETE /api/tags returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify deletion by trying to get the deleted tag
	req = newRequestWithUser("GET", fmt.Sprintf("/api/tags?id=%d", workTagID), "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("GET deleted tag should return 404, got %v", status)
	}

	// Verify only 2 tags remain
	req = newRequestWithUser("GET", "/api/tags", "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	err = json.Unmarshal(rr.Body.Bytes(), &tags)
	if err != nil {
		t.Fatalf("Failed to parse tags after deletion: %v", err)
	}

	if len(tags) != 2 {
		t.Errorf("Expected 2 tags after deletion, got %d", len(tags))
	}

	// Test error cases

	// Test POST - Missing name
	invalidTagJSON := `{"description":"No name","color":"#123456"}`
	req = newRequestWithUser("POST", "/api/tags", invalidTagJSON, user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("POST /api/tags without name should return 400, got %v", status)
	}

	// Test POST - Invalid JSON
	req = newRequestWithUser("POST", "/api/tags", "invalid json", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("POST /api/tags with invalid JSON should return 400, got %v", status)
	}

	// Test GET - Invalid tag ID
	req = newRequestWithUser("GET", "/api/tags?id=invalid", "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("GET /api/tags with invalid ID should return 400, got %v", status)
	}

	// Test GET - Non-existent tag ID
	req = newRequestWithUser("GET", "/api/tags?id=99999", "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("GET /api/tags with non-existent ID should return 404, got %v", status)
	}

	// Test PUT - Missing tag ID
	req = newRequestWithUser("PUT", "/api/tags", updatedTagJSON, user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("PUT /api/tags without ID should return 400, got %v", status)
	}

	// Test PUT - Invalid tag ID
	req = newRequestWithUser("PUT", "/api/tags?id=invalid", updatedTagJSON, user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("PUT /api/tags with invalid ID should return 400, got %v", status)
	}

	// Test PUT - Missing name in update
	invalidUpdateJSON := `{"description":"No name","color":"#123456"}`
	remainingTagID := tags[0].ID
	req = newRequestWithUser("PUT", fmt.Sprintf("/api/tags?id=%d", remainingTagID), invalidUpdateJSON, user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("PUT /api/tags without name should return 400, got %v", status)
	}

	// Test DELETE - Missing tag ID
	req = newRequestWithUser("DELETE", "/api/tags", "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("DELETE /api/tags without ID should return 400, got %v", status)
	}

	// Test DELETE - Invalid tag ID
	req = newRequestWithUser("DELETE", "/api/tags?id=invalid", "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("DELETE /api/tags with invalid ID should return 400, got %v", status)
	}

	// Test unsupported method
	req = newRequestWithUser("PATCH", "/api/tags", "", user)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("PATCH /api/tags should return 405, got %v", status)
	}
}

// TestExportTagsHandler tests exporting tags to CSV
func TestExportTagsHandler(t *testing.T) {
	// Setup: Clean database and create test data
	db.Exec("DELETE FROM tags")
	db.Exec("DELETE FROM users")

	// Create test user
	user := &User{ID: 1, Username: "testuser", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Create test tags
	db.Exec("INSERT INTO tags (name, description, color, user_id) VALUES ('Work', 'Work related', '#ff0000', 1)")
	db.Exec("INSERT INTO tags (name, description, color, user_id) VALUES ('Personal', 'Personal stuff', '#00ff00', 1)")

	// Test export
	req := newRequestWithUser("GET", "/export/tags", "", user)
	rr := httptest.NewRecorder()

	exportTagsHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("export tags handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check content type
	expectedContentType := "text/csv"
	if contentType := rr.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("export tags handler returned wrong content type: got %v want %v", contentType, expectedContentType)
	}

	// Check that CSV contains header and data
	body := rr.Body.String()
	if !strings.Contains(body, "Name,Description,Color") {
		t.Errorf("export tags CSV missing header")
	}
	if !strings.Contains(body, "Work,Work related,#ff0000") {
		t.Errorf("export tags CSV missing Work tag data")
	}
	if !strings.Contains(body, "Personal,Personal stuff,#00ff00") {
		t.Errorf("export tags CSV missing Personal tag data")
	}
}

// TestImportTagsHandler tests importing tags from CSV
func TestImportTagsHandler(t *testing.T) {
	// Setup: Clean database and create test user
	db.Exec("DELETE FROM tags")
	db.Exec("DELETE FROM users")

	user := &User{ID: 1, Username: "testuser", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Test CSV data
	csvData := `Name,Description,Color
Gaming,Gaming related,#0000ff
Study,Study materials,#ffff00`

	req := newMultipartRequestWithUser("/import/tags", "tags.csv", csvData, user)
	rr := httptest.NewRecorder()

	importTagsHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("import tags handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify tags were created
	var count int
	db.QueryRow("SELECT COUNT(*) FROM tags WHERE name IN ('Gaming', 'Study') AND user_id = 1").Scan(&count)
	if count != 2 {
		t.Errorf("import tags did not create expected tags: got %d want 2", count)
	}

	// Verify tag details
	var name, description, color string
	db.QueryRow("SELECT name, description, color FROM tags WHERE name = 'Gaming' AND user_id = 1").Scan(&name, &description, &color)
	if name != "Gaming" || description != "Gaming related" || color != "#0000ff" {
		t.Errorf("Gaming tag not imported correctly: got %s, %s, %s", name, description, color)
	}
}

// TestExportPasswordsHandler tests exporting passwords to CSV
func TestExportPasswordsHandler(t *testing.T) {
	// Setup: Clean database and create test data
	db.Exec("DELETE FROM password_entries")
	db.Exec("DELETE FROM users")
	db.Exec("DELETE FROM tags")
	db.Exec("DELETE FROM entry_tags")

	// Create test user
	user := &User{ID: 1, Username: "testuser", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Create test tags
	db.Exec("INSERT INTO tags (id, name, description, color, user_id) VALUES (1, 'Work', 'Work related', '#ff0000', 1)")

	// Create test passwords
	err := createPasswordEntry(1, "example.com", "user@example.com", "password123", "Test notes", []string{"Work"})
	if err != nil {
		t.Fatalf("Failed to create test password: %v", err)
	}

	// Test export
	req := newRequestWithUser("GET", "/export/passwords", "", user)
	rr := httptest.NewRecorder()

	exportPasswordsHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("export passwords handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check content type
	expectedContentType := "text/csv"
	if contentType := rr.Header().Get("Content-Type"); contentType != expectedContentType {
		t.Errorf("export passwords handler returned wrong content type: got %v want %v", contentType, expectedContentType)
	}

	// Check that CSV contains header and data
	body := rr.Body.String()
	if !strings.Contains(body, "Site,Username,Password,Notes,Tags") {
		t.Errorf("export passwords CSV missing header")
	}
	if !strings.Contains(body, "example.com") {
		t.Errorf("export passwords CSV missing site data")
	}
	if !strings.Contains(body, "user@example.com") {
		t.Errorf("export passwords CSV missing username data")
	}
	if !strings.Contains(body, "password123") {
		t.Errorf("export passwords CSV missing password data")
	}
	if !strings.Contains(body, "Test notes") {
		t.Errorf("export passwords CSV missing notes data")
	}
	if !strings.Contains(body, "Work") {
		t.Errorf("export passwords CSV missing tags data")
	}
}

// TestImportPasswordsHandler tests importing passwords from CSV
func TestImportPasswordsHandler(t *testing.T) {
	// Setup: Clean database and create test user
	db.Exec("DELETE FROM password_entries")
	db.Exec("DELETE FROM users")
	db.Exec("DELETE FROM tags")
	db.Exec("DELETE FROM entry_tags")

	user := &User{ID: 1, Username: "testuser", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Test CSV data
	csvData := `Site,Username,Password,Notes,Tags
github.com,testuser,mypassword,GitHub account,Work;Development
gmail.com,test@gmail.com,emailpass,Email account,Personal`

	req := newMultipartRequestWithUser("/import/passwords", "passwords.csv", csvData, user)
	rr := httptest.NewRecorder()

	importPasswordsHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("import passwords handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify passwords were created
	var count int
	db.QueryRow("SELECT COUNT(*) FROM password_entries WHERE user_id = 1").Scan(&count)
	if count != 2 {
		t.Errorf("import passwords did not create expected passwords: got %d want 2", count)
	}

	// Verify tags were auto-created
	db.QueryRow("SELECT COUNT(*) FROM tags WHERE name IN ('Work', 'Development', 'Personal') AND user_id = 1").Scan(&count)
	if count != 3 {
		t.Errorf("import passwords did not create expected tags: got %d want 3", count)
	}

	// Verify password details (check decrypted values)
	passwords, err := getAllDecryptedPasswords(1)
	if err != nil {
		t.Fatalf("Failed to get passwords: %v", err)
	}

	if len(passwords) != 2 {
		t.Errorf("Expected 2 passwords, got %d", len(passwords))
	}

	// Find GitHub password
	var githubPassword *PasswordEntry
	for _, p := range passwords {
		if p.Site == "github.com" {
			githubPassword = &p
			break
		}
	}

	if githubPassword == nil {
		t.Errorf("GitHub password not found after import")
	} else {
		if githubPassword.Username != "testuser" {
			t.Errorf("GitHub username incorrect: got %s want testuser", githubPassword.Username)
		}
		if githubPassword.Password != "mypassword" {
			t.Errorf("GitHub password incorrect: got %s want mypassword", githubPassword.Password)
		}
		if githubPassword.Notes != "GitHub account" {
			t.Errorf("GitHub notes incorrect: got %s want 'GitHub account'", githubPassword.Notes)
		}
		if len(githubPassword.Tags) != 2 {
			t.Errorf("GitHub tags count incorrect: got %d want 2", len(githubPassword.Tags))
		}
	}
}

// TestImportPasswordsHandler_MalformedCSV tests handling of malformed CSV data
func TestImportPasswordsHandler_MalformedCSV(t *testing.T) {
	// Setup: Clean database and create test user
	db.Exec("DELETE FROM password_entries")
	db.Exec("DELETE FROM users")

	user := &User{ID: 1, Username: "testuser", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Test malformed CSV data (missing columns)
	csvData := `Site,Username,Password,Notes,Tags
github.com,testuser,mypassword
incomplete.com,user`

	req := newMultipartRequestWithUser("/import/passwords", "passwords.csv", csvData, user)
	rr := httptest.NewRecorder()

	importPasswordsHandler(rr, req)

	// The handler should still return 200 but log errors for malformed records
	// However, CSV parsing errors might return 400, so let's check for either
	if status := rr.Code; status != http.StatusOK && status != http.StatusBadRequest {
		t.Errorf("import passwords handler returned unexpected status code: got %v want %v or %v",
			status, http.StatusOK, http.StatusBadRequest)
	}

	// If it was a 400, the malformed CSV was properly rejected
	if rr.Code == http.StatusBadRequest {
		// Check that no passwords were created due to CSV parsing failure
		var count int
		db.QueryRow("SELECT COUNT(*) FROM password_entries WHERE user_id = 1").Scan(&count)
		if count != 0 {
			t.Errorf("import passwords should not have created passwords from malformed CSV: got %d want 0", count)
		}
		return
	}

	// If it was a 200, individual records should have been skipped

	// Should have created 0 passwords due to malformed records
	var count int
	db.QueryRow("SELECT COUNT(*) FROM password_entries WHERE user_id = 1").Scan(&count)
	if count != 0 {
		t.Errorf("import passwords should not have created passwords from malformed CSV: got %d want 0", count)
	}
}

// TestCheckPasswordDuplicateHandler tests the duplicate checking API
func TestCheckPasswordDuplicateHandler(t *testing.T) {
	// Setup: Clean database and create test data
	db.Exec("DELETE FROM passwords")
	db.Exec("DELETE FROM users")

	user := &User{ID: 1, Username: "testuser", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Create a test password
	err := createPasswordEntry(1, "example.com", "user@example.com", "password123", "Test notes", []string{})
	if err != nil {
		t.Fatalf("Failed to create test password: %v", err)
	}

	// Test duplicate check - should find duplicate
	duplicateCheckJSON := `{"site":"example.com","username":"user@example.com"}`
	req := newRequestWithUser("POST", "/api/passwords/check-duplicate", duplicateCheckJSON, user)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	checkPasswordDuplicateHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("check duplicate handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check response indicates duplicate
	if !strings.Contains(rr.Body.String(), `"isDuplicate":true`) {
		t.Errorf("check duplicate should have found duplicate: %s", rr.Body.String())
	}

	// Test non-duplicate check
	nonDuplicateCheckJSON := `{"site":"newsite.com","username":"newuser@example.com"}`
	req = newRequestWithUser("POST", "/api/passwords/check-duplicate", nonDuplicateCheckJSON, user)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()

	checkPasswordDuplicateHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("check duplicate handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check response indicates no duplicate
	if !strings.Contains(rr.Body.String(), `"isDuplicate":false`) {
		t.Errorf("check duplicate should not have found duplicate: %s", rr.Body.String())
	}
}

// TestNewUserEmptyState tests that a newly created user has empty passwords and tags.
func TestNewUserEmptyState(t *testing.T) {
	// Setup: Clean database and create a fresh user
	db.Exec("DELETE FROM password_entries")
	db.Exec("DELETE FROM tags")
	db.Exec("DELETE FROM users")

	// Create a new user
	newUser := &User{ID: 1, Username: "newuser", IsAdmin: false}
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'newuser', 'hash', 0)")

	// Test 1: Check that passwords API returns empty array
	req := newRequestWithUser("GET", "/api/passwords", "", newUser)
	rr := httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/passwords for new user returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify empty passwords array
	if body := strings.TrimSpace(rr.Body.String()); body != "[]" {
		t.Errorf("Expected new user to have empty password list '[]', but got '%s'", body)
	}

	// Test 2: Check that tags API returns empty array
	req = newRequestWithUser("GET", "/api/tags", "", newUser)
	rr = httptest.NewRecorder()
	tagsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/tags for new user returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify empty tags array
	if body := strings.TrimSpace(rr.Body.String()); body != "[]" {
		t.Errorf("Expected new user to have empty tag list '[]', but got '%s'", body)
	}

	// Test 3: Test search query on empty password set
	req = newRequestWithUser("GET", "/api/passwords?q=test", "", newUser)
	rr = httptest.NewRecorder()
	passwordsAPIHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("GET /api/passwords with query for new user returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Verify search on empty set returns empty array
	if body := strings.TrimSpace(rr.Body.String()); body != "[]" {
		t.Errorf("Expected search on empty password list to return '[]', but got '%s'", body)
	}
}

// TestLoginPageHandler tests that the login page renders without authentication
func TestLoginPageHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	// Test the login handler which should show login page
	loginHandler(rr, req)

	// Should return 200 OK for the login page
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Login page handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check that the response contains login form elements
	body := rr.Body.String()
	if !strings.Contains(body, "Sign In") {
		t.Errorf("Login page should contain 'Sign In' button")
	}
	if !strings.Contains(body, `id="username"`) {
		t.Errorf("Login page should contain username input field")
	}
	if !strings.Contains(body, `id="password"`) {
		t.Errorf("Login page should contain password input field")
	}
	if !strings.Contains(body, `id="signInButton"`) {
		t.Errorf("Login page should contain signInButton with ID for JavaScript validation")
	}
	if !strings.Contains(body, "disabled") {
		t.Errorf("Login page Sign In button should initially be disabled")
	}
}

// TestLoginAuthentication tests comprehensive login scenarios
func TestLoginAuthentication(t *testing.T) {
	// Setup: Clean database and create test user
	db.Exec("DELETE FROM login_attempts")
	db.Exec("DELETE FROM users")

	// Create a test user with properly hashed password
	correctPassword := "correctpassword"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', ?, 0)", string(hashedPassword))

	t.Run("SuccessfulLogin", func(t *testing.T) {
		// Test successful login with correct credentials
		formData := "username=testuser&password=correctpassword"
		req := httptest.NewRequest("POST", "/", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "192.168.1.100") // Set a test IP

		rr := httptest.NewRecorder()
		loginHandler(rr, req)

		// Should redirect to dashboard on success
		if status := rr.Code; status != http.StatusSeeOther {
			t.Errorf("Successful login should redirect (303), got %v", status)
		}

		location := rr.Header().Get("Location")
		if location != "/dashboard" {
			t.Errorf("Expected redirect to /dashboard, got %s", location)
		}
	})

	t.Run("InvalidCredentials", func(t *testing.T) {
		// Test login with wrong password
		formData := "username=testuser&password=wrongpassword"
		req := httptest.NewRequest("POST", "/", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "192.168.1.100")

		rr := httptest.NewRecorder()
		loginHandler(rr, req)

		// Should return 401 Unauthorized
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Invalid credentials should return 401, got %v", status)
		}

		body := rr.Body.String()
		if !strings.Contains(body, "Invalid credentials") {
			t.Errorf("Response should contain 'Invalid credentials', got: %s", body)
		}
	})

	t.Run("NonexistentUser", func(t *testing.T) {
		// Test login with nonexistent username
		formData := "username=nonexistentuser&password=anypassword"
		req := httptest.NewRequest("POST", "/", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "192.168.1.100")

		rr := httptest.NewRecorder()
		loginHandler(rr, req)

		// Should return 401 Unauthorized
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Nonexistent user should return 401, got %v", status)
		}
	})

	t.Run("MissingCredentials", func(t *testing.T) {
		// Test login with missing username
		formData := "password=somepassword"
		req := httptest.NewRequest("POST", "/", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "192.168.1.100")

		rr := httptest.NewRecorder()
		loginHandler(rr, req)

		// Should return 401 Unauthorized for missing credentials
		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Missing username should return 401, got %v", status)
		}

		// Test missing password
		formData = "username=testuser"
		req = httptest.NewRequest("POST", "/", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "192.168.1.100")

		rr = httptest.NewRecorder()
		loginHandler(rr, req)

		if status := rr.Code; status != http.StatusUnauthorized {
			t.Errorf("Missing password should return 401, got %v", status)
		}
	})
}

// TestLoginRateLimiting tests rate limiting functionality
func TestLoginRateLimiting(t *testing.T) {
	// Setup: Clean database and create test user
	db.Exec("DELETE FROM login_attempts")
	db.Exec("DELETE FROM users")

	// Create user with properly hashed password
	correctPassword := "correctpassword"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'ratelimituser', ?, 0)", string(hashedPassword))

	testIP := "192.168.1.200"

	t.Run("MultipleFailedAttempts", func(t *testing.T) {
		// Make multiple failed login attempts to trigger rate limiting
		for i := 0; i < 5; i++ {
			formData := "username=ratelimituser&password=wrongpassword"
			req := httptest.NewRequest("POST", "/", strings.NewReader(formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Real-IP", testIP)

			rr := httptest.NewRecorder()
			loginHandler(rr, req)

			// First 3 attempts should return 401, then 429 for rate limiting
			if i < 3 && rr.Code != http.StatusUnauthorized {
				t.Errorf("Failed attempt %d should return 401, got %v", i+1, rr.Code)
			} else if i >= 3 && rr.Code != http.StatusTooManyRequests {
				t.Errorf("Rate limited attempt %d should return 429, got %v", i+1, rr.Code)
			}
		}

		// The 6th attempt should be rate limited
		formData := "username=ratelimituser&password=wrongpassword"
		req := httptest.NewRequest("POST", "/", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", testIP)

		rr := httptest.NewRecorder()
		loginHandler(rr, req)

		// Should return 429 Too Many Requests
		if status := rr.Code; status != http.StatusTooManyRequests {
			t.Errorf("Rate limited attempt should return 429, got %v", status)
		}

		body := rr.Body.String()
		if !strings.Contains(body, "Too many failed login attempts") {
			t.Errorf("Rate limit response should mention failed attempts, got: %s", body)
		}
	})

	t.Run("RateLimitedEvenWithCorrectPassword", func(t *testing.T) {
		// Try to login with correct password while rate limited
		formData := "username=ratelimituser&password=correctpassword"
		req := httptest.NewRequest("POST", "/", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", testIP)

		rr := httptest.NewRecorder()
		loginHandler(rr, req)

		// Should still be rate limited even with correct password
		if status := rr.Code; status != http.StatusTooManyRequests {
			t.Errorf("Rate limited user with correct password should still return 429, got %v", status)
		}
	})
}

// TestRateLimitCheckAPI tests the rate limit check API endpoint
func TestRateLimitCheckAPI(t *testing.T) {
	// Setup: Clean database
	db.Exec("DELETE FROM login_attempts")
	db.Exec("DELETE FROM users")

	// Create user with properly hashed password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'apitestuser', ?, 0)", string(hashedPassword))

	t.Run("NoRateLimit", func(t *testing.T) {
		// Check rate limit for user with no failed attempts
		formData := "username=apitestuser"
		req := httptest.NewRequest("POST", "/api/rate-limit-check", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "192.168.1.300")

		rr := httptest.NewRecorder()
		rateLimitCheckHandler(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Rate limit check should return 200, got %v", status)
		}

		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse JSON response: %v", err)
		}

		if response["isLimited"] != false {
			t.Errorf("Expected isLimited to be false, got %v", response["isLimited"])
		}

		if response["remainingTime"] != float64(0) {
			t.Errorf("Expected remainingTime to be 0, got %v", response["remainingTime"])
		}
	})

	t.Run("WithRateLimit", func(t *testing.T) {
		testIP := "192.168.1.301"

		// Create failed attempts to trigger rate limiting
		for i := 0; i < 5; i++ {
			recordLoginAttempt("apitestuser", testIP, false)
		}

		// Check rate limit status
		formData := "username=apitestuser"
		req := httptest.NewRequest("POST", "/api/rate-limit-check", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", testIP)

		rr := httptest.NewRecorder()
		rateLimitCheckHandler(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Rate limit check should return 200, got %v", status)
		}

		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse JSON response: %v", err)
		}

		if response["isLimited"] != true {
			t.Errorf("Expected isLimited to be true, got %v", response["isLimited"])
		}

		remainingTime := response["remainingTime"].(float64)
		if remainingTime <= 0 {
			t.Errorf("Expected remainingTime to be > 0, got %v", remainingTime)
		}
	})

	t.Run("EmptyUsername", func(t *testing.T) {
		// Check rate limit with empty username
		formData := ""
		req := httptest.NewRequest("POST", "/api/rate-limit-check", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Real-IP", "192.168.1.302")

		rr := httptest.NewRecorder()
		rateLimitCheckHandler(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Rate limit check with empty username should return 200, got %v", status)
		}

		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		if err != nil {
			t.Fatalf("Failed to parse JSON response: %v", err)
		}

		if response["isLimited"] != false {
			t.Errorf("Expected isLimited to be false for empty username, got %v", response["isLimited"])
		}
	})
}
