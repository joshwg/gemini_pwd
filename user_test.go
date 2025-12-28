// Copyright (C) 2025 Joshua Goldstein

// user_test.go
package main

import (
	"testing"
)

// TestCreateUser tests the createUser function.
func TestCreateUser(t *testing.T) {
	// Setup: Ensure the database schema exists and is clean
	ensureTestDB()

	// Create a dummy admin user for context
	admin := &User{ID: 1, Username: "admin", IsAdmin: true}

	// Test case 1: Successful user creation
	err := createUser(admin, "testuser", "password123", false, false)
	if err != nil {
		t.Errorf("Expected no error when creating a valid user, but got: %v", err)
	}

	// Verify the user was actually created
	var username string
	err = db.QueryRow("SELECT username FROM users WHERE username = 'testuser'").Scan(&username)
	if err != nil {
		t.Errorf("Failed to find the newly created user in the database: %v", err)
	}
	if username != "testuser" {
		t.Errorf("Expected username 'testuser', but got '%s'", username)
	}

	// Test case 2: Creating a user that already exists
	err = createUser(admin, "testuser", "password123", false, false)
	if err == nil {
		t.Errorf("Expected an error when creating a user that already exists, but got nil")
	}

	// Test case 3: Non-admin trying to create a user
	nonAdmin := &User{ID: 2, Username: "nonadmin", IsAdmin: false}
	err = createUser(nonAdmin, "anotheruser", "password123", false, false)
	if err == nil {
		t.Errorf("Expected an error when a non-admin tries to create a user, but got nil")
	}
}

// TestCreateTag tests the createTag function.
func TestCreateTag(t *testing.T) {
	// Setup: Ensure the database schema exists and is clean
	ensureTestDB()
	db.Exec("DELETE FROM tags")

	// We need a user to associate the tag with
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Test case 1: Successful tag creation
	err := createTag(1, "Work", "Work related passwords", "#ff0000")
	if err != nil {
		t.Errorf("Expected no error when creating a valid tag, but got: %v", err)
	}

	// Verify the tag was created
	var name string
	err = db.QueryRow("SELECT name FROM tags WHERE name = 'Work' AND user_id = 1").Scan(&name)
	if err != nil {
		t.Errorf("Failed to find the newly created tag in the database: %v", err)
	}
	if name != "Work" {
		t.Errorf("Expected tag name 'Work', but got '%s'", name)
	}

	// Test case 2: Creating a tag that already exists for the same user
	err = createTag(1, "Work", "A duplicate tag", "#00ff00")
	if err == nil {
		t.Errorf("Expected an error when creating a tag that already exists, but got nil")
	}
}

// TestCreatePasswordEntry tests the createPasswordEntry function.
func TestCreatePasswordEntry(t *testing.T) {
	// Setup: Ensure the database schema exists and is clean
	ensureTestDB()
	db.Exec("DELETE FROM password_entries")
	db.Exec("DELETE FROM entry_tags")
	db.Exec("DELETE FROM tags")
	db.Exec("INSERT INTO users (id, username, password_hash, is_admin) VALUES (1, 'testuser', 'hash', 0)")

	// Test case 1: Successful password entry creation with a new tag
	tags := []string{"Social"}
	err := createPasswordEntry(1, "example.com", "user@example.com", "supersecret", "My notes", tags)
	if err != nil {
		t.Errorf("Expected no error when creating a valid password entry, but got: %v", err)
	}

	// Verify the password entry was created
	var site string
	err = db.QueryRow("SELECT site FROM password_entries WHERE site = 'example.com' AND user_id = 1").Scan(&site)
	if err != nil {
		t.Errorf("Failed to find the newly created password entry in the database: %v", err)
	}
	if site != "example.com" {
		t.Errorf("Expected site 'example.com', but got '%s'", site)
	}

	// Verify the tag was created and linked
	var tagID int
	var entryID int
	err = db.QueryRow("SELECT id FROM tags WHERE name = 'Social'").Scan(&tagID)
	if err != nil {
		t.Errorf("Failed to find the newly created tag: %v", err)
	}
	err = db.QueryRow("SELECT entry_id FROM entry_tags WHERE tag_id = ?", tagID).Scan(&entryID)
	if err != nil {
		t.Errorf("Failed to find the link between the entry and the tag: %v", err)
	}
}
