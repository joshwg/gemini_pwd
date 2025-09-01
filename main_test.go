// main_test.go
package main

import (
	"database/sql"
	"log"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestMain is the entry point for testing. It sets up an in-memory SQLite database
// and runs the tests.
func TestMain(m *testing.M) {
	// Use an in-memory SQLite database for testing
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatalf("Failed to open in-memory database: %v", err)
	}
	defer db.Close()

	// Create the database schema
	if err := createSchema(); err != nil {
		log.Fatalf("Failed to create database schema: %v", err)
	}

	// Run the tests
	exitCode := m.Run()

	// Exit with the test result
	os.Exit(exitCode)
}

// createSchema creates the database schema for tests using SQLite syntax
func createSchema() error {
	// SQLite-compatible schema for testing
	schema := `
	-- Create the users table
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		is_admin BOOLEAN NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Create the sessions table 
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);

	-- Create the tags table
	CREATE TABLE IF NOT EXISTS tags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT,
		color TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);

	-- Create the passwords table (named password_entries in the code)
	CREATE TABLE IF NOT EXISTS password_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		site TEXT NOT NULL,
		username TEXT NOT NULL,
		password_encrypted BLOB NOT NULL,
		notes_encrypted BLOB,
		salt BLOB NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		modified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
		UNIQUE(user_id, site, username)
	);

	-- Create entry_tags junction table
	CREATE TABLE IF NOT EXISTS entry_tags (
		entry_id INTEGER NOT NULL,
		tag_id INTEGER NOT NULL,
		PRIMARY KEY (entry_id, tag_id),
		FOREIGN KEY (entry_id) REFERENCES password_entries (id) ON DELETE CASCADE,
		FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
	);

	-- Create login_attempts table
	CREATE TABLE IF NOT EXISTS login_attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		successful BOOLEAN NOT NULL DEFAULT 0,
		attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Create indexes for better performance
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
	CREATE INDEX IF NOT EXISTS idx_password_entries_user_id ON password_entries (user_id);
	CREATE INDEX IF NOT EXISTS idx_password_entries_site ON password_entries (site);
	CREATE INDEX IF NOT EXISTS idx_entry_tags_entry_id ON entry_tags (entry_id);
	CREATE INDEX IF NOT EXISTS idx_entry_tags_tag_id ON entry_tags (tag_id);
	`
	_, err := db.Exec(schema)
	return err
}

// TestDatabaseInitialization is a basic test to ensure the db is set up.
func TestDatabaseInitialization(t *testing.T) {
	if db == nil {
		t.Fatal("database is nil, TestMain setup failed")
	}
	// Ping to ensure the connection is alive
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to ping database: %v", err)
	}
}
