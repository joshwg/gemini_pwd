// test_utils.go
package main

import (
	"testing"
)

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

	-- Create the password_entries table
	CREATE TABLE IF NOT EXISTS password_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site TEXT NOT NULL,
		username TEXT NOT NULL,
		encrypted_password TEXT NOT NULL,
		notes TEXT,
		user_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
	);

	-- Create the entry_tags junction table
	CREATE TABLE IF NOT EXISTS entry_tags (
		entry_id INTEGER NOT NULL,
		tag_id INTEGER NOT NULL,
		PRIMARY KEY (entry_id, tag_id),
		FOREIGN KEY (entry_id) REFERENCES password_entries (id) ON DELETE CASCADE,
		FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
	);

	-- Create the login_attempts table
	CREATE TABLE IF NOT EXISTS login_attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		success BOOLEAN NOT NULL DEFAULT 0
	);

	-- Create indexes for better performance
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
	CREATE INDEX IF NOT EXISTS idx_tags_user_id ON tags (user_id);
	CREATE INDEX IF NOT EXISTS idx_password_entries_user_id ON password_entries (user_id);
	CREATE INDEX IF NOT EXISTS idx_password_entries_site ON password_entries (site);
	CREATE INDEX IF NOT EXISTS idx_entry_tags_entry_id ON entry_tags (entry_id);
	CREATE INDEX IF NOT EXISTS idx_entry_tags_tag_id ON entry_tags (tag_id);
	`
	_, err := db.Exec(schema)
	return err
}

// ensureTestDB makes sure the database schema exists and is clean for all tests
func ensureTestDB(t *testing.T) {
	// Initialize the global db connection to the test database using the real application's schema
	// This ensures we have exactly the same schema as production
	initDB("test_passwords.db")

	// Clean existing data in dependency order
	cleanTables := []string{"entry_tags", "password_entries", "tags", "sessions", "login_attempts", "users"}
	for _, table := range cleanTables {
		db.Exec("DELETE FROM " + table)
	}
}

// setupTestDB deprecated - use ensureTestDB instead
func setupTestDB() *testing.T {
	return nil
}

// cleanTestDB deprecated - cleaning is now handled by ensureTestDB
func cleanTestDB() {
	// This function is now handled by ensureTestDB
}
