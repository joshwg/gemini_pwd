// database.go
package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// db is our global database connection pool. It is declared here
// to be accessible across all files in the main package.
var db *sql.DB

// initDB initializes the database connection and creates tables if they don't exist.
func initDB(filepath string) {
	var err error
	db, err = sql.Open("sqlite3", filepath+"?_foreign_keys=on")
	if err != nil {
		log.Fatal(err)
	}

	createTables := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		is_admin TINYINT(1) NOT NULL DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS tags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		color TEXT,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(user_id, name)
	);
	CREATE TABLE IF NOT EXISTS password_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		site TEXT NOT NULL,
		username TEXT NOT NULL,
		password_encrypted BLOB,
		notes_encrypted BLOB,
		salt BLOB NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS entry_tags (
		entry_id INTEGER NOT NULL,
		tag_id INTEGER NOT NULL,
		PRIMARY KEY (entry_id, tag_id),
		FOREIGN KEY(entry_id) REFERENCES password_entries(id) ON DELETE CASCADE,
		FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS login_attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		successful BOOLEAN NOT NULL DEFAULT 0,
		attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
	CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);
	`
	_, err = db.Exec(createTables)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}

	// Check if the super user exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'super'").Scan(&count)
	if err != nil {
		log.Fatalf("Failed to check for super user: %v", err)
	}

	if count == 0 {
		fmt.Println("Creating 'super' administrator user...")
		hash, err := bcrypt.GenerateFromPassword([]byte("abcd1234"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Failed to hash super user password: %v", err)
		}
		_, err = db.Exec("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)", "super", string(hash))
		if err != nil {
			log.Fatalf("Failed to create super user: %v", err)
		}
		fmt.Println("'super' user created with password 'abcd1234'. Please change it immediately.")
	}
}
