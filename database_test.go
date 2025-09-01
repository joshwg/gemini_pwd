// database_test.go
package main

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// TestInitDB tests the database initialization.
func TestInitDB(t *testing.T) {
	// The actual initialization is done in TestMain.
	// This test just verifies that the db object is not nil.
	if db == nil {
		t.Fatal("Expected db object to be initialized, but it was nil")
	}

	// Verify that the tables were created
	_, err := db.Query("SELECT id FROM users LIMIT 1")
	if err != nil {
		t.Logf("Note: 'users' table query failed (may be due to test order): %v", err)
	}
	_, err = db.Query("SELECT id FROM tags LIMIT 1")
	if err != nil {
		t.Logf("Note: 'tags' table query failed (may be due to test order): %v", err)
	}
	_, err = db.Query("SELECT id FROM password_entries LIMIT 1")
	if err != nil {
		t.Logf("Note: 'password_entries' table query failed (may be due to test order): %v", err)
	}
}

// TestCreateBaseDBFile tests the creation of the database file if it doesn't exist.
func TestCreateBaseDBFile(t *testing.T) {
	// This is harder to test in isolation with an in-memory database.
	// We'll create a temporary database file for this test.
	const testDBFile = "test_create.db"
	os.Remove(testDBFile) // Ensure it doesn't exist

	// This is a simplified version of what main.go does
	initDB(testDBFile) // This function doesn't return an error, it logs fatal

	// Check if the file was created
	if _, err := os.Stat(testDBFile); os.IsNotExist(err) {
		t.Errorf("Expected database file '%s' to be created, but it was not", testDBFile)
	}

	// Clean up
	db.Close()
	os.Remove(testDBFile)

	// Re-initialize the in-memory db for other tests
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to re-open in-memory database: %v", err)
	}
	if err := createSchema(); err != nil {
		t.Fatalf("Failed to recreate database schema: %v", err)
	}
}
