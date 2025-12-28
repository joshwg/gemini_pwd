// Copyright (C) 2025 Joshua Goldstein

// main_test.go
package main

import (
	"database/sql"
	templatePkg "gemini_pwd/pkg/template"
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

	// Initialize template renderer for tests
	templatePkg.InitRenderer("templates", "base.html")

	// Run the tests
	exitCode := m.Run()

	// Exit with the test result
	os.Exit(exitCode)
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
