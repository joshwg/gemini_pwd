// Copyright (C) 2025 Joshua Goldstein

//go:build test || !production
// +build test !production

package main

import "os"

// init sets up the test environment before any other init() functions run.
// This file is named to ensure it loads first (alphabetically before encrypt.go).
func init() {
	// Set PWD_SECRET_KEY for testing if not already set
	// This must run before encrypt.go's init() function
	if os.Getenv("PWD_SECRET_KEY") == "" {
		os.Setenv("PWD_SECRET_KEY", "12345678901234567890123456789012") // 32 bytes
	}
}
