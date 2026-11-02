// Copyright (C) 2025 Joshua Goldstein

// constants.go - User-configurable application constants
package main

import "time"

// Session constants
const (
	sessionDuration = 60 * time.Minute // Idle timeout; also the initial session lifetime
)

// Rate limiting constants
const (
	maxLoginAttempts     = 3
	cooldownDuration     = 30 * time.Second
	maxLoginAttemptsHard = 6
	hardCooldownDuration = 5 * time.Minute
)

// Cleanup constants
const (
	sessionCleanupInterval       = 10 * time.Minute
	loginAttemptsCleanupInterval = 1 * time.Hour
	loginAttemptsRetentionPeriod = 24 * time.Hour
)

// Tag constants
const defaultTagColor = "#6B7280" // dark gray

// Server constants
const defaultServerPort = "7000"

// Network / cookie constants
const (
	defaultBindAddr       = "127.0.0.1"            // Loopback only; the HTTPS reverse proxy connects here
	bindAddrEnvVar        = "PWD_BIND_ADDR"        // Optional override, e.g. "0.0.0.0" to listen on all interfaces
	insecureCookiesEnvVar = "PWD_INSECURE_COOKIES" // Optional; "1" drops the Secure cookie flag (plain-HTTP dev only)
	sessionCookieName     = "session_token"
)

// Database constants
const dbFileEnvVar = "PWD_DB_FILE" // Required; absolute path to the SQLite database file
