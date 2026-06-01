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
