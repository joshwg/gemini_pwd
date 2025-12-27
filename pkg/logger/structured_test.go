// Package logger tests
// Copyright (C) 2025 Joshua Goldstein

package logger

import (
	"bytes"
	"log"
	"testing"
)

// captureLogOutput captures log output for testing
func captureLogOutput(fn func()) string {
	var buf bytes.Buffer

	// Save original log output
	originalOutput := log.Writer()
	originalFlags := log.Flags()

	// Set log to write to our buffer
	log.SetOutput(&buf)
	log.SetFlags(0) // Remove timestamp for consistent testing

	// Execute function
	fn()

	// Restore original log settings
	log.SetOutput(originalOutput)
	log.SetFlags(originalFlags)

	return buf.String()
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{
			name:   "Logger with prefix",
			prefix: "TEST",
		},
		{
			name:   "Logger without prefix",
			prefix: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.prefix)
			if logger.prefix != tt.prefix {
				t.Errorf("NewLogger() prefix = %v, expected %v", logger.prefix, tt.prefix)
			}
		})
	}
}

func TestLoggerInfo(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		message  string
		args     []interface{}
		contains string
	}{
		{
			name:     "Info without prefix",
			prefix:   "",
			message:  "Server starting",
			args:     nil,
			contains: "ℹ️ Server starting",
		},
		{
			name:     "Info with prefix",
			prefix:   "API",
			message:  "Request received",
			args:     nil,
			contains: "ℹ️ [API] Request received",
		},
		{
			name:     "Info with formatting",
			prefix:   "",
			message:  "User %s logged in",
			args:     []interface{}{"john"},
			contains: "ℹ️ User john logged in",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.prefix)
			output := captureLogOutput(func() {
				logger.Info(tt.message, tt.args...)
			})

			if !containsString(output, tt.contains) {
				t.Errorf("Info() output = %q, should contain %q", output, tt.contains)
			}
		})
	}
}

func TestLoggerSuccess(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		message  string
		contains string
	}{
		{
			name:     "Success without prefix",
			prefix:   "",
			message:  "Operation completed",
			contains: "✅ Operation completed",
		},
		{
			name:     "Success with prefix",
			prefix:   "DB",
			message:  "Migration finished",
			contains: "✅ [DB] Migration finished",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.prefix)
			output := captureLogOutput(func() {
				logger.Success(tt.message)
			})

			if !containsString(output, tt.contains) {
				t.Errorf("Success() output = %q, should contain %q", output, tt.contains)
			}
		})
	}
}

func TestLoggerWarning(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		message  string
		contains string
	}{
		{
			name:     "Warning without prefix",
			prefix:   "",
			message:  "Deprecated API used",
			contains: "⚠️ Deprecated API used",
		},
		{
			name:     "Warning with prefix",
			prefix:   "AUTH",
			message:  "Token expires soon",
			contains: "⚠️ [AUTH] Token expires soon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.prefix)
			output := captureLogOutput(func() {
				logger.Warning(tt.message)
			})

			if !containsString(output, tt.contains) {
				t.Errorf("Warning() output = %q, should contain %q", output, tt.contains)
			}
		})
	}
}

func TestLoggerError(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		message  string
		err      error
		contains string
	}{
		{
			name:     "Error without error object",
			prefix:   "",
			message:  "Operation failed",
			err:      nil,
			contains: "❌ Operation failed",
		},
		{
			name:     "Error with error object",
			prefix:   "",
			message:  "Database connection failed",
			err:      &testError{"connection timeout"},
			contains: "❌ Database connection failed - connection timeout",
		},
		{
			name:     "Error with prefix",
			prefix:   "DB",
			message:  "Query failed",
			err:      &testError{"syntax error"},
			contains: "❌ [DB] Query failed - syntax error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.prefix)
			output := captureLogOutput(func() {
				logger.Error(tt.message, tt.err)
			})

			if !containsString(output, tt.contains) {
				t.Errorf("Error() output = %q, should contain %q", output, tt.contains)
			}
		})
	}
}

func TestLoggerSecurity(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		event    string
		details  map[string]interface{}
		contains []string
	}{
		{
			name:     "Security event without details",
			prefix:   "",
			event:    "Failed login attempt",
			details:  nil,
			contains: []string{"🔐 SECURITY: Failed login attempt"},
		},
		{
			name:     "Security event with details",
			prefix:   "",
			event:    "Unauthorized access",
			details:  map[string]interface{}{"ip": "192.168.1.100", "endpoint": "/admin"},
			contains: []string{"🔐 SECURITY: Unauthorized access", "ip=192.168.1.100", "endpoint=/admin"},
		},
		{
			name:     "Security event with prefix",
			prefix:   "AUTH",
			event:    "Password changed",
			details:  map[string]interface{}{"user_id": 123},
			contains: []string{"[AUTH] 🔐 SECURITY: Password changed", "user_id=123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.prefix)
			output := captureLogOutput(func() {
				logger.Security(tt.event, tt.details)
			})

			for _, expected := range tt.contains {
				if !containsString(output, expected) {
					t.Errorf("Security() output = %q, should contain %q", output, expected)
				}
			}
		})
	}
}

func TestDefaultLoggerFunctions(t *testing.T) {
	tests := []struct {
		name     string
		fn       func()
		contains string
	}{
		{
			name: "Default Info",
			fn: func() {
				Info("Test info message")
			},
			contains: "ℹ️ Test info message",
		},
		{
			name: "Default Success",
			fn: func() {
				Success("Test success message")
			},
			contains: "✅ Test success message",
		},
		{
			name: "Default Warning",
			fn: func() {
				Warning("Test warning message")
			},
			contains: "⚠️ Test warning message",
		},
		{
			name: "Default Error",
			fn: func() {
				Error("Test error message", &testError{"test error"})
			},
			contains: "❌ Test error message - test error",
		},
		{
			name: "Default Security",
			fn: func() {
				Security("Test security event", map[string]interface{}{"test": "value"})
			},
			contains: "🔐 SECURITY: Test security event",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureLogOutput(tt.fn)

			if !containsString(output, tt.contains) {
				t.Errorf("Function output = %q, should contain %q", output, tt.contains)
			}
		})
	}
}

func TestLoggerFormatMessage(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		emoji    string
		level    string
		message  string
		expected string
	}{
		{
			name:     "Format without prefix",
			prefix:   "",
			emoji:    "✅",
			level:    "SUCCESS",
			message:  "Test message",
			expected: "✅ Test message",
		},
		{
			name:     "Format with prefix",
			prefix:   "TEST",
			emoji:    "❌",
			level:    "ERROR",
			message:  "Error message",
			expected: "❌ [TEST] Error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.prefix)
			result := logger.formatMessage(tt.emoji, tt.level, tt.message)

			if result != tt.expected {
				t.Errorf("formatMessage() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// testError is a simple error implementation for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}
