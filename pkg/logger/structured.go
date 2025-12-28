// Package logger provides structured logging utilities with consistent formatting
// Copyright (C) 2025 Joshua Goldstein

package logger

import (
	"log"
	"strings"
)

// Logger provides structured logging with emojis and consistent formatting
type Logger struct {
	prefix string
}

// NewLogger creates a new logger with an optional prefix
func NewLogger(prefix string) *Logger {
	return &Logger{prefix: prefix}
}

// formatMessage formats a message with prefix if available
func (l *Logger) formatMessage(emoji, msg string) string {
	prefix := ""
	if l.prefix != "" {
		prefix = "[" + l.prefix + "] "
	}

	return emoji + " " + prefix + msg
}

// Info logs an informational message
func (l *Logger) Info(msg string, args ...interface{}) {
	formatted := l.formatMessage("ℹ️", msg)
	if len(args) > 0 {
		log.Printf(formatted, args...)
	} else {
		log.Print(formatted)
	}
}

// Success logs a success message
func (l *Logger) Success(msg string, args ...interface{}) {
	formatted := l.formatMessage("✅", msg)
	if len(args) > 0 {
		log.Printf(formatted, args...)
	} else {
		log.Print(formatted)
	}
}

// Warning logs a warning message
func (l *Logger) Warning(msg string, args ...interface{}) {
	formatted := l.formatMessage("⚠️", msg)
	if len(args) > 0 {
		log.Printf(formatted, args...)
	} else {
		log.Print(formatted)
	}
}

// Error logs an error message with optional error object
func (l *Logger) Error(msg string, err error, args ...interface{}) {
	if err != nil {
		fullMsg := msg + " - %v"
		allArgs := append(args, err)
		formatted := l.formatMessage("❌", fullMsg)
		log.Printf(formatted, allArgs...)
	} else {
		formatted := l.formatMessage("❌", msg)
		if len(args) > 0 {
			log.Printf(formatted, args...)
		} else {
			log.Print(formatted)
		}
	}
}

// Security logs a security-related event
func (l *Logger) Security(event string, details map[string]interface{}) {
	msg := "🔐 SECURITY: " + event
	if l.prefix != "" {
		msg = "[" + l.prefix + "] " + msg
	}

	if len(details) > 0 {
		detailStrs := make([]string, 0, len(details))
		args := make([]interface{}, 0, len(details))
		for key, value := range details {
			detailStrs = append(detailStrs, key+"=%v")
			args = append(args, value)
		}
		msg += " - " + strings.Join(detailStrs, " ")
		log.Printf(msg, args...)
	} else {
		log.Print(msg)
	}
}

// Fatal logs a fatal error and exits
func (l *Logger) Fatal(msg string, err error, args ...interface{}) {
	if err != nil {
		fullMsg := msg + " - %v"
		allArgs := append(args, err)
		formatted := l.formatMessage("💀", fullMsg)
		log.Fatalf(formatted, allArgs...)
	} else {
		formatted := l.formatMessage("💀", msg)
		if len(args) > 0 {
			log.Fatalf(formatted, args...)
		} else {
			log.Fatal(formatted)
		}
	}
}

// Default logger instance
var Default = NewLogger("")

// Convenience functions for default logger
func Info(msg string, args ...interface{})                  { Default.Info(msg, args...) }
func Success(msg string, args ...interface{})               { Default.Success(msg, args...) }
func Warning(msg string, args ...interface{})               { Default.Warning(msg, args...) }
func Error(msg string, err error, args ...interface{})      { Default.Error(msg, err, args...) }
func Security(event string, details map[string]interface{}) { Default.Security(event, details) }
func Fatal(msg string, err error, args ...interface{})      { Default.Fatal(msg, err, args...) }
