// Package auth provides authentication and authorization utilities
// Copyright (C) 2025 Joshua Goldstein

package auth

import (
	"context"
	"net/http"
)

// User represents a user in the system (this should match your main User struct)
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
}

// Define a custom type for context keys to avoid collisions
type contextKey string

const userContextKey contextKey = "user"

// GetCurrentUser extracts the user from the request context
func GetCurrentUser(r *http.Request) (*User, bool) {
	user, ok := r.Context().Value(userContextKey).(*User)
	return user, ok
}

// SetUserContext adds a user to the request context
func SetUserContext(r *http.Request, user *User) *http.Request {
	ctx := context.WithValue(r.Context(), userContextKey, user)
	return r.WithContext(ctx)
}

// RequireAuth is middleware that ensures the user is authenticated
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := GetCurrentUser(r)
		if !ok || user == nil {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// RequireAdmin is middleware that ensures the user is an admin
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := GetCurrentUser(r)
		if !ok || user == nil {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}
		if !user.IsAdmin {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// MustGetCurrentUser panics if user is not in context (for use after auth middleware)
func MustGetCurrentUser(r *http.Request) *User {
	user, ok := GetCurrentUser(r)
	if !ok || user == nil {
		panic("user not found in context - ensure auth middleware is applied")
	}
	return user
}
