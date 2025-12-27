// Copyright (C) 2025 Joshua Goldstein

// Package api provides common API request and response types
package api

// User-related request types
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"isAdmin"`
}

type UpdateUserRequest struct {
	Username    string `json:"username"`
	NewUsername string `json:"newUsername"`
	IsAdmin     *bool  `json:"isAdmin"`
	NewPassword string `json:"newPassword"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// Password-related request types
type CreatePasswordRequest struct {
	Site     string   `json:"site"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Notes    string   `json:"notes"`
	Tags     []string `json:"tags"`
}

type UpdatePasswordRequest struct {
	ID       int      `json:"id"`
	Site     string   `json:"site"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Notes    string   `json:"notes"`
	Tags     []string `json:"tags"`
}

type CheckDuplicateRequest struct {
	Site     string `json:"site"`
	Username string `json:"username"`
	ID       int    `json:"id,omitempty"` // For edit mode, exclude this entry from duplicate check
}

// Tag-related request types
type CreateTagRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
}

type UpdateTagRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
}

// Filter request types
type PasswordFilterRequest struct {
	Query  string `json:"query"`  // Text search for site/username
	TagIDs []int  `json:"tagIds"` // Specific tag IDs to filter by
	Limit  int    `json:"limit"`  // Maximum number of results (default 100)
	Offset int    `json:"offset"` // Pagination offset (default 0)
}

// Common response types
type RateLimitResponse struct {
	IsLimited     bool `json:"isLimited"`
	RemainingTime int  `json:"remainingTime"`
}

type DuplicateCheckResponse struct {
	IsDuplicate bool `json:"isDuplicate"`
}

type SuccessResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}
