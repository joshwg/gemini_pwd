// models.go
package main

// User represents a user in the system.
type User struct {
	ID       int
	Username string
	IsAdmin  bool
}

// PasswordEntry represents a password entry in the system.
type PasswordEntry struct {
	ID        int      `json:"id"`
	Site      string   `json:"site"`
	Username  string   `json:"username"`
	Password  string   `json:"password,omitempty"` // omitempty to not send password back to frontend by default
	Notes     string   `json:"notes,omitempty"`
	Tags      []string `json:"tags"`
	CreatedAt string   `json:"createdAt"`
}

// Tag represents a tag in the system.
type Tag struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
}
