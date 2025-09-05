// Package validation provides input validation utilities
package validation

import (
	"fmt"
	"strings"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Validator provides validation methods
type Validator struct {
	errors []ValidationError
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		errors: make([]ValidationError, 0),
	}
}

// Required validates that a field is not empty
func (v *Validator) Required(field, value string) *Validator {
	if strings.TrimSpace(value) == "" {
		v.errors = append(v.errors, ValidationError{
			Field:   field,
			Message: "is required",
		})
	}
	return v
}

// MinLength validates minimum string length
func (v *Validator) MinLength(field, value string, min int) *Validator {
	if len(strings.TrimSpace(value)) < min {
		v.errors = append(v.errors, ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be at least %d characters", min),
		})
	}
	return v
}

// MaxLength validates maximum string length
func (v *Validator) MaxLength(field, value string, max int) *Validator {
	if len(value) > max {
		v.errors = append(v.errors, ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be no more than %d characters", max),
		})
	}
	return v
}

// Email validates email format (basic validation)
func (v *Validator) Email(field, value string) *Validator {
	if value != "" && !strings.Contains(value, "@") {
		v.errors = append(v.errors, ValidationError{
			Field:   field,
			Message: "must be a valid email address",
		})
	}
	return v
}

// HasErrors returns true if there are validation errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// Errors returns all validation errors
func (v *Validator) Errors() []ValidationError {
	return v.errors
}

// ErrorMessages returns error messages as strings
func (v *Validator) ErrorMessages() []string {
	messages := make([]string, len(v.errors))
	for i, err := range v.errors {
		messages[i] = err.Error()
	}
	return messages
}

// FirstError returns the first error message or empty string if no errors
func (v *Validator) FirstError() string {
	if len(v.errors) > 0 {
		return v.errors[0].Error()
	}
	return ""
}

// PasswordEntryRequest represents a password entry for validation
type PasswordEntryRequest struct {
	Site     string   `json:"site"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Notes    string   `json:"notes"`
	Tags     []string `json:"tags"`
}

// ValidatePasswordEntry validates a password entry request
func ValidatePasswordEntry(entry PasswordEntryRequest) *Validator {
	v := NewValidator()

	v.Required("site", entry.Site).
		MaxLength("site", entry.Site, 255)

	v.Required("username", entry.Username).
		MaxLength("username", entry.Username, 255)

	// Password is optional for updates, but if provided should have min length
	if entry.Password != "" {
		v.MinLength("password", entry.Password, 1).
			MaxLength("password", entry.Password, 1000)
	}

	v.MaxLength("notes", entry.Notes, 2000)

	return v
}

// UserRequest represents a user for validation
type UserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

// ValidateUserCreation validates a user creation request
func ValidateUserCreation(user UserRequest) *Validator {
	v := NewValidator()

	v.Required("username", user.Username).
		MinLength("username", user.Username, 3).
		MaxLength("username", user.Username, 50)

	v.Required("password", user.Password).
		MinLength("password", user.Password, 8).
		MaxLength("password", user.Password, 1000)

	return v
}

// TagRequest represents a tag for validation
type TagRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
}

// ValidateTag validates a tag request
func ValidateTag(tag TagRequest) *Validator {
	v := NewValidator()

	v.Required("name", tag.Name).
		MaxLength("name", tag.Name, 100)

	v.MaxLength("description", tag.Description, 500)
	v.MaxLength("color", tag.Color, 20)

	return v
}
