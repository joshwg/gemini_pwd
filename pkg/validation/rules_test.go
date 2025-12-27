// Copyright (C) 2025 Joshua Goldstein

package validation

import (
	"strings"
	"testing"
)

func TestValidationError(t *testing.T) {
	err := ValidationError{
		Field:   "username",
		Message: "is required",
	}

	expected := "username: is required"
	if err.Error() != expected {
		t.Errorf("Expected error message %q, got %q", expected, err.Error())
	}
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()

	if v == nil {
		t.Fatal("NewValidator() returned nil")
	}

	if v.HasErrors() {
		t.Error("New validator should not have errors")
	}

	if len(v.Errors()) != 0 {
		t.Errorf("New validator should have 0 errors, got %d", len(v.Errors()))
	}
}

func TestValidatorRequired(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    string
		hasError bool
	}{
		{
			name:     "valid non-empty value",
			field:    "username",
			value:    "testuser",
			hasError: false,
		},
		{
			name:     "empty string",
			field:    "username",
			value:    "",
			hasError: true,
		},
		{
			name:     "whitespace only",
			field:    "username",
			value:    "   ",
			hasError: true,
		},
		{
			name:     "tab and newline",
			field:    "username",
			value:    "\t\n",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewValidator()
			v.Required(tt.field, tt.value)

			if v.HasErrors() != tt.hasError {
				t.Errorf("Expected hasError=%t, got %t", tt.hasError, v.HasErrors())
			}

			if tt.hasError {
				errors := v.Errors()
				if len(errors) != 1 {
					t.Fatalf("Expected 1 error, got %d", len(errors))
				}
				if errors[0].Field != tt.field {
					t.Errorf("Expected field %q, got %q", tt.field, errors[0].Field)
				}
				if errors[0].Message != "is required" {
					t.Errorf("Expected message 'is required', got %q", errors[0].Message)
				}
			}
		})
	}
}

func TestValidatorMinLength(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    string
		min      int
		hasError bool
	}{
		{
			name:     "valid length",
			field:    "password",
			value:    "password123",
			min:      8,
			hasError: false,
		},
		{
			name:     "exactly minimum length",
			field:    "password",
			value:    "12345678",
			min:      8,
			hasError: false,
		},
		{
			name:     "too short",
			field:    "password",
			value:    "123",
			min:      8,
			hasError: true,
		},
		{
			name:     "empty string",
			field:    "password",
			value:    "",
			min:      1,
			hasError: true,
		},
		{
			name:     "whitespace trimmed",
			field:    "password",
			value:    "  abc  ",
			min:      4,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewValidator()
			v.MinLength(tt.field, tt.value, tt.min)

			if v.HasErrors() != tt.hasError {
				t.Errorf("Expected hasError=%t, got %t", tt.hasError, v.HasErrors())
			}

			if tt.hasError {
				errors := v.Errors()
				if len(errors) != 1 {
					t.Fatalf("Expected 1 error, got %d", len(errors))
				}
				if !strings.Contains(errors[0].Message, "must be at least") {
					t.Errorf("Expected message to contain 'must be at least', got %q", errors[0].Message)
				}
			}
		})
	}
}

func TestValidatorMaxLength(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    string
		max      int
		hasError bool
	}{
		{
			name:     "valid length",
			field:    "username",
			value:    "user",
			max:      10,
			hasError: false,
		},
		{
			name:     "exactly maximum length",
			field:    "username",
			value:    "1234567890",
			max:      10,
			hasError: false,
		},
		{
			name:     "too long",
			field:    "username",
			value:    "12345678901",
			max:      10,
			hasError: true,
		},
		{
			name:     "empty string",
			field:    "username",
			value:    "",
			max:      10,
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewValidator()
			v.MaxLength(tt.field, tt.value, tt.max)

			if v.HasErrors() != tt.hasError {
				t.Errorf("Expected hasError=%t, got %t", tt.hasError, v.HasErrors())
			}

			if tt.hasError {
				errors := v.Errors()
				if len(errors) != 1 {
					t.Fatalf("Expected 1 error, got %d", len(errors))
				}
				if !strings.Contains(errors[0].Message, "must be no more than") {
					t.Errorf("Expected message to contain 'must be no more than', got %q", errors[0].Message)
				}
			}
		})
	}
}

func TestValidatorEmail(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		value    string
		hasError bool
	}{
		{
			name:     "valid email",
			field:    "email",
			value:    "test@example.com",
			hasError: false,
		},
		{
			name:     "another valid email",
			field:    "email",
			value:    "user@domain.org",
			hasError: false,
		},
		{
			name:     "empty email (allowed)",
			field:    "email",
			value:    "",
			hasError: false,
		},
		{
			name:     "invalid email - no @",
			field:    "email",
			value:    "invalid.email",
			hasError: true,
		},
		{
			name:     "invalid email - just text",
			field:    "email",
			value:    "notanemail",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewValidator()
			v.Email(tt.field, tt.value)

			if v.HasErrors() != tt.hasError {
				t.Errorf("Expected hasError=%t, got %t", tt.hasError, v.HasErrors())
			}

			if tt.hasError {
				errors := v.Errors()
				if len(errors) != 1 {
					t.Fatalf("Expected 1 error, got %d", len(errors))
				}
				expectedMessage := "must be a valid email address"
				if errors[0].Message != expectedMessage {
					t.Errorf("Expected message %q, got %q", expectedMessage, errors[0].Message)
				}
			}
		})
	}
}

func TestValidatorChaining(t *testing.T) {
	v := NewValidator()

	// Chain multiple validations
	v.Required("username", "").
		MinLength("password", "123", 8).
		MaxLength("notes", strings.Repeat("a", 100), 50)

	if !v.HasErrors() {
		t.Error("Expected errors from chained validations")
	}

	errors := v.Errors()
	if len(errors) != 3 {
		t.Errorf("Expected 3 errors, got %d", len(errors))
	}

	// Verify each error field
	expectedFields := []string{"username", "password", "notes"}
	for i, err := range errors {
		if err.Field != expectedFields[i] {
			t.Errorf("Error %d: expected field %q, got %q", i, expectedFields[i], err.Field)
		}
	}
}

func TestValidatorErrorMessages(t *testing.T) {
	v := NewValidator()
	v.Required("field1", "").
		MinLength("field2", "ab", 5)

	messages := v.ErrorMessages()
	if len(messages) != 2 {
		t.Errorf("Expected 2 error messages, got %d", len(messages))
	}

	// Check that messages are properly formatted
	for _, msg := range messages {
		if !strings.Contains(msg, ":") {
			t.Errorf("Expected error message to contain ':', got %q", msg)
		}
	}
}

func TestValidatorFirstError(t *testing.T) {
	t.Run("with errors", func(t *testing.T) {
		v := NewValidator()
		v.Required("username", "").
			Required("password", "")

		firstError := v.FirstError()
		if firstError == "" {
			t.Error("Expected first error, got empty string")
		}

		expected := "username: is required"
		if firstError != expected {
			t.Errorf("Expected first error %q, got %q", expected, firstError)
		}
	})

	t.Run("without errors", func(t *testing.T) {
		v := NewValidator()
		firstError := v.FirstError()
		if firstError != "" {
			t.Errorf("Expected empty string, got %q", firstError)
		}
	})
}

func TestValidatePasswordEntry(t *testing.T) {
	tests := []struct {
		name      string
		entry     PasswordEntryRequest
		hasError  bool
		numErrors int
	}{
		{
			name: "valid entry",
			entry: PasswordEntryRequest{
				Site:     "example.com",
				Username: "user",
				Password: "password123",
				Notes:    "Some notes",
				Tags:     []string{"work", "important"},
			},
			hasError:  false,
			numErrors: 0,
		},
		{
			name: "missing required fields",
			entry: PasswordEntryRequest{
				Site:     "",
				Username: "",
				Password: "password123",
				Notes:    "Some notes",
			},
			hasError:  true,
			numErrors: 2, // site and username required
		},
		{
			name: "site too long",
			entry: PasswordEntryRequest{
				Site:     strings.Repeat("a", 300),
				Username: "user",
				Password: "password123",
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "username too long",
			entry: PasswordEntryRequest{
				Site:     "example.com",
				Username: strings.Repeat("u", 300),
				Password: "password123",
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "password too long",
			entry: PasswordEntryRequest{
				Site:     "example.com",
				Username: "user",
				Password: strings.Repeat("p", 1100),
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "notes too long",
			entry: PasswordEntryRequest{
				Site:     "example.com",
				Username: "user",
				Password: "password123",
				Notes:    strings.Repeat("n", 2100),
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "empty password allowed",
			entry: PasswordEntryRequest{
				Site:     "example.com",
				Username: "user",
				Password: "",
				Notes:    "Notes",
			},
			hasError:  false,
			numErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := ValidatePasswordEntry(tt.entry)

			if v.HasErrors() != tt.hasError {
				t.Errorf("Expected hasError=%t, got %t", tt.hasError, v.HasErrors())
			}

			if len(v.Errors()) != tt.numErrors {
				t.Errorf("Expected %d errors, got %d", tt.numErrors, len(v.Errors()))
			}
		})
	}
}

func TestValidateUserCreation(t *testing.T) {
	tests := []struct {
		name      string
		user      UserRequest
		hasError  bool
		numErrors int
	}{
		{
			name: "valid user",
			user: UserRequest{
				Username: "testuser",
				Password: "password123",
				IsAdmin:  false,
			},
			hasError:  false,
			numErrors: 0,
		},
		{
			name: "missing username and password",
			user: UserRequest{
				Username: "",
				Password: "",
				IsAdmin:  true,
			},
			hasError:  true,
			numErrors: 4, // username required, username min length, password required, password min length
		},
		{
			name: "username too short",
			user: UserRequest{
				Username: "ab",
				Password: "password123",
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "username too long",
			user: UserRequest{
				Username: strings.Repeat("u", 60),
				Password: "password123",
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "password too short",
			user: UserRequest{
				Username: "testuser",
				Password: "123",
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "password too long",
			user: UserRequest{
				Username: "testuser",
				Password: strings.Repeat("p", 1100),
			},
			hasError:  true,
			numErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := ValidateUserCreation(tt.user)

			if v.HasErrors() != tt.hasError {
				t.Errorf("Expected hasError=%t, got %t", tt.hasError, v.HasErrors())
			}

			if len(v.Errors()) != tt.numErrors {
				t.Errorf("Expected %d errors, got %d", tt.numErrors, len(v.Errors()))
				for i, err := range v.Errors() {
					t.Logf("Error %d: %s", i, err.Error())
				}
			}
		})
	}
}

func TestValidateTag(t *testing.T) {
	tests := []struct {
		name      string
		tag       TagRequest
		hasError  bool
		numErrors int
	}{
		{
			name: "valid tag",
			tag: TagRequest{
				Name:        "work",
				Description: "Work related passwords",
				Color:       "#ff0000",
			},
			hasError:  false,
			numErrors: 0,
		},
		{
			name: "missing name",
			tag: TagRequest{
				Name:        "",
				Description: "Description",
				Color:       "#ff0000",
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "name too long",
			tag: TagRequest{
				Name:        strings.Repeat("n", 150),
				Description: "Description",
				Color:       "#ff0000",
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "description too long",
			tag: TagRequest{
				Name:        "work",
				Description: strings.Repeat("d", 600),
				Color:       "#ff0000",
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "color too long",
			tag: TagRequest{
				Name:        "work",
				Description: "Description",
				Color:       strings.Repeat("c", 30),
			},
			hasError:  true,
			numErrors: 1,
		},
		{
			name: "empty optional fields",
			tag: TagRequest{
				Name:        "work",
				Description: "",
				Color:       "",
			},
			hasError:  false,
			numErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := ValidateTag(tt.tag)

			if v.HasErrors() != tt.hasError {
				t.Errorf("Expected hasError=%t, got %t", tt.hasError, v.HasErrors())
			}

			if len(v.Errors()) != tt.numErrors {
				t.Errorf("Expected %d errors, got %d", tt.numErrors, len(v.Errors()))
				for i, err := range v.Errors() {
					t.Logf("Error %d: %s", i, err.Error())
				}
			}
		})
	}
}
