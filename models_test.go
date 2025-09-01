// models_test.go
package main

import (
	"encoding/json"
	"testing"
)

// TestUserJSON tests the JSON serialization of the User struct.
func TestUserJSON(t *testing.T) {
	user := User{
		ID:       1,
		Username: "testuser",
		IsAdmin:  true,
	}

	_, err := json.Marshal(user)
	if err != nil {
		t.Errorf("Failed to marshal User struct to JSON: %v", err)
	}
}

// TestPasswordEntryJSON tests the JSON serialization of the PasswordEntry struct.
func TestPasswordEntryJSON(t *testing.T) {
	// Note: The Salt field has `json:"-"`, so it should not be in the output.
	entry := PasswordEntry{
		ID:        1,
		Site:      "example.com",
		Username:  "user",
		Password:  "secret", // This field is for decrypted data, not stored in DB
		Notes:     "notes",
		Tags:      []Tag{{ID: 1, Name: "a", Color: "#ff0000"}, {ID: 2, Name: "b", Color: "#00ff00"}},
		CreatedAt: "2023-01-01",
		Salt:      []byte("salty"),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to marshal PasswordEntry struct to JSON: %v", err)
	}

	// Unmarshal into a map to check for the absence of the salt
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON back to map: %v", err)
	}

	if _, exists := result["Salt"]; exists {
		t.Errorf("The 'Salt' field should not be present in the JSON output")
	}
	if result["site"] != "example.com" {
		t.Errorf("Expected site to be 'example.com', got %v", result["site"])
	}
}

// TestTagJSON tests the JSON serialization of the Tag struct.
func TestTagJSON(t *testing.T) {
	tag := Tag{
		ID:          1,
		Name:        "Work",
		Description: "Work stuff",
		Color:       "#123456",
	}

	_, err := json.Marshal(tag)
	if err != nil {
		t.Errorf("Failed to marshal Tag struct to JSON: %v", err)
	}
}
