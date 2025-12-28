// Copyright (C) 2025 Joshua Goldstein

// utils.go
package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

// Default color for tags created without a color specified
const defaultTagColor = "#6B7280" // dark gray

// =============================================================================
// Priority 1: Tag ID Resolution Functions
// =============================================================================

// GetOrCreateTagID retrieves the tag ID for a given tag name, or creates it if it doesn't exist.
// Returns the tag ID or an error.
func GetOrCreateTagID(tx *sql.Tx, userID int, tagName string) (int64, error) {
	if tagName == "" {
		return 0, fmt.Errorf("tag name cannot be empty")
	}

	var tagID int64
	err := tx.QueryRow("SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE", userID, tagName).Scan(&tagID)

	if err == nil {
		return tagID, nil
	}

	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("failed to query tag: %w", err)
	}

	// Tag doesn't exist, create it with default color
	res, err := tx.Exec("INSERT INTO tags (user_id, name, description, color) VALUES (?, ?, '', ?)", userID, tagName, defaultTagColor)
	if err != nil {
		return 0, fmt.Errorf("failed to create tag: %w", err)
	}

	tagID, err = res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get new tag id: %w", err)
	}

	return tagID, nil
}

// LinkPasswordToTag creates a link between a password entry and a tag.
func LinkPasswordToTag(tx *sql.Tx, entryID, tagID int64) error {
	_, err := tx.Exec("INSERT INTO entry_tags (entry_id, tag_id) VALUES (?, ?)", entryID, tagID)
	if err != nil {
		return fmt.Errorf("failed to link password and tag: %w", err)
	}
	return nil
}

// LinkPasswordToTags links a password entry to multiple tags by name.
// Creates tags if they don't exist. Empty tag names are skipped.
func LinkPasswordToTags(tx *sql.Tx, userID int, entryID int64, tagNames []string) error {
	for _, tagName := range tagNames {
		if tagName == "" {
			continue
		}

		tagID, err := GetOrCreateTagID(tx, userID, tagName)
		if err != nil {
			return err
		}

		if err := LinkPasswordToTag(tx, entryID, tagID); err != nil {
			return err
		}
	}
	return nil
}

// =============================================================================
// Priority 2: Tag Parsing Functions
// =============================================================================

// ParseTagsFromGroupConcat parses concatenated tag data from SQL GROUP_CONCAT
// into a slice of Tag structs. Returns empty slice if any of the inputs are invalid.
func ParseTagsFromGroupConcat(tagIDs, tagNames, tagColors sql.NullString) []Tag {
	if !tagNames.Valid || !tagIDs.Valid || !tagColors.Valid {
		return []Tag{}
	}

	tagIDStrings := strings.Split(tagIDs.String, ",")
	tagNameStrings := strings.Split(tagNames.String, ",")
	tagColorStrings := strings.Split(tagColors.String, ",")

	tags := make([]Tag, 0, len(tagNameStrings))
	for i, name := range tagNameStrings {
		if i < len(tagIDStrings) && i < len(tagColorStrings) {
			if id, err := strconv.Atoi(tagIDStrings[i]); err == nil {
				tags = append(tags, Tag{
					ID:    id,
					Name:  name,
					Color: tagColorStrings[i],
				})
			}
		}
	}

	return tags
}

// =============================================================================
// Priority 3: Case-Insensitive Query Helpers
// =============================================================================

// RecordExists checks if at least one record exists matching the query.
// Returns true if count > 0, false otherwise.
func RecordExists(query string, args ...interface{}) (bool, error) {
	var count int
	err := db.QueryRow(query, args...).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CheckDuplicateTag checks if a tag with the given name already exists for the user.
// If excludeID is provided and > 0, that tag ID will be excluded from the check
// (useful when updating an existing tag).
func CheckDuplicateTag(userID int, tagName string, excludeID ...int) (bool, error) {
	query := "SELECT COUNT(*) FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE"
	args := []interface{}{userID, tagName}

	if len(excludeID) > 0 && excludeID[0] > 0 {
		query += " AND id != ?"
		args = append(args, excludeID[0])
	}

	return RecordExists(query, args...)
}

// CheckDuplicatePasswordEntry checks if a password entry with the same site and username
// already exists for the user. If excludeID is provided and > 0, that entry ID will be
// excluded from the check (useful when updating an existing entry).
func CheckDuplicatePasswordEntry(userID int, site, username string, excludeID ...int) (bool, error) {
	query := "SELECT COUNT(*) FROM password_entries WHERE user_id = ? AND site = ? AND username = ? COLLATE NOCASE"
	args := []interface{}{userID, site, username}

	if len(excludeID) > 0 && excludeID[0] > 0 {
		query += " AND id != ?"
		args = append(args, excludeID[0])
	}

	return RecordExists(query, args...)
}

// CheckUsernameExists checks if a username already exists in the system.
// If excludeID is provided and > 0, that user ID will be excluded from the check
// (useful when updating an existing user).
func CheckUsernameExists(username string, excludeID ...int) (bool, error) {
	query := "SELECT COUNT(*) FROM users WHERE username = ? COLLATE NOCASE"
	args := []interface{}{username}

	if len(excludeID) > 0 && excludeID[0] > 0 {
		query += " AND id != ?"
		args = append(args, excludeID[0])
	}

	return RecordExists(query, args...)
}

// =============================================================================
// Priority 4: Encryption and Salt Generation
// =============================================================================

// GenerateSalt generates a cryptographically secure random 16-byte salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// EncryptedPasswordData contains encrypted password entry data.
type EncryptedPasswordData struct {
	EncryptedPassword []byte
	EncryptedNotes    []byte
	Salt              []byte
}

// EncryptPasswordData encrypts password and notes fields with a newly generated salt.
// Returns the encrypted data or an error.
func EncryptPasswordData(password, notes string) (*EncryptedPasswordData, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	encryptedPassword, err := encrypt([]byte(password), salt)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt password: %w", err)
	}

	encryptedNotes, err := encrypt([]byte(notes), salt)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt notes: %w", err)
	}

	return &EncryptedPasswordData{
		EncryptedPassword: encryptedPassword,
		EncryptedNotes:    encryptedNotes,
		Salt:              salt,
	}, nil
}
