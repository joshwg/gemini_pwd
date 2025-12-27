// Copyright (C) 2025 Joshua Goldstein

// user.go
package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Default color for tags imported without a color
const defaultTagColor = "#6B7280" // dark gray

// updateEmptyTagColors updates all tags with empty colors to use the default color
func updateEmptyTagColors() error {
	_, err := db.Exec("UPDATE tags SET color = ? WHERE color = '' OR color IS NULL", defaultTagColor)
	if err != nil {
		return fmt.Errorf("failed to update empty tag colors: %w", err)
	}
	return nil
}

// The User, PasswordEntry, and Tag structs are assumed to be in models.go
// as per our previous conversation.

// authenticateUser checks username and password, returns User object on success.
func authenticateUser(username, password string) (*User, error) {
	var id int
	var hash string
	var isAdmin bool
	// Use COLLATE NOCASE for case-insensitive username check
	err := db.QueryRow("SELECT id, password_hash, is_admin FROM users WHERE username = ? COLLATE NOCASE", username).Scan(&id, &hash, &isAdmin)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	return &User{ID: id, Username: username, IsAdmin: isAdmin}, nil
}

// createUser creates a new user. It can be called by an admin or,
// with skipAdminCheck, for initial setup.
func createUser(admin *User, newUsername, newPassword string, makeAdmin, skipAdminCheck bool) error {
	if !skipAdminCheck && (admin == nil || !admin.IsAdmin) {
		return fmt.Errorf("permission denied: only administrators can create users")
	}

	// Check for existing user case-insensitively
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? COLLATE NOCASE", newUsername).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for existing user: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("username already exists")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	_, err = db.Exec("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", newUsername, string(hash), makeAdmin)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// deleteUser (Admin only)
func deleteUser(admin *User, usernameToDelete string) error {
	if admin == nil || !admin.IsAdmin {
		return fmt.Errorf("permission denied: only administrators can delete users")
	}
	if strings.EqualFold(admin.Username, usernameToDelete) {
		return fmt.Errorf("cannot delete yourself")
	}
	res, err := db.Exec("DELETE FROM users WHERE username = ? COLLATE NOCASE", usernameToDelete)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user '%s' not found", usernameToDelete)
	}
	return nil
}

// renameUser (Admin only)
func renameUser(admin *User, userID int, oldUsername, newUsername string) error {
	if admin == nil || !admin.IsAdmin {
		return fmt.Errorf("permission denied: only administrators can rename users")
	}

	// Check for new username case-insensitively, excluding the current user by ID.
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? COLLATE NOCASE AND id != ?", newUsername, userID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for existing new username: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("new username already exists")
	}

	_, err = db.Exec("UPDATE users SET username = ? WHERE id = ?", newUsername, userID)
	if err != nil {
		return fmt.Errorf("failed to rename user: %w", err)
	}
	return nil
}

// changeAdminStatus (Admin only)
func changeAdminStatus(admin *User, targetUsername string, newStatus bool) error {
	if admin == nil || !admin.IsAdmin {
		return fmt.Errorf("permission denied: only administrators can change admin status")
	}
	if strings.EqualFold(admin.Username, targetUsername) {
		return fmt.Errorf("cannot change your own admin status")
	}
	_, err := db.Exec("UPDATE users SET is_admin = ? WHERE username = ? COLLATE NOCASE", newStatus, targetUsername)
	if err != nil {
		return fmt.Errorf("failed to update admin status: %w", err)
	}
	return nil
}

// changePassword
func changePassword(currentUser *User, targetUsername, currentPassword, newPassword string) error {
	var targetUserID int
	var targetUserHash string
	// Use COLLATE NOCASE for case-insensitive username check
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ? COLLATE NOCASE", targetUsername).Scan(&targetUserID, &targetUserHash)
	if err != nil {
		return fmt.Errorf("target user '%s' not found", targetUsername)
	}

	// Admin can change anyone's password without the current one
	if currentUser.IsAdmin {
		if strings.EqualFold(currentUser.Username, targetUsername) && currentPassword == "" {
			return fmt.Errorf("current password is required to change your own password")
		}
		if currentPassword != "" {
			if err := bcrypt.CompareHashAndPassword([]byte(targetUserHash), []byte(currentPassword)); err != nil {
				return fmt.Errorf("incorrect current password")
			}
		}
	} else {
		// Non-admin can only change their own password
		if currentUser.ID != targetUserID {
			return fmt.Errorf("permission denied: you can only change your own password")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(targetUserHash), []byte(currentPassword)); err != nil {
			return fmt.Errorf("incorrect current password")
		}
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	_, err = db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(newHash), targetUserID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// getUserByID retrieves a user by their ID.
func getUserByID(id int) (*User, error) {
	var u User
	err := db.QueryRow("SELECT id, username, is_admin FROM users WHERE id = ?", id).Scan(&u.ID, &u.Username, &u.IsAdmin)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// getAllUsers retrieves a list of all users from the database.
func getAllUsers() ([]User, error) {
	rows, err := db.Query("SELECT id, username, is_admin FROM users ORDER BY username ASC")
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.IsAdmin); err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}
		users = append(users, user)
	}
	return users, nil
}

// getTags retrieves a list of all tags for a user.
func getTags(userID int) ([]Tag, error) {
	rows, err := db.Query("SELECT id, name, description, color FROM tags WHERE user_id = ? ORDER BY name COLLATE NOCASE ASC", userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query tags: %w", err)
	}
	defer rows.Close()

	var tags []Tag
	for rows.Next() {
		var tag Tag
		if err := rows.Scan(&tag.ID, &tag.Name, &tag.Description, &tag.Color); err != nil {
			return nil, fmt.Errorf("failed to scan tag row: %w", err)
		}
		tags = append(tags, tag)
	}

	if tags == nil {
		return []Tag{}, nil
	}

	return tags, nil
}

// getTagByID retrieves a single tag for a user.
func getTagByID(userID int, tagID int) (*Tag, error) {
	var tag Tag
	err := db.QueryRow("SELECT id, name, description, color FROM tags WHERE id = ? AND user_id = ?", tagID, userID).Scan(&tag.ID, &tag.Name, &tag.Description, &tag.Color)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("tag not found or permission denied")
		}
		return nil, fmt.Errorf("failed to query tag: %w", err)
	}
	return &tag, nil
}

// createTag creates a new tag for a user.
func createTag(userID int, name, description, color string) error {
	// Check for existing tag case-insensitively
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE", userID, name).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for existing tag: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("tag '%s' already exists", name)
	}

	_, err = db.Exec("INSERT INTO tags (user_id, name, description, color) VALUES (?, ?, ?, ?)", userID, name, description, color)
	if err != nil {
		return fmt.Errorf("failed to create tag: %w", err)
	}
	return nil
}

// createOrUpdateTag creates a new tag or updates an existing one (for imports)
func createOrUpdateTag(userID int, name, description, color string) error {
	// Check if tag exists
	var existingID int
	err := db.QueryRow("SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE", userID, name).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check for existing tag: %w", err)
	}

	if err == sql.ErrNoRows {
		// Tag doesn't exist, create it
		_, err = db.Exec("INSERT INTO tags (user_id, name, description, color) VALUES (?, ?, ?, ?)", userID, name, description, color)
		if err != nil {
			return fmt.Errorf("failed to create tag: %w", err)
		}
	} else {
		// Tag exists, update it
		_, err = db.Exec("UPDATE tags SET description = ?, color = ? WHERE id = ?", description, color, existingID)
		if err != nil {
			return fmt.Errorf("failed to update tag: %w", err)
		}
	}
	return nil
}

// updateTag updates an existing tag's name, description, and color.
func updateTag(userID int, tagID int, newName, newDescription, newColor string) error {
	// Check for existing tag case-insensitively, excluding the current tag.
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE AND id != ?", userID, newName, tagID).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for existing tag: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("tag '%s' already exists", newName)
	}

	result, err := db.Exec("UPDATE tags SET name = ?, description = ?, color = ? WHERE id = ? AND user_id = ?", newName, newDescription, newColor, tagID, userID)
	if err != nil {
		return fmt.Errorf("failed to update tag: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check update result: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("tag not found or you don't have permission to update it")
	}

	return nil
}

// deleteTag deletes an existing tag.
func deleteTag(userID int, tagID int) error {
	res, err := db.Exec("DELETE FROM tags WHERE id = ? AND user_id = ?", tagID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete tag: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("tag not found or you don't have permission to delete it")
	}
	return nil
}

// getPasswords retrieves a list of passwords for a user with filtering support.
// Returns only metadata (no sensitive data) for client-side display.
func getPasswords(userID int, query string) ([]PasswordEntry, error) {
	// Convert legacy string query to new filter format for backward compatibility
	filter := PasswordFilter{
		Query:  query,
		TagIDs: []int{},
		Limit:  100,
		Offset: 0,
	}
	return getPasswordsWithFilter(userID, filter)
}

// PasswordFilter represents filtering options for password queries
type PasswordFilter struct {
	Query  string // Text search for site/username/tags
	TagIDs []int  // Specific tag IDs to filter by
	Limit  int    // Maximum number of results
	Offset int    // Pagination offset
}

// getPasswordsWithFilter retrieves passwords with advanced filtering support
func getPasswordsWithFilter(userID int, filter PasswordFilter) ([]PasswordEntry, error) {
	var args []interface{}
	var conditions []string

	// Base query - always filter by user
	sqlQuery := `
		SELECT
			pe.id, pe.site, pe.username, pe.created_at, pe.modified_at,
			GROUP_CONCAT(t.id) as tagIDs,
			GROUP_CONCAT(t.name) as tagNames, 
			GROUP_CONCAT(t.color) as tagColors
		FROM
			password_entries pe
		LEFT JOIN
			entry_tags et ON pe.id = et.entry_id
		LEFT JOIN
			tags t ON et.tag_id = t.id
		WHERE
			pe.user_id = ?
	`
	args = append(args, userID)

	// Add text search condition
	if filter.Query != "" {
		conditions = append(conditions, `(
			pe.site LIKE ? COLLATE NOCASE
			OR pe.username LIKE ? COLLATE NOCASE
			OR t.name LIKE ? COLLATE NOCASE
		)`)
		searchQuery := "%" + filter.Query + "%"
		args = append(args, searchQuery, searchQuery, searchQuery)
	}

	// Add tag filter conditions
	if len(filter.TagIDs) > 0 {
		// For tag filtering, we need to ensure ALL specified tags are present
		tagPlaceholders := make([]string, len(filter.TagIDs))
		for i, tagID := range filter.TagIDs {
			tagPlaceholders[i] = "?"
			args = append(args, tagID)
		}

		// Use HAVING with COUNT to ensure all tags are matched
		conditions = append(conditions, fmt.Sprintf(`pe.id IN (
			SELECT et2.entry_id 
			FROM entry_tags et2 
			WHERE et2.tag_id IN (%s)
			GROUP BY et2.entry_id 
			HAVING COUNT(DISTINCT et2.tag_id) = %d
		)`, strings.Join(tagPlaceholders, ","), len(filter.TagIDs)))
	}

	// Apply conditions
	if len(conditions) > 0 {
		sqlQuery += " AND " + strings.Join(conditions, " AND ")
	}

	// Group by and order
	sqlQuery += `
		GROUP BY
			pe.id
		ORDER BY
			pe.site ASC
	`

	// Add pagination
	if filter.Limit <= 0 {
		filter.Limit = 100 // Default limit
	}
	sqlQuery += " LIMIT ?"
	args = append(args, filter.Limit)

	if filter.Offset > 0 {
		sqlQuery += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := db.Query(sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query passwords: %w", err)
	}
	defer rows.Close()

	var passwords []PasswordEntry
	for rows.Next() {
		var p PasswordEntry
		var tagIDs, tagNames, tagColors sql.NullString
		// Only scan non-sensitive data for client display
		if err := rows.Scan(&p.ID, &p.Site, &p.Username, &p.CreatedAt, &p.ModifiedAt, &tagIDs, &tagNames, &tagColors); err != nil {
			return nil, fmt.Errorf("failed to scan password row: %w", err)
		}

		// Parse tags into proper Tag objects
		if tagNames.Valid && tagIDs.Valid && tagColors.Valid {
			tagIDStrings := strings.Split(tagIDs.String, ",")
			tagNameStrings := strings.Split(tagNames.String, ",")
			tagColorStrings := strings.Split(tagColors.String, ",")

			p.Tags = make([]Tag, 0, len(tagNameStrings))
			for i, name := range tagNameStrings {
				if i < len(tagIDStrings) && i < len(tagColorStrings) {
					if id, err := strconv.Atoi(tagIDStrings[i]); err == nil {
						p.Tags = append(p.Tags, Tag{
							ID:    id,
							Name:  name,
							Color: tagColorStrings[i],
						})
					}
				}
			}
		} else {
			p.Tags = []Tag{}
		}

		// Set empty strings for sensitive data - they should not be sent to client
		p.Password = ""
		p.Notes = ""

		passwords = append(passwords, p)
	}

	if passwords == nil {
		return []PasswordEntry{}, nil
	}

	return passwords, nil
}

// getPasswordByIDDecrypted retrieves and decrypts a single password by ID
func getPasswordByIDDecrypted(id int, globalKey []byte) (*PasswordEntry, error) {
	var p PasswordEntry
	var passwordEncrypted, notesEncrypted, salt []byte

	query := `SELECT id, site, username, password_encrypted, notes_encrypted, salt, created_at, tags FROM passwords WHERE id = ?`
	err := db.QueryRow(query, id).Scan(&p.ID, &p.Site, &p.Username, &passwordEncrypted, &notesEncrypted, &salt, &p.CreatedAt, &p.Tags)
	if err != nil {
		return nil, err
	}

	// Decrypt password
	if len(passwordEncrypted) > 0 {
		decryptedPassword, err := decrypt(passwordEncrypted, salt)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt password: %w", err)
		}
		p.Password = string(decryptedPassword)
	}

	// Decrypt notes
	if len(notesEncrypted) > 0 {
		decryptedNotes, err := decrypt(notesEncrypted, salt)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt notes: %w", err)
		}
		p.Notes = string(decryptedNotes)
	}

	return &p, nil
}

// getDecryptedPassword retrieves and decrypts only the password field for a specific user and password ID
func getDecryptedPassword(userID, passwordID int) (string, error) {
	var passwordEncrypted, salt []byte

	err := db.QueryRow(`
		SELECT password_encrypted, salt 
		FROM password_entries 
		WHERE id = ? AND user_id = ?`,
		passwordID, userID).Scan(&passwordEncrypted, &salt)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("password not found or access denied")
		}
		return "", fmt.Errorf("failed to query password: %w", err)
	}

	if len(passwordEncrypted) > 0 {
		decryptedPassword, err := decrypt(passwordEncrypted, salt)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt password: %w", err)
		}
		return string(decryptedPassword), nil
	}

	return "", nil
}

// getDecryptedNotes retrieves and decrypts only the notes field for a specific user and password ID
func getDecryptedNotes(userID, passwordID int) (string, error) {
	var notesEncrypted, salt []byte

	err := db.QueryRow(`
		SELECT notes_encrypted, salt 
		FROM password_entries 
		WHERE id = ? AND user_id = ?`,
		passwordID, userID).Scan(&notesEncrypted, &salt)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("password not found or access denied")
		}
		return "", fmt.Errorf("failed to query notes: %w", err)
	}

	if len(notesEncrypted) > 0 {
		decryptedNotes, err := decrypt(notesEncrypted, salt)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt notes: %w", err)
		}
		return string(decryptedNotes), nil
	}

	return "", nil
}

// createPasswordEntry creates a new password entry.
func createPasswordEntry(userID int, site, username, password, notes string, tagNames []string) error {
	// Check for existing password entry (unique by site and username)
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM password_entries WHERE user_id = ? AND site = ? AND username = ? COLLATE NOCASE", userID, site, username).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check for existing password entry: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("password entry for site '%s' and username '%s' already exists", site, username)
	}

	// Generate a unique salt for this entry
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// First, encrypt the sensitive data using the new salt
	encryptedPassword, err := encrypt([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}

	encryptedNotes, err := encrypt([]byte(notes), salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt notes: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO password_entries (user_id, site, username, password_encrypted, notes_encrypted, salt, created_at, modified_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", userID, site, username, encryptedPassword, encryptedNotes, salt)
	if err != nil {
		return fmt.Errorf("failed to insert password entry: %w", err)
	}

	lastID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	// Add tags to the new password entry
	for _, tagName := range tagNames {
		if tagName == "" {
			continue // Skip empty tag names
		}

		var tagID int64
		err := tx.QueryRow("SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE", userID, tagName).Scan(&tagID)
		if err != nil {
			if err == sql.ErrNoRows {
				// Create the tag if it doesn't exist with default color
				res, err := tx.Exec("INSERT INTO tags (user_id, name, description, color) VALUES (?, ?, '', ?)", userID, tagName, defaultTagColor)
				if err != nil {
					return fmt.Errorf("failed to create tag: %w", err)
				}
				tagID, err = res.LastInsertId()
				if err != nil {
					return fmt.Errorf("failed to get new tag id: %w", err)
				}
			} else {
				return fmt.Errorf("failed to query tag: %w", err)
			}
		}

		// Link the password and tag
		_, err = tx.Exec("INSERT INTO entry_tags (entry_id, tag_id) VALUES (?, ?)", lastID, tagID)
		if err != nil {
			return fmt.Errorf("failed to link password and tag: %w", err)
		}
	}

	return tx.Commit()
}

// createOrUpdatePasswordEntry creates a new password entry or updates an existing one (for imports)
func createOrUpdatePasswordEntry(userID int, site, username, password, notes string, tagNames []string) error {
	// Check if password entry exists (unique by site and username)
	var existingID int
	err := db.QueryRow("SELECT id FROM password_entries WHERE user_id = ? AND site = ? AND username = ? COLLATE NOCASE", userID, site, username).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check for existing password entry: %w", err)
	}

	if err == sql.ErrNoRows {
		// Entry doesn't exist, create it
		return createPasswordEntryWithTags(userID, site, username, password, notes, tagNames)
	} else {
		// Entry exists, update it
		return updatePasswordEntry(userID, existingID, site, username, password, notes, tagNames)
	}
}

// createPasswordEntryWithTags creates a password entry and handles tag creation
func createPasswordEntryWithTags(userID int, site, username, password, notes string, tagNames []string) error {
	// Generate a unique salt for this entry
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// First, encrypt the sensitive data using the new salt
	encryptedPassword, err := encrypt([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}

	encryptedNotes, err := encrypt([]byte(notes), salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt notes: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO password_entries (user_id, site, username, password_encrypted, notes_encrypted, salt, created_at, modified_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", userID, site, username, encryptedPassword, encryptedNotes, salt)
	if err != nil {
		return fmt.Errorf("failed to insert password entry: %w", err)
	}

	lastID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	// Add tags to the new password entry
	for _, tagName := range tagNames {
		if tagName == "" {
			continue // Skip empty tag names
		}

		var tagID int64
		err := tx.QueryRow("SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE", userID, tagName).Scan(&tagID)
		if err != nil {
			if err == sql.ErrNoRows {
				// Create the tag if it doesn't exist with default color
				res, err := tx.Exec("INSERT INTO tags (user_id, name, description, color) VALUES (?, ?, '', ?)", userID, tagName, defaultTagColor)
				if err != nil {
					return fmt.Errorf("failed to create tag: %w", err)
				}
				tagID, err = res.LastInsertId()
				if err != nil {
					return fmt.Errorf("failed to get new tag id: %w", err)
				}
			} else {
				return fmt.Errorf("failed to query tag: %w", err)
			}
		}

		// Link the password and tag
		_, err = tx.Exec("INSERT INTO entry_tags (entry_id, tag_id) VALUES (?, ?)", lastID, tagID)
		if err != nil {
			return fmt.Errorf("failed to link password and tag: %w", err)
		}
	}

	return tx.Commit()
}

// updatePasswordEntry updates an existing password entry.
func updatePasswordEntry(userID, id int, site, username, password, notes string, tagNames []string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get the salt for the existing entry
	var salt []byte
	err = tx.QueryRow("SELECT salt FROM password_entries WHERE id = ? AND user_id = ?", id, userID).Scan(&salt)
	if err != nil {
		return fmt.Errorf("failed to retrieve salt for password entry: %w", err)
	}

	// Update the password entry
	// If password is empty, only update non-password fields (keep existing password)
	encryptedNotes, err := encrypt([]byte(notes), salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt notes: %w", err)
	}

	if password != "" {
		// Update with new password
		encryptedPassword, err := encrypt([]byte(password), salt)
		if err != nil {
			return fmt.Errorf("failed to encrypt password: %w", err)
		}
		_, err = tx.Exec("UPDATE password_entries SET site = ?, username = ?, password_encrypted = ?, notes_encrypted = ?, modified_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?", site, username, encryptedPassword, encryptedNotes, id, userID)
		if err != nil {
			return fmt.Errorf("failed to update password entry: %w", err)
		}
	} else {
		// Update without changing password (keep existing password)
		_, err = tx.Exec("UPDATE password_entries SET site = ?, username = ?, notes_encrypted = ?, modified_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?", site, username, encryptedNotes, id, userID)
		if err != nil {
			return fmt.Errorf("failed to update password entry: %w", err)
		}
	}

	// Clear existing tags for the password entry
	_, err = tx.Exec("DELETE FROM entry_tags WHERE entry_id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to clear existing tags: %w", err)
	}

	// Add new tags
	for _, tagName := range tagNames {
		var tagID int64
		err := tx.QueryRow("SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE", userID, tagName).Scan(&tagID)
		if err != nil {
			if err == sql.ErrNoRows {
				// Create the tag if it doesn't exist with default color
				res, err := tx.Exec("INSERT INTO tags (user_id, name, description, color) VALUES (?, ?, '', ?)", userID, tagName, defaultTagColor)
				if err != nil {
					return fmt.Errorf("failed to create tag: %w", err)
				}
				tagID, err = res.LastInsertId()
				if err != nil {
					return fmt.Errorf("failed to get new tag id: %w", err)
				}
			} else {
				return fmt.Errorf("failed to query tag: %w", err)
			}
		}

		// Link the password and tag
		_, err = tx.Exec("INSERT INTO entry_tags (entry_id, tag_id) VALUES (?, ?)", id, tagID)
		if err != nil {
			return fmt.Errorf("failed to link password and tag: %w", err)
		}
	}

	return tx.Commit()
}

// deletePasswordEntry deletes an existing password entry.
func deletePasswordEntry(userID, id int) error {
	res, err := db.Exec("DELETE FROM password_entries WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		return fmt.Errorf("failed to delete password entry: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("password entry not found or you don't have permission to delete it")
	}
	return nil
}

// getAllDecryptedPasswords retrieves all password entries for a user and decrypts them for export.
func getAllDecryptedPasswords(userID int) ([]PasswordEntry, error) {
	sqlQuery := `
		SELECT
			pe.id, pe.site, pe.username, pe.password_encrypted, pe.notes_encrypted, pe.salt, pe.created_at, 
			(SELECT GROUP_CONCAT(t.name) FROM tags t JOIN entry_tags et ON t.id = et.tag_id WHERE et.entry_id = pe.id) as tagNames
		FROM
			password_entries pe
		WHERE
			pe.user_id = ?
		ORDER BY
			pe.site ASC
	`
	rows, err := db.Query(sqlQuery, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query passwords for export: %w", err)
	}
	defer rows.Close()

	var passwords []PasswordEntry
	for rows.Next() {
		var p PasswordEntry
		var tagNames sql.NullString
		var encryptedPassword, encryptedNotes, salt []byte
		if err := rows.Scan(&p.ID, &p.Site, &p.Username, &encryptedPassword, &encryptedNotes, &salt, &p.CreatedAt, &tagNames); err != nil {
			return nil, fmt.Errorf("failed to scan password row for export: %w", err)
		}

		decryptedPassword, err := decrypt(encryptedPassword, salt)
		if err != nil {
			// Log error but don't fail the whole export
			fmt.Printf("could not decrypt password for entry %d: %v\n", p.ID, err)
			p.Password = "[DECRYPTION FAILED]"
		} else {
			p.Password = string(decryptedPassword)
		}

		decryptedNotes, err := decrypt(encryptedNotes, salt)
		if err != nil {
			fmt.Printf("could not decrypt notes for entry %d: %v\n", p.ID, err)
			p.Notes = "[DECRYPTION FAILED]"
		} else {
			p.Notes = string(decryptedNotes)
		}

		if tagNames.Valid {
			// For export, we return tag names as a slice of strings
			tagNameStrings := strings.Split(tagNames.String, ",")
			p.Tags = make([]Tag, 0, len(tagNameStrings))
			for _, name := range tagNameStrings {
				p.Tags = append(p.Tags, Tag{Name: name})
			}
		} else {
			p.Tags = []Tag{}
		}

		passwords = append(passwords, p)
	}

	if passwords == nil {
		return []PasswordEntry{}, nil
	}

	return passwords, nil
}

// getPasswordByID retrieves a password by its ID and decrypts it.
func getPasswordByID(userID, id int) (*PasswordEntry, error) {
	var p PasswordEntry
	var encryptedPassword, encryptedNotes, salt []byte
	var tagIDs, tagNames, tagColors sql.NullString

	sqlQuery := `
		SELECT
			pe.id, pe.site, pe.username, pe.password_encrypted, pe.notes_encrypted, pe.salt, pe.created_at, pe.modified_at,
			GROUP_CONCAT(t.id) as tagIDs,
			GROUP_CONCAT(t.name) as tagNames, 
			GROUP_CONCAT(t.color) as tagColors
		FROM
			password_entries pe
		LEFT JOIN
			entry_tags et ON pe.id = et.entry_id
		LEFT JOIN
			tags t ON et.tag_id = t.id
		WHERE
			pe.user_id = ? AND pe.id = ?
		GROUP BY
			pe.id
	`
	err := db.QueryRow(sqlQuery, userID, id).Scan(&p.ID, &p.Site, &p.Username, &encryptedPassword, &encryptedNotes, &salt, &p.CreatedAt, &p.ModifiedAt, &tagIDs, &tagNames, &tagColors)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve password: %w", err)
	}

	// Parse tags into proper Tag objects
	if tagNames.Valid && tagIDs.Valid && tagColors.Valid {
		tagIDStrings := strings.Split(tagIDs.String, ",")
		tagNameStrings := strings.Split(tagNames.String, ",")
		tagColorStrings := strings.Split(tagColors.String, ",")

		p.Tags = make([]Tag, 0, len(tagNameStrings))
		for i, name := range tagNameStrings {
			if i < len(tagIDStrings) && i < len(tagColorStrings) {
				if tagID, err := strconv.Atoi(tagIDStrings[i]); err == nil {
					p.Tags = append(p.Tags, Tag{
						ID:    tagID,
						Name:  name,
						Color: tagColorStrings[i],
					})
				}
			}
		}
	} else {
		p.Tags = []Tag{}
	}

	// Decrypt the password and notes
	decryptedPassword, err := decrypt(encryptedPassword, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt password: %w", err)
	}
	p.Password = string(decryptedPassword)

	decryptedNotes, err := decrypt(encryptedNotes, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt notes: %w", err)
	}
	p.Notes = string(decryptedNotes)

	return &p, nil
}
