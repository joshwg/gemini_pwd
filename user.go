// user.go
package main

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

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
	return tags, nil
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

	_, err = db.Exec("UPDATE tags SET name = ?, description = ?, color = ? WHERE id = ? AND user_id = ?", newName, newDescription, newColor, tagID, userID)
	if err != nil {
		return fmt.Errorf("failed to update tag: %w", err)
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

// getPasswords retrieves a list of all passwords for a user, with optional filtering.
func getPasswords(userID int, query string) ([]PasswordEntry, error) {
	var rows *sql.Rows
	var err error

	sqlQuery := `
		SELECT
			pe.id, pe.site, pe.username, pe.password_encrypted, pe.notes_encrypted, pe.created_at, GROUP_CONCAT(t.name) as tagNames, GROUP_CONCAT(t.color) as tagColors
		FROM
			password_entries pe
		LEFT JOIN
			entry_tags et ON pe.id = et.entry_id
		LEFT JOIN
			tags t ON et.tag_id = t.id
		WHERE
			pe.user_id = ?
	`
	if query != "" {
		sqlQuery += `
			AND (
				pe.site LIKE ? COLLATE NOCASE
				OR pe.username LIKE ? COLLATE NOCASE
				OR t.name LIKE ? COLLATE NOCASE
			)
		`
	}
	sqlQuery += `
		GROUP BY
			pe.id
		ORDER BY
			pe.site ASC
	`
	
	if query != "" {
		searchQuery := "%" + query + "%"
		rows, err = db.Query(sqlQuery, userID, searchQuery, searchQuery, searchQuery)
	} else {
		rows, err = db.Query(sqlQuery, userID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query passwords: %w", err)
	}
	defer rows.Close()

	var passwords []PasswordEntry
	for rows.Next() {
		var p PasswordEntry
		var tagNames, tagColors sql.NullString
		var encryptedPassword, encryptedNotes []byte
		if err := rows.Scan(&p.ID, &p.Site, &p.Username, &encryptedPassword, &encryptedNotes, &p.CreatedAt, &tagNames, &tagColors); err != nil {
			return nil, fmt.Errorf("failed to scan password row: %w", err)
		}
		
		if tagNames.Valid {
			p.Tags = strings.Split(tagNames.String, ",")
		} else {
			p.Tags = []string{}
		}

		passwords = append(passwords, p)
	}
	
	return passwords, nil
}

// createPasswordEntry creates a new password entry.
func createPasswordEntry(userID int, site, username, password, notes string, tagNames []string) error {
	// First, encrypt the sensitive data
	encryptedPassword, err := encrypt([]byte(password))
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}

	encryptedNotes, err := encrypt([]byte(notes))
	if err != nil {
		return fmt.Errorf("failed to encrypt notes: %w", err)
	}
	
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	
	res, err := tx.Exec("INSERT INTO password_entries (user_id, site, username, password_encrypted, notes_encrypted) VALUES (?, ?, ?, ?, ?)", userID, site, username, encryptedPassword, encryptedNotes)
	if err != nil {
		return fmt.Errorf("failed to insert password entry: %w", err)
	}
	
	lastID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	// Add tags to the new password entry
	for _, tagName := range tagNames {
		var tagID int64
		err := tx.QueryRow("SELECT id FROM tags WHERE user_id = ? AND name = ? COLLATE NOCASE", userID, tagName).Scan(&tagID)
		if err != nil {
			if err == sql.ErrNoRows {
				// Create the tag if it doesn't exist
				res, err := tx.Exec("INSERT INTO tags (user_id, name) VALUES (?, ?)", userID, tagName)
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

	// Update the password entry
	encryptedPassword, err := encrypt([]byte(password))
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}
	encryptedNotes, err := encrypt([]byte(notes))
	if err != nil {
		return fmt.Errorf("failed to encrypt notes: %w", err)
	}
	_, err = tx.Exec("UPDATE password_entries SET site = ?, username = ?, password_encrypted = ?, notes_encrypted = ? WHERE id = ? AND user_id = ?", site, username, encryptedPassword, encryptedNotes, id, userID)
	if err != nil {
		return fmt.Errorf("failed to update password entry: %w", err)
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
				// Create the tag if it doesn't exist
				res, err := tx.Exec("INSERT INTO tags (user_id, name) VALUES (?, ?)", userID, tagName)
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

// getPasswordByID retrieves a password by its ID and decrypts it.
func getPasswordByID(userID, id int) (*PasswordEntry, error) {
	var p PasswordEntry
	var encryptedPassword, encryptedNotes []byte
	var tagNames, tagColors sql.NullString

	sqlQuery := `
		SELECT
			pe.id, pe.site, pe.username, pe.password_encrypted, pe.notes_encrypted, pe.created_at, GROUP_CONCAT(t.name) as tagNames, GROUP_CONCAT(t.color) as tagColors
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
	err := db.QueryRow(sqlQuery, userID, id).Scan(&p.ID, &p.Site, &p.Username, &encryptedPassword, &encryptedNotes, &p.CreatedAt, &tagNames, &tagColors)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve password: %w", err)
	}

	if tagNames.Valid {
		p.Tags = strings.Split(tagNames.String, ",")
	} else {
		p.Tags = []string{}
	}

	// Decrypt the password and notes
	decryptedPassword, err := decrypt(encryptedPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt password: %w", err)
	}
	p.Password = string(decryptedPassword)

	decryptedNotes, err := decrypt(encryptedNotes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt notes: %w", err)
	}
	p.Notes = string(decryptedNotes)

	return &p, nil
}
