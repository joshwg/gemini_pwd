// user.go
package main

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)


// User represents a user in the system.
type User struct {
	ID       int
	Username string
	IsAdmin  bool
}

// authenticateUser checks username and password, returns User object on success.
func authenticateUser(username, password string) (*User, error) {
	var id int
	var hash string
	var isAdmin bool
	err := db.QueryRow("SELECT id, password_hash, is_admin FROM users WHERE username = ?", username).Scan(&id, &hash, &isAdmin)
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
	if admin.Username == usernameToDelete {
		return fmt.Errorf("cannot delete yourself")
	}
	res, err := db.Exec("DELETE FROM users WHERE username = ?", usernameToDelete)
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
func renameUser(admin *User, oldUsername, newUsername string) error {
    if admin == nil || !admin.IsAdmin {
        return fmt.Errorf("permission denied: only administrators can rename users")
    }
    _, err := db.Exec("UPDATE users SET username = ? WHERE username = ?", newUsername, oldUsername)
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
	if admin.Username == targetUsername {
		return fmt.Errorf("cannot change your own admin status")
	}
	_, err := db.Exec("UPDATE users SET is_admin = ? WHERE username = ?", newStatus, targetUsername)
	if err != nil {
		return fmt.Errorf("failed to update admin status: %w", err)
	}
	return nil
}

// changePassword
func changePassword(currentUser *User, targetUsername, currentPassword, newPassword string) error {
	var targetUserID int
	var targetUserHash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", targetUsername).Scan(&targetUserID, &targetUserHash)
	if err != nil {
		return fmt.Errorf("target user '%s' not found", targetUsername)
	}

	// Admin can change anyone's password without the current one
	if currentUser.IsAdmin {
		if currentUser.ID == targetUserID {
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
