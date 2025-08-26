// handlers.go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"html/template"
	"fmt"
)

// -- IMPORTANT: Helper functions and structs are now assumed to be in other files (e.g., auth.go, user.go) --

// createSession and clearSession are assumed to be in auth.go.
// authenticateUser, createUser, deleteUser, renameUser, and changePassword
// are now assumed to be in user.go.

// parseTemplate is a helper to simplify template parsing with error handling.
// This function is now fixed to correctly render templates with a base layout.
func parseTemplate(w http.ResponseWriter, name string, data interface{}) {
    tmpl, err := template.ParseFiles("templates/base.html", "templates/" + name)
    if err != nil {
        http.Error(w, "Could not load template", http.StatusInternalServerError)
        log.Printf("Error parsing template '%s': %v", name, err)
        return
    }
    
    // The key change: We execute the "base.html" template, which in turn
    // finds and renders the "content" block from the other template file.
    err = tmpl.ExecuteTemplate(w, "base.html", data)
    if err != nil {
        http.Error(w, "Could not render template", http.StatusInternalServerError)
        log.Printf("Error rendering template '%s': %v", name, err)
    }
}

// renderStandaloneTemplate is a helper for simple, non-base-templated pages.
func renderStandaloneTemplate(w http.ResponseWriter, name string) {
	tmpl, err := template.ParseFiles("templates/" + name)
	if err != nil {
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		log.Printf("Error parsing simple template '%s': %v", name, err)
		return
	}
	tmpl.Execute(w, nil)
}

// loginHandler serves the login page and handles login requests.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := authenticateUser(username, password)
		if err != nil {
			// Using http.Error to send a clean message
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			log.Printf("Failed login attempt for user: %s", username)
			return
		}

		createSession(w, user)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther) // Use 303 for POST-redirect-GET
		return
	}
	
	// GET request, serve the login page using the new function
	renderStandaloneTemplate(w, "login.html")
}

// dashboardHandler serves the main user dashboard.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// We assume a middleware has populated the user object in the context.
	user, ok := r.Context().Value("user").(*User)
	if !ok || user == nil {
		// This case should be handled by middleware, but it's a good fail-safe.
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	
	// Added a more robust template parsing helper
	parseTemplate(w, "index.html", user)
}

// adminHandler serves the admin page for user management.
func adminHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*User)
	if !ok || user == nil || !user.IsAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("Access denied for non-admin user: %+v", user)
		return
	}
	
	// Reference the new template file name
	parseTemplate(w, "users.html", user)
}

// logoutHandler clears the user's session.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther) // Use 303 for POST-redirect-GET
}

// usersAPIHandler provides a RESTful interface for user management (for admins).
func usersAPIHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := r.Context().Value("user").(*User)
	if !ok || currentUser == nil || !currentUser.IsAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("API access denied for non-admin user: %+v", currentUser)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// Get all users
		users, err := getAllUsers()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get users: %v", err), http.StatusInternalServerError)
			log.Printf("Error getting all users: %v", err)
			return
		}
		json.NewEncoder(w).Encode(users)
	case http.MethodPost:
		// Create new user
		var data struct {
			Username string `json:"username"`
			Password string `json:"password"`
			IsAdmin  bool   `json:"isAdmin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			log.Printf("Failed to decode JSON for user creation: %v", err)
			return
		}
		if data.Username == "" || data.Password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		if err := createUser(currentUser, data.Username, data.Password, data.IsAdmin, false); err != nil {
			http.Error(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusInternalServerError)
			log.Printf("Error creating user: %v", err)
			return
		}
		w.WriteHeader(http.StatusCreated)

	case http.MethodDelete:
		// Delete user
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "Username query parameter is required", http.StatusBadRequest)
			return
		}

		if err := deleteUser(currentUser, username); err != nil {
			http.Error(w, fmt.Sprintf("Failed to delete user: %v", err), http.StatusInternalServerError)
			log.Printf("Error deleting user: %v", err)
			return
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodPut:
		// Update user info
		var data struct {
			Username string `json:"username"`
			NewUsername string `json:"newUsername"`
			IsAdmin  *bool `json:"isAdmin"`
			NewPassword string `json:"newPassword"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			log.Printf("Failed to decode JSON for user update: %v", err)
			return
		}

		if data.NewUsername != "" {
			if err := renameUser(currentUser, data.Username, data.NewUsername); err != nil {
				http.Error(w, fmt.Sprintf("Failed to rename user: %v", err), http.StatusInternalServerError)
				log.Printf("Error renaming user: %v", err)
				return
			}
		}

		if data.IsAdmin != nil {
			if err := changeAdminStatus(currentUser, data.Username, *data.IsAdmin); err != nil {
				http.Error(w, fmt.Sprintf("Failed to change admin status: %v", err), http.StatusInternalServerError)
				log.Printf("Error changing admin status: %v", err)
				return
			}
		}

		if data.NewPassword != "" {
			if err := changePassword(currentUser, data.Username, "", data.NewPassword); err != nil {
				http.Error(w, fmt.Sprintf("Failed to change password: %v", err), http.StatusInternalServerError)
				log.Printf("Error changing password: %v", err)
				return
			}
		}

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func changeMyPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUser, ok := r.Context().Value("user").(*User)
	if !ok || currentUser == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	
	var data struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("Failed to decode JSON for password change: %v", err)
		return
	}
	if data.CurrentPassword == "" || data.NewPassword == "" {
		http.Error(w, "Current and new passwords are required", http.StatusBadRequest)
		return
	}

	if err := changePassword(currentUser, currentUser.Username, data.CurrentPassword, data.NewPassword); err != nil {
		http.Error(w, fmt.Sprintf("Failed to change password: %v", err), http.StatusInternalServerError)
		log.Printf("Error changing password for user '%s': %v", currentUser.Username, err)
		return
	}
	
	w.WriteHeader(http.StatusOK)
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	renderStandaloneTemplate(w, "test.html")
}
