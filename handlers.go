// handlers.go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"html/template"
	"fmt"
	"strconv"
)

// parseTemplate is a helper to simplify template parsing with a base layout.
func parseTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, err := template.ParseFiles("templates/base.html", "templates/"+name)
	if err != nil {
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		log.Printf("Error parsing template '%s': %v", name, err)
		return
	}

	err = tmpl.ExecuteTemplate(w, "base.html", data)
	if err != nil {
		http.Error(w, "Could not render template", http.StatusInternalServerError)
		log.Printf("Error rendering template '%s': %v", name, err)
	}
}

// renderStandaloneTemplate is a helper for simple, non-base-templated pages.
func renderStandaloneTemplate(w http.ResponseWriter, name string) {
	tmpl, err := template.ParseFiles("templates/"+name)
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
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			log.Printf("Failed login attempt for user: %s", username)
			return
		}

		createSession(w, user)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	renderStandaloneTemplate(w, "login.html")
}

// dashboardHandler serves the main user dashboard.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*User)
	if !ok || user == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	parseTemplate(w, "index.html", user)
}

// usersHandler serves the user management page (formerly admin).
func usersHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*User)
	if !ok || user == nil || !user.IsAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("Access denied for non-admin user: %+v", user)
		return
	}

	parseTemplate(w, "users.html", user)
}

// tagsHandler serves the tag management page.
func tagsHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*User)
	if !ok || user == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	parseTemplate(w, "tags.html", user)
}

// logoutHandler clears the user's session.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
		users, err := getAllUsers()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get users: %v", err), http.StatusInternalServerError)
			log.Printf("Error getting all users: %v", err)
			return
		}
		json.NewEncoder(w).Encode(users)
	case http.MethodPost:
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
			http.Error(w, err.Error(), http.StatusConflict)
			log.Printf("Error creating user: %v", err)
			return
		}
		w.WriteHeader(http.StatusCreated)

	case http.MethodDelete:
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "Username query parameter is required", http.StatusBadRequest)
			return
		}

		if err := deleteUser(currentUser, username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Printf("Error deleting user: %v", err)
			return
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodPut:
		var data struct {
			Username    string `json:"username"`
			NewUsername string `json:"newUsername"`
			IsAdmin     *bool  `json:"isAdmin"`
			NewPassword string `json:"newPassword"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			log.Printf("Failed to decode JSON for user update: %v", err)
			return
		}
		
		var targetUserID int
		err := db.QueryRow("SELECT id FROM users WHERE username = ? COLLATE NOCASE", data.Username).Scan(&targetUserID)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		if data.NewUsername != "" {
			if err := renameUser(currentUser, targetUserID, data.Username, data.NewUsername); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				log.Printf("Error renaming user: %v", err)
				return
			}
		}

		if data.IsAdmin != nil {
			if err := changeAdminStatus(currentUser, data.Username, *data.IsAdmin); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Printf("Error changing admin status: %v", err)
				return
			}
		}

		if data.NewPassword != "" {
			if err := changePassword(currentUser, data.Username, "", data.NewPassword); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Printf("Error changing password: %v", err)
				return
			}
		}

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// changeMyPasswordHandler provides an endpoint for a user to update their own password.
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
		NewPassword     string `json:"newPassword"`
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error changing password for user '%s': %v", currentUser.Username, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// testHandler serves a simple, non-templated page for debugging.
func testHandler(w http.ResponseWriter, r *http.Request) {
	renderStandaloneTemplate(w, "test.html")
}

// passwordsAPIHandler provides a RESTful interface for password management.
func passwordsAPIHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := r.Context().Value("user").(*User)
	if !ok || currentUser == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		query := r.URL.Query().Get("q")
		passwords, err := getPasswords(currentUser.ID, query)
		if err != nil {
			log.Printf("Error retrieving passwords for user %d: %v", currentUser.ID, err)
			http.Error(w, "Failed to retrieve passwords", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(passwords)
	case http.MethodPost:
		var data struct {
			Site     string   `json:"site"`
			Username string   `json:"username"`
			Password string   `json:"password"`
			Notes    string   `json:"notes"`
			Tags     []string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if data.Site == "" || data.Username == "" || data.Password == "" {
			http.Error(w, "Site, username, and password are required", http.StatusBadRequest)
			return
		}

		if err := createPasswordEntry(currentUser.ID, data.Site, data.Username, data.Password, data.Notes, data.Tags); err != nil {
			http.Error(w, fmt.Sprintf("Failed to create password: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		passwordID := r.URL.Query().Get("id")
		if passwordID == "" {
			http.Error(w, "Password ID is required", http.StatusBadRequest)
			return
		}
		
		id, err := strconv.Atoi(passwordID)
		if err != nil {
			http.Error(w, "Invalid password ID", http.StatusBadRequest)
			return
		}

		if err := deletePasswordEntry(currentUser.ID, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodPut:
		var data struct {
			ID       int      `json:"id"`
			Site     string   `json:"site"`
			Username string   `json:"username"`
			Password string   `json:"password"`
			Notes    string   `json:"notes"`
			Tags     []string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if data.Site == "" || data.Username == "" {
			http.Error(w, "Site and username are required", http.StatusBadRequest)
			return
		}

		if err := updatePasswordEntry(currentUser.ID, data.ID, data.Site, data.Username, data.Password, data.Notes, data.Tags); err != nil {
			http.Error(w, fmt.Sprintf("Failed to update password: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// tagsAPIHandler provides a RESTful interface for tag management.
func tagsAPIHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := r.Context().Value("user").(*User)
	if !ok || currentUser == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		tags, err := getTags(currentUser.ID)
		if err != nil {
			http.Error(w, "Failed to retrieve tags", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(tags)
	case http.MethodPost:
		var data struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Color       string `json:"color"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if data.Name == "" {
			http.Error(w, "Tag name is required", http.StatusBadRequest)
			return
		}
		if err := createTag(currentUser.ID, data.Name, data.Description, data.Color); err != nil {
			http.Error(w, fmt.Sprintf("Failed to create tag: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var data struct {
			ID          int    `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Color       string `json:"color"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if data.Name == "" {
			http.Error(w, "Tag name is required", http.StatusBadRequest)
			return
		}
		if err := updateTag(currentUser.ID, data.ID, data.Name, data.Description, data.Color); err != nil {
			http.Error(w, fmt.Sprintf("Failed to update tag: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		tagID := r.URL.Query().Get("id")
		if tagID == "" {
			http.Error(w, "Tag ID is required", http.StatusBadRequest)
			return
		}

		id, err := strconv.Atoi(tagID)
		if err != nil {
			http.Error(w, "Invalid tag ID", http.StatusBadRequest)
			return
		}
		
		if err := deleteTag(currentUser.ID, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
