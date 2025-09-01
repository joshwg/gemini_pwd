// handlers.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
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
	// Check if user is already authenticated and redirect to dashboard
	if c, err := r.Cookie("session_token"); err == nil {
		if user, err := validateSession(c.Value); err == nil && user != nil {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		clientIP := getClientIP(r)

		// Check rate limiting before attempting authentication
		isLimited, cooldownTime, err := checkRateLimit(username, clientIP)
		if err != nil {
			log.Printf("Error checking rate limit: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if isLimited {
			// Record this failed attempt
			recordLoginAttempt(username, clientIP, false)

			minutes := int(cooldownTime.Minutes())
			seconds := int(cooldownTime.Seconds()) % 60
			var message string
			if minutes > 0 {
				message = fmt.Sprintf("Too many failed login attempts. Please wait %d minutes and %d seconds before trying again.", minutes, seconds)
			} else {
				message = fmt.Sprintf("Too many failed login attempts. Please wait %d seconds before trying again.", seconds)
			}

			http.Error(w, message, http.StatusTooManyRequests)
			log.Printf("Rate limited login attempt for user: %s from IP: %s", username, clientIP)
			return
		}

		user, err := authenticateUser(username, password)
		if err != nil {
			// Record failed attempt
			recordLoginAttempt(username, clientIP, false)

			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			log.Printf("Failed login attempt for user: %s from IP: %s", username, clientIP)
			return
		}

		// Record successful attempt
		recordLoginAttempt(username, clientIP, true)

		// Create session
		err = createSession(w, user)
		if err != nil {
			log.Printf("Error creating session for user %s: %v", username, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// When login is successful, we now redirect from the server again.
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	renderStandaloneTemplate(w, "login.html")
}

// rateLimitCheckHandler provides an API to check rate limit status for login attempts
func rateLimitCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	clientIP := getClientIP(r)

	if username == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"isLimited":     false,
			"remainingTime": 0,
		})
		return
	}

	isLimited, cooldownTime, err := checkRateLimit(username, clientIP)
	if err != nil {
		log.Printf("Error checking rate limit for API: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"isLimited":     isLimited,
		"remainingTime": int(cooldownTime.Seconds()),
	})
}

// dashboardHandler serves the main user dashboard.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok || user == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	parseTemplate(w, "index.html", user)
}

// usersHandler serves the user management page (formerly admin).
func usersHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok || user == nil || !user.IsAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("Access denied for non-admin user: %+v", user)
		return
	}

	parseTemplate(w, "users.html", user)
}

// tagsHandler serves the tag management page.
func tagsHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
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
	currentUser, ok := getUserFromContext(r)
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

			// Invalidate all sessions for the target user after admin password change
			if err := clearAllUserSessions(targetUserID); err != nil {
				log.Printf("Error clearing sessions after admin password change for user '%s': %v", data.Username, err)
			}
		}

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// changeMyPasswordHandler provides an endpoint for a user to update their own password.
func changeMyPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUser, ok := getUserFromContext(r)
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

	// Invalidate all sessions for this user after password change
	if err := clearAllUserSessions(currentUser.ID); err != nil {
		log.Printf("Error clearing sessions after password change for user '%s': %v", currentUser.Username, err)
	}

	// Clear current session cookie
	clearSession(w, r)

	w.WriteHeader(http.StatusOK)
}

// testHandler serves a simple, non-templated page for debugging.
func testHandler(w http.ResponseWriter, r *http.Request) {
	renderStandaloneTemplate(w, "test.html")
}

// passwordsAPIHandler provides a RESTful interface for password management.
func passwordsAPIHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// Check if requesting a specific password by ID for editing
		passwordID := r.URL.Query().Get("id")
		action := r.URL.Query().Get("action")

		if passwordID != "" {
			// Fetch individual password for editing or copying
			id, err := strconv.Atoi(passwordID)
			if err != nil {
				http.Error(w, "Invalid password ID", http.StatusBadRequest)
				return
			}

			// Get the password entry with user verification
			password, err := getPasswordByID(currentUser.ID, id)
			if err != nil {
				log.Printf("Error retrieving password for user %d, ID %d: %v", currentUser.ID, id, err)
				http.Error(w, "Password not found", http.StatusNotFound)
				return
			}

			if action == "copy" {
				// For copy action, decrypt and return only the password value
				decryptedPassword, err := getDecryptedPassword(currentUser.ID, id)
				if err != nil {
					log.Printf("Error decrypting password for copy: %v", err)
					http.Error(w, "Failed to decrypt password", http.StatusInternalServerError)
					return
				}

				// Return only the password value as plain text
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte(decryptedPassword))
				return
			} else {
				// For edit action, decrypt password and notes fields
				decryptedPassword, err := getDecryptedPassword(currentUser.ID, id)
				if err != nil {
					log.Printf("Error decrypting password for edit: %v", err)
					http.Error(w, "Failed to decrypt password", http.StatusInternalServerError)
					return
				}

				decryptedNotes, err := getDecryptedNotes(currentUser.ID, id)
				if err != nil {
					log.Printf("Error decrypting notes for edit: %v", err)
					http.Error(w, "Failed to decrypt notes", http.StatusInternalServerError)
					return
				}

				// Populate the decrypted fields
				password.Password = decryptedPassword
				password.Notes = decryptedNotes

				// Return the full password entry with decrypted password and notes
				json.NewEncoder(w).Encode(password)
				return
			}
		}

		// Default behavior: fetch all passwords (without decrypted password/notes)
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
		if data.Site == "" || data.Username == "" {
			http.Error(w, "Site and username are required", http.StatusBadRequest)
			return
		}

		if err := createPasswordEntry(currentUser.ID, data.Site, data.Username, data.Password, data.Notes, data.Tags); err != nil {
			http.Error(w, fmt.Sprintf("Failed to create password: %v", err), http.StatusInternalServerError)
			return
		}

		// Fetch the created password entry to return it (without sensitive data)
		passwords, err := getPasswords(currentUser.ID, "")
		if err != nil {
			log.Printf("Error retrieving passwords after creation: %v", err)
			http.Error(w, "Password created but failed to retrieve", http.StatusInternalServerError)
			return
		}

		// Find the most recently created password for this user
		var createdPassword *PasswordEntry
		for _, p := range passwords {
			if p.Site == data.Site && p.Username == data.Username {
				createdPassword = &p
				break
			}
		}

		if createdPassword == nil {
			http.Error(w, "Password created but not found", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createdPassword)
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

		log.Printf("Updating password entry: userID=%d, entryID=%d, site=%s, username=%s, tags=%v", currentUser.ID, data.ID, data.Site, data.Username, data.Tags)
		if err := updatePasswordEntry(currentUser.ID, data.ID, data.Site, data.Username, data.Password, data.Notes, data.Tags); err != nil {
			log.Printf("Error updating password entry: %v", err)
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
	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		tagIDStr := r.URL.Query().Get("id")
		if tagIDStr != "" {
			tagID, err := strconv.Atoi(tagIDStr)
			if err != nil {
				http.Error(w, "Invalid tag ID", http.StatusBadRequest)
				return
			}
			tag, err := getTagByID(currentUser.ID, tagID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(tag)
		} else {
			tags, err := getTags(currentUser.ID)
			if err != nil {
				http.Error(w, "Failed to retrieve tags", http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(tags)
		}
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
		tagIDStr := r.URL.Query().Get("id")
		if tagIDStr == "" {
			http.Error(w, "Tag ID is required for update", http.StatusBadRequest)
			return
		}
		tagID, err := strconv.Atoi(tagIDStr)
		if err != nil {
			http.Error(w, "Invalid tag ID", http.StatusBadRequest)
			return
		}

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
		if err := updateTag(currentUser.ID, tagID, data.Name, data.Description, data.Color); err != nil {
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

func exportTagsHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get filename from query parameter, default if not provided
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "tags_export.csv"
	}
	// Ensure .csv extension
	if !strings.HasSuffix(strings.ToLower(filename), ".csv") {
		filename += ".csv"
	}

	tags, err := getTags(currentUser.ID)
	if err != nil {
		http.Error(w, "Failed to retrieve tags for export", http.StatusInternalServerError)
		log.Printf("Error getting tags for user %d for export: %v", currentUser.ID, err)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment;filename=%s", filename))

	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	writer.Write([]string{"Name", "Description", "Color"})

	// Write data
	for _, tag := range tags {
		writer.Write([]string{tag.Name, tag.Description, tag.Color})
	}
}

func importTagsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	file, _, err := r.FormFile("importFile")
	if err != nil {
		http.Error(w, "Failed to read uploaded file", http.StatusBadRequest)
		log.Printf("Error reading form file: %v", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		http.Error(w, "Failed to parse CSV file", http.StatusBadRequest)
		log.Printf("Error parsing CSV: %v", err)
		return
	}

	// Skip header row
	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) < 3 {
			log.Printf("Skipping malformed record on line %d", i+1)
			continue
		}
		// record[0] = Name, record[1] = Description, record[2] = Color
		err := createOrUpdateTag(currentUser.ID, record[0], record[1], record[2])
		if err != nil {
			// Log error but continue processing other tags
			log.Printf("Failed to import tag '%s' on line %d: %v", record[0], i+1, err)
		}
	}

	w.Write([]byte("Tags imported successfully"))
}

func exportPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get filename from query parameter, default if not provided
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		filename = "passwords_export.csv"
	}
	// Ensure .csv extension
	if !strings.HasSuffix(strings.ToLower(filename), ".csv") {
		filename += ".csv"
	}

	passwords, err := getAllDecryptedPasswords(currentUser.ID)
	if err != nil {
		http.Error(w, "Failed to retrieve passwords for export", http.StatusInternalServerError)
		log.Printf("Error getting passwords for user %d for export: %v", currentUser.ID, err)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment;filename=%s", filename))

	writer := csv.NewWriter(w)
	defer writer.Flush()

	writer.Write([]string{"Site", "Username", "Password", "Notes", "Tags"})

	for _, p := range passwords {
		// Extract tag names for CSV export
		tagNames := make([]string, len(p.Tags))
		for i, tag := range p.Tags {
			tagNames[i] = tag.Name
		}
		tagsStr := strings.Join(tagNames, ";") // Use semicolon in case a tag name has a comma
		writer.Write([]string{p.Site, p.Username, p.Password, p.Notes, tagsStr})
	}
}

func importPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	file, _, err := r.FormFile("importFile")
	if err != nil {
		http.Error(w, "Failed to read uploaded file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		http.Error(w, "Failed to parse CSV file", http.StatusBadRequest)
		return
	}

	for i, record := range records {
		if i == 0 { // Skip header
			continue
		}
		if len(record) < 5 {
			log.Printf("Skipping malformed password record on line %d: expected 5 columns (site, username, password, notes, tags), got %d columns: %v", i+1, len(record), record)
			continue
		}
		site, username, password, notes, tagsStr := record[0], record[1], record[2], record[3], record[4]

		// Validate required fields
		if strings.TrimSpace(site) == "" {
			log.Printf("Skipping password record on line %d: site field is empty", i+1)
			continue
		}
		if strings.TrimSpace(username) == "" {
			log.Printf("Skipping password record on line %d: username field is empty", i+1)
			continue
		}

		tags := strings.Split(tagsStr, ";")

		// Trim whitespace from tags
		for j, t := range tags {
			tags[j] = strings.TrimSpace(t)
		}

		err := createOrUpdatePasswordEntry(currentUser.ID, site, username, password, notes, tags)
		if err != nil {
			log.Printf("Failed to import password for site '%s' on line %d: %v", site, i+1, err)
		}
	}

	w.Write([]byte("Passwords imported successfully"))
}

// checkPasswordDuplicateHandler checks if a password entry already exists
func checkPasswordDuplicateHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Site     string `json:"site"`
		Username string `json:"username"`
		ID       int    `json:"id,omitempty"` // For edit mode, exclude this entry from duplicate check
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check for existing password entry (unique by site and username)
	var count int
	var err error

	if request.ID > 0 {
		// Edit mode - exclude the current entry from duplicate check
		err = db.QueryRow("SELECT COUNT(*) FROM password_entries WHERE user_id = ? AND site = ? AND username = ? AND id != ? COLLATE NOCASE",
			currentUser.ID, request.Site, request.Username, request.ID).Scan(&count)
	} else {
		// Add mode - check for any duplicates
		err = db.QueryRow("SELECT COUNT(*) FROM password_entries WHERE user_id = ? AND site = ? AND username = ? COLLATE NOCASE",
			currentUser.ID, request.Site, request.Username).Scan(&count)
	}

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	response := struct {
		IsDuplicate bool `json:"isDuplicate"`
	}{
		IsDuplicate: count > 0,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
