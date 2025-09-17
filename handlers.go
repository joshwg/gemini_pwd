// handlers.go
package main

import (
	"encoding/csv"
	"fmt"
	"gemini_pwd/pkg/api"
	"gemini_pwd/pkg/httputil"
	"gemini_pwd/pkg/logger"
	templatePkg "gemini_pwd/pkg/template"
	"net/http"
	"strconv"
	"strings"
)

// parseTemplate is a helper to simplify template parsing with a base layout.
func parseTemplate(w http.ResponseWriter, name string, data interface{}) {
	err := templatePkg.RenderWithBase(w, name, data)
	if err != nil {
		httputil.InternalServerError(w, "Could not render template", err)
		logger.Error("Failed to render template", err, "template", name)
	}
}

// renderStandaloneTemplate is a helper for simple, non-base-templated pages.
func renderStandaloneTemplate(w http.ResponseWriter, name string) {
	err := templatePkg.RenderStandalone(w, name, nil)
	if err != nil {
		httputil.InternalServerError(w, "Could not render template", err)
		logger.Error("Failed to render standalone template", err, "template", name)
	}
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
			logger.Error("Error checking rate limit", err)
			httputil.InternalServerError(w, "", err)
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

			httputil.WriteError(w, message, http.StatusTooManyRequests, nil)
			logger.Security("Rate limited login attempt", map[string]interface{}{
				"username": username,
				"ip":       clientIP,
			})
			return
		}

		user, err := authenticateUser(username, password)
		if err != nil {
			// Record failed attempt
			recordLoginAttempt(username, clientIP, false)

			httputil.Unauthorized(w, "Invalid credentials")
			logger.Security("Failed login attempt", map[string]interface{}{
				"username": username,
				"ip":       clientIP,
			})
			return
		}

		// Record successful attempt
		recordLoginAttempt(username, clientIP, true)

		// Create session
		err = createSession(w, user)
		if err != nil {
			logger.Error("Error creating session for user", err, username)
			httputil.InternalServerError(w, "", err)
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
		httputil.MethodNotAllowed(w)
		return
	}

	username := r.FormValue("username")
	clientIP := getClientIP(r)

	if username == "" {
		api.WriteRateLimitResponse(w, false, 0)
		return
	}

	isLimited, cooldownTime, err := checkRateLimit(username, clientIP)
	if err != nil {
		logger.Error("Error checking rate limit for API", err)
		httputil.InternalServerError(w, "", err)
		return
	}

	api.WriteRateLimitResponse(w, isLimited, int(cooldownTime.Seconds()))
}

// dashboardHandler serves the main user dashboard.
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok || user == nil {
		httputil.Unauthorized(w, "")
		return
	}

	parseTemplate(w, "index.html", user)
}

// usersHandler serves the user management page (formerly admin).
func usersHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok || user == nil || !user.IsAdmin {
		httputil.Forbidden(w, "")
		logger.Security("Access denied for non-admin user", map[string]interface{}{
			"user": fmt.Sprintf("%+v", user),
		})
		return
	}

	parseTemplate(w, "users.html", user)
}

// tagsHandler serves the tag management page.
func tagsHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getUserFromContext(r)
	if !ok || user == nil {
		httputil.Unauthorized(w, "")
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
		httputil.Forbidden(w, "Forbidden")
		logger.Security("API access denied for non-admin user", map[string]interface{}{
			"user_id":  currentUser.ID,
			"username": currentUser.Username,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		users, err := getAllUsers()
		if err != nil {
			httputil.InternalServerError(w, "Failed to get users", err)
			logger.Error("Error getting all users", err)
			return
		}
		httputil.WriteJSON(w, users)
	case http.MethodPost:
		var data api.CreateUserRequest
		if !api.DecodeRequest(w, r, &data, "user creation") {
			return
		}
		if data.Username == "" || data.Password == "" {
			httputil.BadRequest(w, "Username and password are required")
			return
		}

		if err := createUser(currentUser, data.Username, data.Password, data.IsAdmin, false); err != nil {
			if strings.Contains(err.Error(), "username already exists") {
				httputil.WriteError(w, err.Error(), http.StatusConflict, err)
			} else {
				httputil.InternalServerError(w, err.Error(), err)
			}
			logger.Error("Error creating user", err)
			return
		}
		w.WriteHeader(http.StatusCreated)

	case http.MethodDelete:
		username := r.URL.Query().Get("username")
		if username == "" {
			httputil.BadRequest(w, "Username query parameter is required")
			return
		}

		if err := deleteUser(currentUser, username); err != nil {
			httputil.InternalServerError(w, err.Error(), err)
			logger.Error("Error deleting user", err)
			return
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodPut:
		var data api.UpdateUserRequest
		if !api.DecodeRequest(w, r, &data, "user update") {
			return
		}

		var targetUserID int
		err := db.QueryRow("SELECT id FROM users WHERE username = ? COLLATE NOCASE", data.Username).Scan(&targetUserID)
		if err != nil {
			httputil.BadRequest(w, "User not found")
			return
		}

		if data.NewUsername != "" {
			if err := renameUser(currentUser, targetUserID, data.Username, data.NewUsername); err != nil {
				httputil.InternalServerError(w, err.Error(), err)
				logger.Error("Error renaming user", err)
				return
			}
		}

		if data.IsAdmin != nil {
			if err := changeAdminStatus(currentUser, data.Username, *data.IsAdmin); err != nil {
				httputil.InternalServerError(w, err.Error(), err)
				logger.Error("Error changing admin status", err)
				return
			}
		}

		if data.NewPassword != "" {
			if err := changePassword(currentUser, data.Username, "", data.NewPassword); err != nil {
				httputil.InternalServerError(w, err.Error(), err)
				logger.Error("Error changing password", err)
				return
			}

			// Invalidate all sessions for the target user after admin password change
			if err := clearAllUserSessions(targetUserID); err != nil {
				logger.Error("Error clearing sessions after admin password change for user '"+data.Username+"'", err)
			}
		}

		w.WriteHeader(http.StatusOK)

	default:
		httputil.MethodNotAllowed(w)
	}
}

// changeMyPasswordHandler provides an endpoint for a user to update their own password.
func changeMyPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		httputil.MethodNotAllowed(w)
		return
	}

	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		httputil.Unauthorized(w, "User not authenticated")
		return
	}

	var data api.ChangePasswordRequest
	if !api.DecodeRequest(w, r, &data, "password change") {
		return
	}
	if data.CurrentPassword == "" || data.NewPassword == "" {
		httputil.BadRequest(w, "Current and new passwords are required")
		return
	}

	if err := changePassword(currentUser, currentUser.Username, data.CurrentPassword, data.NewPassword); err != nil {
		httputil.InternalServerError(w, err.Error(), err)
		logger.Error("Error changing password for user '"+currentUser.Username+"'", err)
		return
	}

	// Invalidate all sessions for this user after password change
	if err := clearAllUserSessions(currentUser.ID); err != nil {
		logger.Error("Error clearing sessions after password change for user '"+currentUser.Username+"'", err)
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
		httputil.Forbidden(w, "Forbidden")
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
				httputil.BadRequest(w, "Invalid password ID")
				return
			}

			// Get the password entry with user verification
			password, err := getPasswordByID(currentUser.ID, id)
			if err != nil {
				logger.Error("Error retrieving password for user", err, "user_id", currentUser.ID, "password_id", id)
				httputil.WriteError(w, "Password not found", http.StatusNotFound, err)
				return
			}

			if action == "copy" {
				// For copy action, decrypt and return only the password value
				decryptedPassword, err := getDecryptedPassword(currentUser.ID, id)
				if err != nil {
					logger.Error("Error decrypting password for copy", err)
					httputil.InternalServerError(w, "Failed to decrypt password", err)
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
					logger.Error("Error decrypting password for edit", err)
					httputil.InternalServerError(w, "Failed to decrypt password", err)
					return
				}

				decryptedNotes, err := getDecryptedNotes(currentUser.ID, id)
				if err != nil {
					logger.Error("Error decrypting notes for edit", err)
					httputil.InternalServerError(w, "Failed to decrypt notes", err)
					return
				}

				// Populate the decrypted fields
				password.Password = decryptedPassword
				password.Notes = decryptedNotes

				// Return the full password entry with decrypted password and notes
				httputil.WriteJSON(w, password)
				return
			}
		}

		// Default behavior: fetch passwords with filtering support
		var filter PasswordFilter

		// Parse query parameter for text search
		if query := r.URL.Query().Get("q"); query != "" {
			filter.Query = query
		}

		// Parse tag filter parameters (comma-separated tag IDs)
		if tagIDsParam := r.URL.Query().Get("tags"); tagIDsParam != "" {
			tagIDStrs := strings.Split(tagIDsParam, ",")
			for _, tagIDStr := range tagIDStrs {
				if tagID, err := strconv.Atoi(strings.TrimSpace(tagIDStr)); err == nil {
					filter.TagIDs = append(filter.TagIDs, tagID)
				}
			}
		}

		// Parse limit parameter
		if limitParam := r.URL.Query().Get("limit"); limitParam != "" {
			if limit, err := strconv.Atoi(limitParam); err == nil && limit > 0 {
				filter.Limit = limit
			}
		}
		if filter.Limit == 0 {
			filter.Limit = 100 // Default limit
		}

		// Parse offset parameter for pagination
		if offsetParam := r.URL.Query().Get("offset"); offsetParam != "" {
			if offset, err := strconv.Atoi(offsetParam); err == nil && offset >= 0 {
				filter.Offset = offset
			}
		}

		// Only return passwords if filters are applied (for security)
		if filter.Query == "" && len(filter.TagIDs) == 0 {
			// Return empty array when no filters are specified
			httputil.WriteJSON(w, []PasswordEntry{})
			return
		}

		passwords, err := getPasswordsWithFilter(currentUser.ID, filter)
		if err != nil {
			logger.Error("Error retrieving passwords for user", err, "user_id", currentUser.ID)
			httputil.InternalServerError(w, "Failed to retrieve passwords", err)
			return
		}
		httputil.WriteJSON(w, passwords)
	case http.MethodPost:
		var data api.CreatePasswordRequest
		if !api.DecodeRequest(w, r, &data, "password creation") {
			return
		}
		if data.Site == "" || data.Username == "" {
			httputil.BadRequest(w, "Site and username are required")
			return
		}

		if err := createPasswordEntry(currentUser.ID, data.Site, data.Username, data.Password, data.Notes, data.Tags); err != nil {
			httputil.InternalServerError(w, "Failed to create password", err)
			return
		}

		// Fetch the created password entry to return it (without sensitive data)
		passwords, err := getPasswords(currentUser.ID, "")
		if err != nil {
			logger.Error("Error retrieving passwords after creation", err)
			httputil.InternalServerError(w, "Password created but failed to retrieve", err)
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
			httputil.InternalServerError(w, "Password created but not found", nil)
			return
		}

		w.WriteHeader(http.StatusCreated)
		httputil.WriteJSON(w, createdPassword)
	case http.MethodDelete:
		passwordID := r.URL.Query().Get("id")
		if passwordID == "" {
			httputil.BadRequest(w, "Password ID is required")
			return
		}

		id, err := strconv.Atoi(passwordID)
		if err != nil {
			httputil.BadRequest(w, "Invalid password ID")
			return
		}

		if err := deletePasswordEntry(currentUser.ID, id); err != nil {
			httputil.InternalServerError(w, err.Error(), err)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodPut:
		var data api.UpdatePasswordRequest
		if !api.DecodeRequest(w, r, &data, "password update") {
			return
		}
		if data.Site == "" || data.Username == "" {
			httputil.BadRequest(w, "Site and username are required")
			return
		}

		logger.Info("Updating password entry", "user_id", currentUser.ID, "entry_id", data.ID, "site", data.Site, "username", data.Username, "tags", data.Tags)
		if err := updatePasswordEntry(currentUser.ID, data.ID, data.Site, data.Username, data.Password, data.Notes, data.Tags); err != nil {
			logger.Error("Error updating password entry", err)
			httputil.InternalServerError(w, "Failed to update password", err)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		httputil.MethodNotAllowed(w)
	}
}

// tagsAPIHandler provides a RESTful interface for tag management.
func tagsAPIHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		httputil.Forbidden(w, "Forbidden")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		tagIDStr := r.URL.Query().Get("id")
		if tagIDStr != "" {
			tagID, err := strconv.Atoi(tagIDStr)
			if err != nil {
				httputil.BadRequest(w, "Invalid tag ID")
				return
			}
			tag, err := getTagByID(currentUser.ID, tagID)
			if err != nil {
				httputil.WriteError(w, err.Error(), http.StatusNotFound, err)
				return
			}
			httputil.WriteJSON(w, tag)
		} else {
			tags, err := getTags(currentUser.ID)
			if err != nil {
				httputil.InternalServerError(w, "Failed to retrieve tags", err)
				return
			}
			httputil.WriteJSON(w, tags)
		}
	case http.MethodPost:
		var data api.CreateTagRequest
		if !api.DecodeRequest(w, r, &data, "tag creation") {
			return
		}
		if data.Name == "" {
			httputil.BadRequest(w, "Tag name is required")
			return
		}
		if err := createTag(currentUser.ID, data.Name, data.Description, data.Color); err != nil {
			httputil.InternalServerError(w, "Failed to create tag", err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		tagIDStr := r.URL.Query().Get("id")
		if tagIDStr == "" {
			httputil.BadRequest(w, "Tag ID is required for update")
			return
		}
		tagID, err := strconv.Atoi(tagIDStr)
		if err != nil {
			httputil.BadRequest(w, "Invalid tag ID")
			return
		}

		var data api.UpdateTagRequest
		if !api.DecodeRequest(w, r, &data, "tag update") {
			return
		}
		if data.Name == "" {
			httputil.BadRequest(w, "Tag name is required")
			return
		}
		if err := updateTag(currentUser.ID, tagID, data.Name, data.Description, data.Color); err != nil {
			httputil.InternalServerError(w, "Failed to update tag", err)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		tagID := r.URL.Query().Get("id")
		if tagID == "" {
			httputil.BadRequest(w, "Tag ID is required")
			return
		}

		id, err := strconv.Atoi(tagID)
		if err != nil {
			httputil.BadRequest(w, "Invalid tag ID")
			return
		}

		if err := deleteTag(currentUser.ID, id); err != nil {
			httputil.InternalServerError(w, err.Error(), err)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		httputil.MethodNotAllowed(w)
	}
}

func exportTagsHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		httputil.Forbidden(w, "Forbidden")
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
		httputil.InternalServerError(w, "Failed to retrieve tags for export", err)
		logger.Error("Error getting tags for user for export", err, "user_id", currentUser.ID)
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
		httputil.MethodNotAllowed(w)
		return
	}

	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		httputil.Forbidden(w, "Forbidden")
		return
	}

	file, _, err := r.FormFile("importFile")
	if err != nil {
		httputil.BadRequest(w, "Failed to read uploaded file")
		logger.Error("Error reading form file", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		httputil.BadRequest(w, "Failed to parse CSV file")
		logger.Error("Error parsing CSV", err)
		return
	}

	// Skip header row
	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) < 3 {
			logger.Warning("Skipping malformed record on line " + fmt.Sprintf("%d", i+1))
			continue
		}
		// record[0] = Name, record[1] = Description, record[2] = Color
		err := createOrUpdateTag(currentUser.ID, record[0], record[1], record[2])
		if err != nil {
			// Log error but continue processing other tags
			logger.Error("Failed to import tag '"+record[0]+"' on line "+fmt.Sprintf("%d", i+1), err)
		}
	}

	w.Write([]byte("Tags imported successfully"))
}

func exportPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		httputil.Forbidden(w, "Forbidden")
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
		httputil.InternalServerError(w, "Failed to retrieve passwords for export", err)
		logger.Error("Error getting passwords for user for export", err, "user_id", currentUser.ID)
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
		httputil.MethodNotAllowed(w)
		return
	}

	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		httputil.Forbidden(w, "Forbidden")
		return
	}

	file, _, err := r.FormFile("importFile")
	if err != nil {
		httputil.BadRequest(w, "Failed to read uploaded file")
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		httputil.BadRequest(w, "Failed to parse CSV file")
		return
	}

	for i, record := range records {
		if i == 0 { // Skip header
			continue
		}
		if len(record) < 5 {
			logger.Warning("Skipping malformed password record on line " + fmt.Sprintf("%d", i+1) + ": expected 5 columns (site, username, password, notes, tags), got " + fmt.Sprintf("%d", len(record)) + " columns")
			continue
		}
		site, username, password, notes, tagsStr := record[0], record[1], record[2], record[3], record[4]

		// Validate required fields
		if strings.TrimSpace(site) == "" {
			logger.Warning("Skipping password record on line " + fmt.Sprintf("%d", i+1) + ": site field is empty")
			continue
		}
		if strings.TrimSpace(username) == "" {
			logger.Warning("Skipping password record on line " + fmt.Sprintf("%d", i+1) + ": username field is empty")
			continue
		}

		tags := strings.Split(tagsStr, ";")

		// Trim whitespace from tags
		for j, t := range tags {
			tags[j] = strings.TrimSpace(t)
		}

		err := createOrUpdatePasswordEntry(currentUser.ID, site, username, password, notes, tags)
		if err != nil {
			logger.Error("Failed to import password for site '"+site+"' on line "+fmt.Sprintf("%d", i+1), err)
		}
	}

	w.Write([]byte("Passwords imported successfully"))
}

// checkPasswordDuplicateHandler checks if a password entry already exists
func checkPasswordDuplicateHandler(w http.ResponseWriter, r *http.Request) {
	currentUser, ok := getUserFromContext(r)
	if !ok || currentUser == nil {
		httputil.Unauthorized(w, "Unauthorized")
		return
	}

	if r.Method != http.MethodPost {
		httputil.MethodNotAllowed(w)
		return
	}

	var request api.CheckDuplicateRequest
	if !api.DecodeRequest(w, r, &request, "duplicate check") {
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
		httputil.InternalServerError(w, "Database error", err)
		return
	}

	api.WriteDuplicateCheckResponse(w, count > 0)
}
