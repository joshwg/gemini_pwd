// main.go
package main

import (
	"log"
	"net/http"
)

// The 'db' variable is declared in database.go and is accessible here.

func main() {
	// Initialize the database connection and tables
	initDB("passwords.db")

	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/", loginHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/test", testHandler)
	
	// Protected routes (require authentication)
	mux.HandleFunc("/dashboard", authMiddleware(dashboardHandler))
	mux.HandleFunc("/logout", authMiddleware(logoutHandler))
	mux.HandleFunc("/users", authMiddleware(usersHandler))
	mux.HandleFunc("/tags", authMiddleware(tagsHandler))
	mux.HandleFunc("/api/users", authMiddleware(usersAPIHandler))
	mux.HandleFunc("/api/user/password", authMiddleware(changeMyPasswordHandler))
	mux.HandleFunc("/api/passwords", authMiddleware(passwordsAPIHandler))
	mux.HandleFunc("/api/tags", authMiddleware(tagsAPIHandler))

	// Import/Export routes
	mux.HandleFunc("/export/tags", authMiddleware(exportTagsHandler))
	mux.HandleFunc("/import/tags", authMiddleware(importTagsHandler))
	mux.HandleFunc("/export/passwords", authMiddleware(exportPasswordsHandler))
	mux.HandleFunc("/import/passwords", authMiddleware(importPasswordsHandler))

	// Start the server
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
