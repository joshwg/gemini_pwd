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

	// Public routes (no authentication required)
	mux.HandleFunc("/", loginHandler)
	mux.HandleFunc("/login", loginHandler)
	
	// Protected routes (require authentication)
	// We'll apply the authMiddleware to these routes.
	mux.HandleFunc("/dashboard", authMiddleware(dashboardHandler))
	mux.HandleFunc("/logout", authMiddleware(logoutHandler))
	// Updated the route from /admin to /users
	mux.HandleFunc("/users", authMiddleware(adminHandler))
	mux.HandleFunc("/api/users", authMiddleware(usersAPIHandler))
	mux.HandleFunc("/api/change-password", authMiddleware(changeMyPasswordHandler))

	// Start the server
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
