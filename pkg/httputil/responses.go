// Package httputil provides HTTP utility functions for consistent response handling
package httputil

import (
	"encoding/json"
	"gemini_pwd/pkg/logger"
	"net/http"
)

// WriteError writes an error response and logs it
func WriteError(w http.ResponseWriter, message string, status int, err error) {
	http.Error(w, message, status)
	if err != nil {
		logger.Error("HTTP Error", err, "status", status, "message", message)
	} else {
		logger.Warning("HTTP Error: "+message, "status", status)
	}
}

// WriteJSON writes a JSON response with proper headers
func WriteJSON(w http.ResponseWriter, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(data)
}

// WriteJSONError writes a JSON error response
func WriteJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// WriteJSONSuccess writes a JSON success response
func WriteJSONSuccess(w http.ResponseWriter, message string, data interface{}) {
	response := map[string]interface{}{
		"success": true,
		"message": message,
	}
	if data != nil {
		response["data"] = data
	}
	WriteJSON(w, response)
}

// DecodeJSON decodes JSON from request body into the provided interface
func DecodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// MethodNotAllowed writes a method not allowed error
func MethodNotAllowed(w http.ResponseWriter) {
	WriteError(w, "Method not allowed", http.StatusMethodNotAllowed, nil)
}

// Unauthorized writes an unauthorized error
func Unauthorized(w http.ResponseWriter, message string) {
	if message == "" {
		message = "User not authenticated"
	}
	WriteError(w, message, http.StatusUnauthorized, nil)
}

// Forbidden writes a forbidden error
func Forbidden(w http.ResponseWriter, message string) {
	if message == "" {
		message = "Forbidden"
	}
	WriteError(w, message, http.StatusForbidden, nil)
}

// BadRequest writes a bad request error
func BadRequest(w http.ResponseWriter, message string) {
	WriteError(w, message, http.StatusBadRequest, nil)
}

// InternalServerError writes an internal server error
func InternalServerError(w http.ResponseWriter, message string, err error) {
	if message == "" {
		message = "Internal server error"
	}
	WriteError(w, message, http.StatusInternalServerError, err)
}
