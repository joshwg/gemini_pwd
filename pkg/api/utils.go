// Package api provides common API utility functions
// Copyright (C) 2025 Joshua Goldstein

package api

import (
	"net/http"

	"gemini_pwd/pkg/httputil"
	"gemini_pwd/pkg/logger"
)

// DecodeRequest decodes JSON request body into the provided data structure
// and handles common error responses
func DecodeRequest(w http.ResponseWriter, r *http.Request, data interface{}, operation string) bool {
	if err := httputil.DecodeJSON(r, data); err != nil {
		httputil.BadRequest(w, "Invalid request body")
		logger.Error("Failed to decode JSON for "+operation, err)
		return false
	}
	return true
}

// WriteSuccessResponse writes a standardized success response
func WriteSuccessResponse(w http.ResponseWriter, message string, data interface{}) {
	response := SuccessResponse{
		Success: true,
		Message: message,
		Data:    data,
	}
	httputil.WriteJSON(w, response)
}

// WriteErrorResponse writes a standardized error response
func WriteErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	response := ErrorResponse{
		Success: false,
		Error:   message,
	}
	w.WriteHeader(statusCode)
	httputil.WriteJSON(w, response)
}

// WriteRateLimitResponse writes a rate limit check response
func WriteRateLimitResponse(w http.ResponseWriter, isLimited bool, remainingTime int) {
	response := RateLimitResponse{
		IsLimited:     isLimited,
		RemainingTime: remainingTime,
	}
	httputil.WriteJSON(w, response)
}

// WriteDuplicateCheckResponse writes a duplicate check response
func WriteDuplicateCheckResponse(w http.ResponseWriter, isDuplicate bool) {
	response := DuplicateCheckResponse{
		IsDuplicate: isDuplicate,
	}
	httputil.WriteJSON(w, response)
}
