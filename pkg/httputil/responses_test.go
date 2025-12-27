// Package httputil tests
// Copyright (C) 2025 Joshua Goldstein

package httputil

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteError(t *testing.T) {
	tests := []struct {
		name           string
		message        string
		status         int
		err            error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Error with underlying error",
			message:        "Something went wrong",
			status:         http.StatusInternalServerError,
			err:            errors.New("database connection failed"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Something went wrong\n",
		},
		{
			name:           "Error without underlying error",
			message:        "Bad request",
			status:         http.StatusBadRequest,
			err:            nil,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Bad request\n",
		},
		{
			name:           "Custom status code",
			message:        "Not found",
			status:         http.StatusNotFound,
			err:            nil,
			expectedStatus: http.StatusNotFound,
			expectedBody:   "Not found\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			WriteError(rr, tt.message, tt.status, tt.err)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Status code = %v, expected %v", rr.Code, tt.expectedStatus)
			}

			if rr.Body.String() != tt.expectedBody {
				t.Errorf("Body = %q, expected %q", rr.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	tests := []struct {
		name         string
		data         interface{}
		expectError  bool
		expectedBody string
	}{
		{
			name:         "Simple object",
			data:         map[string]string{"message": "hello"},
			expectError:  false,
			expectedBody: `{"message":"hello"}`,
		},
		{
			name:         "Array",
			data:         []string{"a", "b", "c"},
			expectError:  false,
			expectedBody: `["a","b","c"]`,
		},
		{
			name:         "String",
			data:         "simple string",
			expectError:  false,
			expectedBody: `"simple string"`,
		},
		{
			name:         "Number",
			data:         42,
			expectError:  false,
			expectedBody: `42`,
		},
		{
			name:         "Boolean",
			data:         true,
			expectError:  false,
			expectedBody: `true`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			err := WriteJSON(rr, tt.data)

			if (err != nil) != tt.expectError {
				t.Errorf("WriteJSON() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if !tt.expectError {
				// Check content type
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Content-Type = %v, expected application/json", contentType)
				}

				// Check body (remove newline added by json encoder)
				body := strings.TrimSpace(rr.Body.String())
				if body != tt.expectedBody {
					t.Errorf("Body = %q, expected %q", body, tt.expectedBody)
				}
			}
		})
	}
}

func TestWriteJSONError(t *testing.T) {
	tests := []struct {
		name           string
		message        string
		status         int
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Bad Request",
			message:        "Invalid input",
			status:         http.StatusBadRequest,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid input",
		},
		{
			name:           "Internal Server Error",
			message:        "Database error",
			status:         http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Database error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			WriteJSONError(rr, tt.message, tt.status)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Status code = %v, expected %v", rr.Code, tt.expectedStatus)
			}

			// Check content type
			contentType := rr.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Content-Type = %v, expected application/json", contentType)
			}

			// Decode and check error message
			var response map[string]string
			err := json.NewDecoder(rr.Body).Decode(&response)
			if err != nil {
				t.Fatalf("Failed to decode JSON response: %v", err)
			}

			if response["error"] != tt.expectedError {
				t.Errorf("Error message = %v, expected %v", response["error"], tt.expectedError)
			}
		})
	}
}

func TestWriteJSONSuccess(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		data            interface{}
		expectedMessage string
		expectData      bool
	}{
		{
			name:            "Success with data",
			message:         "Operation completed",
			data:            map[string]int{"count": 5},
			expectedMessage: "Operation completed",
			expectData:      true,
		},
		{
			name:            "Success without data",
			message:         "Operation completed",
			data:            nil,
			expectedMessage: "Operation completed",
			expectData:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			WriteJSONSuccess(rr, tt.message, tt.data)

			if rr.Code != http.StatusOK {
				t.Errorf("Status code = %v, expected %v", rr.Code, http.StatusOK)
			}

			// Decode response
			var response map[string]interface{}
			err := json.NewDecoder(rr.Body).Decode(&response)
			if err != nil {
				t.Fatalf("Failed to decode JSON response: %v", err)
			}

			// Check success field
			if success, ok := response["success"].(bool); !ok || !success {
				t.Errorf("Success = %v, expected true", response["success"])
			}

			// Check message field
			if message, ok := response["message"].(string); !ok || message != tt.expectedMessage {
				t.Errorf("Message = %v, expected %v", response["message"], tt.expectedMessage)
			}

			// Check data field
			if tt.expectData {
				if _, ok := response["data"]; !ok {
					t.Error("Expected data field to be present")
				}
			} else {
				if _, ok := response["data"]; ok && response["data"] != nil {
					t.Error("Expected data field to be absent or nil")
				}
			}
		})
	}
}

func TestDecodeJSON(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		target    interface{}
		expectErr bool
	}{
		{
			name:      "Valid JSON object",
			body:      `{"name":"test","value":42}`,
			target:    &map[string]interface{}{},
			expectErr: false,
		},
		{
			name:      "Valid JSON array",
			body:      `["a","b","c"]`,
			target:    &[]string{},
			expectErr: false,
		},
		{
			name:      "Invalid JSON",
			body:      `{"name":"test","value":}`,
			target:    &map[string]interface{}{},
			expectErr: true,
		},
		{
			name:      "Empty body",
			body:      ``,
			target:    &map[string]interface{}{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			err := DecodeJSON(req, tt.target)

			if (err != nil) != tt.expectErr {
				t.Errorf("DecodeJSON() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestMethodNotAllowed(t *testing.T) {
	rr := httptest.NewRecorder()
	MethodNotAllowed(rr)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status code = %v, expected %v", rr.Code, http.StatusMethodNotAllowed)
	}

	expectedBody := "Method not allowed\n"
	if rr.Body.String() != expectedBody {
		t.Errorf("Body = %q, expected %q", rr.Body.String(), expectedBody)
	}
}

func TestUnauthorized(t *testing.T) {
	tests := []struct {
		name         string
		message      string
		expectedBody string
	}{
		{
			name:         "Custom message",
			message:      "Invalid token",
			expectedBody: "Invalid token\n",
		},
		{
			name:         "Empty message (default)",
			message:      "",
			expectedBody: "User not authenticated\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			Unauthorized(rr, tt.message)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("Status code = %v, expected %v", rr.Code, http.StatusUnauthorized)
			}

			if rr.Body.String() != tt.expectedBody {
				t.Errorf("Body = %q, expected %q", rr.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestForbidden(t *testing.T) {
	tests := []struct {
		name         string
		message      string
		expectedBody string
	}{
		{
			name:         "Custom message",
			message:      "Access denied",
			expectedBody: "Access denied\n",
		},
		{
			name:         "Empty message (default)",
			message:      "",
			expectedBody: "Forbidden\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			Forbidden(rr, tt.message)

			if rr.Code != http.StatusForbidden {
				t.Errorf("Status code = %v, expected %v", rr.Code, http.StatusForbidden)
			}

			if rr.Body.String() != tt.expectedBody {
				t.Errorf("Body = %q, expected %q", rr.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestBadRequest(t *testing.T) {
	rr := httptest.NewRecorder()
	BadRequest(rr, "Invalid input")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status code = %v, expected %v", rr.Code, http.StatusBadRequest)
	}

	expectedBody := "Invalid input\n"
	if rr.Body.String() != expectedBody {
		t.Errorf("Body = %q, expected %q", rr.Body.String(), expectedBody)
	}
}

func TestInternalServerError(t *testing.T) {
	tests := []struct {
		name         string
		message      string
		err          error
		expectedBody string
	}{
		{
			name:         "Custom message with error",
			message:      "Database failed",
			err:          errors.New("connection timeout"),
			expectedBody: "Database failed\n",
		},
		{
			name:         "Empty message (default)",
			message:      "",
			err:          errors.New("some error"),
			expectedBody: "Internal server error\n",
		},
		{
			name:         "No error",
			message:      "Something failed",
			err:          nil,
			expectedBody: "Something failed\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			InternalServerError(rr, tt.message, tt.err)

			if rr.Code != http.StatusInternalServerError {
				t.Errorf("Status code = %v, expected %v", rr.Code, http.StatusInternalServerError)
			}

			if rr.Body.String() != tt.expectedBody {
				t.Errorf("Body = %q, expected %q", rr.Body.String(), tt.expectedBody)
			}
		})
	}
}
