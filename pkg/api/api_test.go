// Package api tests
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateUserRequest(t *testing.T) {
	tests := []struct {
		name     string
		jsonStr  string
		expected CreateUserRequest
		wantErr  bool
	}{
		{
			name:    "Valid CreateUserRequest",
			jsonStr: `{"username":"testuser","password":"testpass","isAdmin":true}`,
			expected: CreateUserRequest{
				Username: "testuser",
				Password: "testpass",
				IsAdmin:  true,
			},
			wantErr: false,
		},
		{
			name:     "Empty JSON",
			jsonStr:  `{}`,
			expected: CreateUserRequest{},
			wantErr:  false,
		},
		{
			name:    "Invalid JSON",
			jsonStr: `{"username":"testuser","password":}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req CreateUserRequest
			err := json.Unmarshal([]byte(tt.jsonStr), &req)

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateUserRequest unmarshal error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && req != tt.expected {
				t.Errorf("CreateUserRequest = %+v, expected %+v", req, tt.expected)
			}
		})
	}
}

func TestUpdateUserRequest(t *testing.T) {
	tests := []struct {
		name     string
		jsonStr  string
		expected UpdateUserRequest
	}{
		{
			name:    "Valid UpdateUserRequest with IsAdmin true",
			jsonStr: `{"username":"testuser","newUsername":"newuser","isAdmin":true,"newPassword":"newpass"}`,
			expected: UpdateUserRequest{
				Username:    "testuser",
				NewUsername: "newuser",
				IsAdmin:     boolPtr(true),
				NewPassword: "newpass",
			},
		},
		{
			name:    "Valid UpdateUserRequest with IsAdmin false",
			jsonStr: `{"username":"testuser","isAdmin":false}`,
			expected: UpdateUserRequest{
				Username: "testuser",
				IsAdmin:  boolPtr(false),
			},
		},
		{
			name:    "UpdateUserRequest with nil IsAdmin",
			jsonStr: `{"username":"testuser","newUsername":"newuser"}`,
			expected: UpdateUserRequest{
				Username:    "testuser",
				NewUsername: "newuser",
				IsAdmin:     nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req UpdateUserRequest
			err := json.Unmarshal([]byte(tt.jsonStr), &req)
			if err != nil {
				t.Fatalf("UpdateUserRequest unmarshal error = %v", err)
			}

			if req.Username != tt.expected.Username {
				t.Errorf("Username = %v, expected %v", req.Username, tt.expected.Username)
			}
			if req.NewUsername != tt.expected.NewUsername {
				t.Errorf("NewUsername = %v, expected %v", req.NewUsername, tt.expected.NewUsername)
			}
			if req.NewPassword != tt.expected.NewPassword {
				t.Errorf("NewPassword = %v, expected %v", req.NewPassword, tt.expected.NewPassword)
			}

			// Special handling for pointer comparison
			if tt.expected.IsAdmin == nil && req.IsAdmin != nil {
				t.Errorf("IsAdmin = %v, expected nil", req.IsAdmin)
			} else if tt.expected.IsAdmin != nil && req.IsAdmin == nil {
				t.Errorf("IsAdmin = nil, expected %v", *tt.expected.IsAdmin)
			} else if tt.expected.IsAdmin != nil && req.IsAdmin != nil && *req.IsAdmin != *tt.expected.IsAdmin {
				t.Errorf("IsAdmin = %v, expected %v", *req.IsAdmin, *tt.expected.IsAdmin)
			}
		})
	}
}

func TestPasswordRequests(t *testing.T) {
	// Test CreatePasswordRequest
	createJSON := `{"site":"example.com","username":"user","password":"pass","notes":"notes","tags":["tag1","tag2"]}`
	var createReq CreatePasswordRequest
	err := json.Unmarshal([]byte(createJSON), &createReq)
	if err != nil {
		t.Fatalf("CreatePasswordRequest unmarshal error = %v", err)
	}

	expected := CreatePasswordRequest{
		Site:     "example.com",
		Username: "user",
		Password: "pass",
		Notes:    "notes",
		Tags:     []string{"tag1", "tag2"},
	}

	if createReq.Site != expected.Site || createReq.Username != expected.Username ||
		createReq.Password != expected.Password || createReq.Notes != expected.Notes ||
		len(createReq.Tags) != len(expected.Tags) {
		t.Errorf("CreatePasswordRequest = %+v, expected %+v", createReq, expected)
	}

	// Check tags separately
	for i, tag := range createReq.Tags {
		if i >= len(expected.Tags) || tag != expected.Tags[i] {
			t.Errorf("CreatePasswordRequest tags mismatch at index %d: got %v, expected %v", i, tag, expected.Tags[i])
		}
	}

	// Test UpdatePasswordRequest
	updateJSON := `{"id":1,"site":"example.com","username":"user","password":"pass","notes":"notes","tags":["tag1"]}`
	var updateReq UpdatePasswordRequest
	err = json.Unmarshal([]byte(updateJSON), &updateReq)
	if err != nil {
		t.Fatalf("UpdatePasswordRequest unmarshal error = %v", err)
	}

	expectedUpdate := UpdatePasswordRequest{
		ID:       1,
		Site:     "example.com",
		Username: "user",
		Password: "pass",
		Notes:    "notes",
		Tags:     []string{"tag1"},
	}

	if updateReq.ID != expectedUpdate.ID || updateReq.Site != expectedUpdate.Site {
		t.Errorf("UpdatePasswordRequest = %+v, expected %+v", updateReq, expectedUpdate)
	}
}

func TestTagRequests(t *testing.T) {
	// Test CreateTagRequest
	createJSON := `{"name":"work","description":"Work related","color":"#FF0000"}`
	var createReq CreateTagRequest
	err := json.Unmarshal([]byte(createJSON), &createReq)
	if err != nil {
		t.Fatalf("CreateTagRequest unmarshal error = %v", err)
	}

	expected := CreateTagRequest{
		Name:        "work",
		Description: "Work related",
		Color:       "#FF0000",
	}

	if createReq.Name != expected.Name || createReq.Description != expected.Description ||
		createReq.Color != expected.Color {
		t.Errorf("CreateTagRequest = %+v, expected %+v", createReq, expected)
	}
}

func TestResponseTypes(t *testing.T) {
	// Test RateLimitResponse
	rateResp := RateLimitResponse{
		IsLimited:     true,
		RemainingTime: 30,
	}

	data, err := json.Marshal(rateResp)
	if err != nil {
		t.Fatalf("RateLimitResponse marshal error = %v", err)
	}

	expectedJSON := `{"isLimited":true,"remainingTime":30}`
	if string(data) != expectedJSON {
		t.Errorf("RateLimitResponse JSON = %s, expected %s", string(data), expectedJSON)
	}

	// Test DuplicateCheckResponse
	dupResp := DuplicateCheckResponse{IsDuplicate: true}
	data, err = json.Marshal(dupResp)
	if err != nil {
		t.Fatalf("DuplicateCheckResponse marshal error = %v", err)
	}

	expectedJSON = `{"isDuplicate":true}`
	if string(data) != expectedJSON {
		t.Errorf("DuplicateCheckResponse JSON = %s, expected %s", string(data), expectedJSON)
	}
}

func TestDecodeRequest(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		operation      string
		expectedStatus int
		shouldSucceed  bool
	}{
		{
			name:          "Valid JSON",
			body:          `{"username":"test","password":"pass","isAdmin":false}`,
			operation:     "test operation",
			shouldSucceed: true,
		},
		{
			name:           "Invalid JSON",
			body:           `{"username":"test","password":}`,
			operation:      "test operation",
			expectedStatus: http.StatusBadRequest,
			shouldSucceed:  false,
		},
		{
			name:          "Empty body",
			body:          `{}`,
			operation:     "test operation",
			shouldSucceed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			var data CreateUserRequest
			result := DecodeRequest(rr, req, &data, tt.operation)

			if result != tt.shouldSucceed {
				t.Errorf("DecodeRequest() = %v, expected %v", result, tt.shouldSucceed)
			}

			if !tt.shouldSucceed && rr.Code != tt.expectedStatus {
				t.Errorf("Status code = %v, expected %v", rr.Code, tt.expectedStatus)
			}
		})
	}
}

func TestWriteResponses(t *testing.T) {
	// Test WriteSuccessResponse
	t.Run("WriteSuccessResponse", func(t *testing.T) {
		rr := httptest.NewRecorder()
		data := map[string]string{"key": "value"}
		WriteSuccessResponse(rr, "Operation successful", data)

		if rr.Code != http.StatusOK {
			t.Errorf("Status code = %v, expected %v", rr.Code, http.StatusOK)
		}

		var response SuccessResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if !response.Success {
			t.Error("Expected success to be true")
		}
		if response.Message != "Operation successful" {
			t.Errorf("Message = %v, expected 'Operation successful'", response.Message)
		}
	})

	// Test WriteErrorResponse
	t.Run("WriteErrorResponse", func(t *testing.T) {
		rr := httptest.NewRecorder()
		WriteErrorResponse(rr, http.StatusBadRequest, "Bad request")

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Status code = %v, expected %v", rr.Code, http.StatusBadRequest)
		}

		var response ErrorResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response.Success {
			t.Error("Expected success to be false")
		}
		if response.Error != "Bad request" {
			t.Errorf("Error = %v, expected 'Bad request'", response.Error)
		}
	})

	// Test WriteRateLimitResponse
	t.Run("WriteRateLimitResponse", func(t *testing.T) {
		rr := httptest.NewRecorder()
		WriteRateLimitResponse(rr, true, 60)

		var response RateLimitResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if !response.IsLimited {
			t.Error("Expected IsLimited to be true")
		}
		if response.RemainingTime != 60 {
			t.Errorf("RemainingTime = %v, expected 60", response.RemainingTime)
		}
	})

	// Test WriteDuplicateCheckResponse
	t.Run("WriteDuplicateCheckResponse", func(t *testing.T) {
		rr := httptest.NewRecorder()
		WriteDuplicateCheckResponse(rr, true)

		var response DuplicateCheckResponse
		err := json.NewDecoder(rr.Body).Decode(&response)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if !response.IsDuplicate {
			t.Error("Expected IsDuplicate to be true")
		}
	})
}

// Helper function for creating bool pointers
func boolPtr(b bool) *bool {
	return &b
}
